use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time;

use crate::prom_proxy::edge::{DEFAULT_EDGE_HASH_KEY, EdgeError, EdgeStore};
use crate::prom_proxy::encode::{Label, Sample, TimeSeries, encode_write_request};
use crate::prom_proxy::protocol::{
    ErrorBody, MSG_ERROR, MSG_REMOTE_WRITE, MSG_REMOTE_WRITE_ACK, RemoteWriteAck,
    prepare_remote_write_body,
};
use crate::tiny_frame::{self, CHACHA20POLY1305, Frame};

/// edge counter 指标名。
const EDGE_METRIC_NAME: &str = "prom_proxy_edge_total";
/// 每 60s 将累计总值上报 Prometheus。
const EDGE_FLUSH_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("encode: {0}")]
    Encode(#[from] crate::prom_proxy::encode::EncodeError),
    #[error("redis: {0}")]
    Redis(#[from] EdgeError),
    #[error("{0}")]
    Msg(String),
}

#[derive(Clone)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    /// Prometheus remote_write URL，例如 `http://127.0.0.1:9090/api/v1/write`。
    pub prometheus_url: String,
    /// Redis URL，例如 `redis://127.0.0.1:6379`。
    pub redis_url: String,
    /// Redis Hash key，默认 [`DEFAULT_EDGE_HASH_KEY`]。
    pub edge_hash_key: String,
    /// 接受的请求 message_type，默认 [`MSG_REMOTE_WRITE`]。
    pub message_type: u8,
}

impl ServerConfig {
    pub fn new(
        listen: SocketAddr,
        prometheus_url: impl Into<String>,
        redis_url: impl Into<String>,
    ) -> Self {
        Self {
            listen,
            prometheus_url: prometheus_url.into(),
            redis_url: redis_url.into(),
            edge_hash_key: DEFAULT_EDGE_HASH_KEY.into(),
            message_type: MSG_REMOTE_WRITE,
        }
    }

    pub fn edge_hash_key(mut self, key: impl Into<String>) -> Self {
        self.edge_hash_key = key.into();
        self
    }
}

struct Inner {
    config: ServerConfig,
    http: reqwest::Client,
    edges: EdgeStore,
}

impl Inner {
    async fn incr_edge(&self, key: &str) -> Result<(), ServerError> {
        self.edges.incr(key, 1).await?;
        Ok(())
    }
}

pub struct Server {
    inner: Arc<Inner>,
}

impl Server {
    pub async fn new(config: ServerConfig) -> Result<Self, ServerError> {
        let edges = EdgeStore::connect(&config.redis_url, &config.edge_hash_key).await?;
        Ok(Self {
            inner: Arc::new(Inner {
                config,
                http: reqwest::Client::new(),
                edges,
            }),
        })
    }

    pub fn spawn(self) -> JoinHandle<Result<(), ServerError>> {
        let (tx, _rx) = oneshot::channel::<SocketAddr>();
        self.spawn_with_ready(tx)
    }

    pub fn spawn_with_addr(
        self,
    ) -> (JoinHandle<Result<(), ServerError>>, oneshot::Receiver<SocketAddr>) {
        let (tx, rx) = oneshot::channel();
        (self.spawn_with_ready(tx), rx)
    }

    fn spawn_with_ready(
        self,
        ready: oneshot::Sender<SocketAddr>,
    ) -> JoinHandle<Result<(), ServerError>> {
        tokio::spawn(async move {
            let listener = TcpListener::bind(self.inner.config.listen).await?;
            let addr = listener.local_addr()?;
            let _ = ready.send(addr);

            let state = Arc::clone(&self.inner);
            tokio::spawn(async move {
                let mut ticker = time::interval(EDGE_FLUSH_INTERVAL);
                ticker.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
                loop {
                    ticker.tick().await;
                    if let Err(e) = flush_edges(&state).await {
                        eprintln!("prom_proxy: edge flush error: {e}");
                    }
                }
            });

            loop {
                let (stream, _) = listener.accept().await?;
                let state = Arc::clone(&self.inner);
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(&state, stream).await {
                        eprintln!("prom_proxy: connection error: {e}");
                    }
                });
            }
        })
    }
}

async fn handle_conn(state: &Arc<Inner>, mut stream: TcpStream) -> Result<(), ServerError> {
    let frame = tiny_frame::read_frame(&mut stream).await?;
    if frame.message_type != state.config.message_type {
        write_error(
            &state,
            &mut stream,
            frame.tx_id,
            format!("unexpected message_type {}", frame.message_type),
        )
        .await?;
        return Ok(());
    }

    match forward_frame(state, &frame).await {
        Ok(status) => {
            if let Err(e) = state.incr_edge("remote_write_ok").await {
                eprintln!("prom_proxy: edge incr error: {e}");
            }
            let body = serde_json::to_vec(&RemoteWriteAck { status })?;
            tiny_frame::write_frame(
                &mut stream,
                MSG_REMOTE_WRITE_ACK,
                frame.tx_id,
                &body,
                CHACHA20POLY1305,
            )
            .await?;
        }
        Err(e) => {
            if let Err(err) = state.incr_edge("remote_write_err").await {
                eprintln!("prom_proxy: edge incr error: {err}");
            }
            write_error(&state, &mut stream, frame.tx_id, e.to_string()).await?;
        }
    }
    Ok(())
}

async fn forward_frame(state: &Arc<Inner>, frame: &Frame) -> Result<u16, ServerError> {
    post_remote_write(state, &frame.data).await
}

async fn flush_edges(state: &Arc<Inner>) -> Result<(), ServerError> {
    let totals = state.edges.totals().await?;
    if totals.is_empty() {
        return Ok(());
    }

    let now = chrono_now_ms();
    let series: Vec<TimeSeries> = totals
        .into_iter()
        .map(|(key, total)| TimeSeries {
            labels: vec![
                Label {
                    name: "__name__".into(),
                    value: EDGE_METRIC_NAME.into(),
                },
                Label {
                    name: "key".into(),
                    value: key,
                },
            ],
            samples: vec![Sample {
                value: total as f64,
                timestamp_ms: now,
            }],
        })
        .collect();

    let protobuf = encode_write_request(&series)?;
    let body = prepare_remote_write_body(&protobuf);
    post_remote_write(state, &body).await?;
    Ok(())
}

async fn post_remote_write(state: &Arc<Inner>, body: &[u8]) -> Result<u16, ServerError> {
    let resp = state
        .http
        .post(&state.config.prometheus_url)
        .header("Content-Encoding", "snappy")
        .header("Content-Type", "application/x-protobuf")
        .header("X-Prometheus-Remote-Write-Version", "0.1.0")
        .header("User-Agent", "proto4-prom-proxy/0.1.0")
        .body(body.to_vec())
        .send()
        .await?;

    let status = resp.status().as_u16();
    if resp.status().is_success() || status == 204 {
        Ok(status)
    } else {
        let text = resp.text().await.unwrap_or_default();
        Err(ServerError::Msg(format!(
            "upstream HTTP {status}: {text}"
        )))
    }
}

async fn write_error(
    _state: &Arc<Inner>,
    stream: &mut TcpStream,
    tx_id: u64,
    message: String,
) -> Result<(), ServerError> {
    let body = serde_json::to_vec(&ErrorBody { message })?;
    tiny_frame::write_frame(stream, MSG_ERROR, tx_id, &body, CHACHA20POLY1305).await?;
    Ok(())
}

fn chrono_now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Once;

    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::tiny_frame::{self, KEY_LEN};

    static INIT_KEY: Once = Once::new();

    fn ensure_key() {
        INIT_KEY.call_once(|| {
            let _ = tiny_frame::ENCRYPT_KEY_CHACHA20POLY1305.set(Some([0x42; KEY_LEN]));
        });
    }

    async fn test_inner(prometheus_url: String) -> Option<Arc<Inner>> {
        let redis_url = std::env::var("PROM_PROXY_REDIS_URL")
            .unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let hash_key = format!("prom_proxy:test:server:{}", std::process::id());
        let edges = EdgeStore::connect(&redis_url, &hash_key).await.ok()?;
        edges.clear().await.ok();
        Some(Arc::new(Inner {
            config: ServerConfig::new("127.0.0.1:0".parse().unwrap(), prometheus_url, redis_url)
                .edge_hash_key(hash_key),
            http: reqwest::Client::new(),
            edges,
        }))
    }

    #[tokio::test]
    async fn flush_edges_posts_counter_totals() {
        ensure_key();

        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/write"))
            .and(header("Content-Encoding", "snappy"))
            .respond_with(ResponseTemplate::new(204))
            .expect(2)
            .mount(&mock)
            .await;

        let Some(inner) = test_inner(format!("{}/api/v1/write", mock.uri())).await else {
            return;
        };
        inner.edges.incr("requests", 7).await.unwrap();
        inner.edges.incr("errors", 2).await.unwrap();

        flush_edges(&inner).await.unwrap();
        inner.edges.incr("requests", 3).await.unwrap();
        flush_edges(&inner).await.unwrap();
    }
}
