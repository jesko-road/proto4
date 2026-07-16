use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

use crate::dfinder::protocol::{
    ErrorBody, MSG_ERROR, MSG_QUERY, MSG_QUERY_RESULT, MSG_REGISTER, MSG_REGISTER_ACK, NodeExtra,
    NodeInfo, QueryRequest, QueryResult, RegisterRequest,
};
use crate::dfinder::store::{NodeStore, StoreError};
use crate::tiny_frame::{self, Frame};

/// 服务端健康探测：由使用者注册。返回 `true` 表示节点可达/健康。
pub type HealthProbe<E = ()> = Arc<
    dyn Fn(NodeInfo<E>) -> Pin<Box<dyn Future<Output = bool> + Send>> + Send + Sync,
>;

/// 将异步闭包包装为 [`HealthProbe`]。
pub fn health_probe<E, F, Fut>(f: F) -> HealthProbe<E>
where
    E: NodeExtra,
    F: Fn(NodeInfo<E>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = bool> + Send + 'static,
{
    Arc::new(move |node| Box::pin(f(node)))
}

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("store: {0}")]
    Store(#[from] StoreError),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Msg(String),
}

pub struct ServerConfig<E: NodeExtra = ()> {
    pub listen: SocketAddr,
    /// SQLite 路径；`None` 时使用内存库（仅测试）。
    pub db_path: Option<PathBuf>,
    pub probe_interval: Duration,
    /// 连续不健康超过此时长则永久注销。
    pub offline_ttl: Duration,
    pub health_probe: HealthProbe<E>,
}

impl<E: NodeExtra> Clone for ServerConfig<E> {
    fn clone(&self) -> Self {
        Self {
            listen: self.listen,
            db_path: self.db_path.clone(),
            probe_interval: self.probe_interval,
            offline_ttl: self.offline_ttl,
            health_probe: Arc::clone(&self.health_probe),
        }
    }
}

struct HealthState {
    healthy: bool,
    last_ok: Instant,
}

struct Inner<E: NodeExtra> {
    store: NodeStore<E>,
    health: HashMap<String, HealthState>,
    probe: HealthProbe<E>,
    offline_ttl: Duration,
}

pub struct Server<E: NodeExtra = ()> {
    inner: Arc<RwLock<Inner<E>>>,
    listen: SocketAddr,
    probe_interval: Duration,
}

impl<E: NodeExtra> Server<E> {
    pub fn new(config: ServerConfig<E>) -> Result<Self, ServerError> {
        let store = match &config.db_path {
            Some(path) => NodeStore::open(path)?,
            None => NodeStore::open_in_memory()?,
        };

        let now = Instant::now();
        let mut health = HashMap::new();
        for node in store.list_all()? {
            health.insert(
                node.ip.clone(),
                HealthState {
                    healthy: false,
                    last_ok: now,
                },
            );
        }

        Ok(Self {
            inner: Arc::new(RwLock::new(Inner {
                store,
                health,
                probe: config.health_probe,
                offline_ttl: config.offline_ttl,
            })),
            listen: config.listen,
            probe_interval: config.probe_interval,
        })
    }

    /// 启动 TCP 服务与定时探测；返回句柄，drop/abort 可停止。
    pub fn spawn(self) -> JoinHandle<Result<(), ServerError>> {
        tokio::spawn(async move { self.run().await })
    }

    /// 绑定并启动；`ready` 在 listen 成功后收到实际地址（支持 `0` 端口）。
    pub fn spawn_with_addr(
        self,
    ) -> (
        JoinHandle<Result<(), ServerError>>,
        tokio::sync::oneshot::Receiver<SocketAddr>,
    ) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(async move { self.run_and_notify(tx).await });
        (handle, rx)
    }

    pub async fn run(self) -> Result<(), ServerError> {
        let (tx, _rx) = tokio::sync::oneshot::channel();
        self.run_and_notify(tx).await
    }

    async fn run_and_notify(
        self,
        ready: tokio::sync::oneshot::Sender<SocketAddr>,
    ) -> Result<(), ServerError> {
        let listener = TcpListener::bind(self.listen).await?;
        let addr = listener.local_addr()?;
        let _ = ready.send(addr);
        let inner = self.inner.clone();
        let interval = self.probe_interval;

        let probe_inner = inner.clone();
        let probe_task = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                if let Err(e) = run_probe_cycle(&probe_inner).await {
                    eprintln!("dfinder probe cycle error: {e}");
                }
            }
        });

        let result = async {
            loop {
                let (stream, peer) = listener.accept().await?;
                let inner = inner.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(stream, peer, inner).await {
                        eprintln!("dfinder conn error from {peer}: {e}");
                    }
                });
            }
        }
        .await;

        probe_task.abort();
        result
    }
}

async fn run_probe_cycle<E: NodeExtra>(
    inner: &Arc<RwLock<Inner<E>>>,
) -> Result<(), ServerError> {
    let (nodes, probe, offline_ttl) = {
        let g = inner.read().await;
        (g.store.list_all()?, g.probe.clone(), g.offline_ttl)
    };

    let now = Instant::now();
    let mut expired = Vec::new();

    for node in nodes {
        let ip = node.ip.clone();
        let ok = (probe)(node).await;
        let mut g = inner.write().await;
        let state = g.health.entry(ip.clone()).or_insert(HealthState {
            healthy: false,
            last_ok: now,
        });
        if ok {
            state.healthy = true;
            state.last_ok = now;
        } else {
            state.healthy = false;
            if now.duration_since(state.last_ok) >= offline_ttl {
                expired.push(ip);
            }
        }
    }

    if !expired.is_empty() {
        let mut g = inner.write().await;
        for ip in expired {
            g.store.remove(&ip)?;
            g.health.remove(&ip);
        }
    }

    Ok(())
}

async fn handle_conn<E: NodeExtra>(
    mut stream: TcpStream,
    peer: SocketAddr,
    inner: Arc<RwLock<Inner<E>>>,
) -> Result<(), ServerError> {
    let frame = tiny_frame::read_frame(&mut stream).await?;
    match frame.message_type {
        MSG_REGISTER => handle_register(&mut stream, peer, &frame, &inner).await,
        MSG_QUERY => handle_query(&mut stream, &frame, &inner).await,
        other => {
            write_error(&mut stream, frame.tx_id, format!("unknown message_type {other}")).await
        }
    }
}

async fn handle_register<E: NodeExtra>(
    stream: &mut TcpStream,
    peer: SocketAddr,
    frame: &Frame,
    inner: &Arc<RwLock<Inner<E>>>,
) -> Result<(), ServerError> {
    let req: RegisterRequest<E> = serde_json::from_slice(&frame.data)?;
    if req.labels.is_empty() {
        return write_error(stream, frame.tx_id, "register requires >= 1 label").await;
    }

    let ip = peer.ip().to_string();
    let node = NodeInfo {
        ip: ip.clone(),
        port: req.port,
        labels: req.labels,
        extra: req.extra,
    };

    {
        let mut g = inner.write().await;
        g.store.upsert(&node)?;
        g.health.insert(
            ip,
            HealthState {
                healthy: true,
                last_ok: Instant::now(),
            },
        );
    }

    tiny_frame::write_frame_plain(stream, MSG_REGISTER_ACK, frame.tx_id, b"{}").await?;
    Ok(())
}

async fn handle_query<E: NodeExtra>(
    stream: &mut TcpStream,
    frame: &Frame,
    inner: &Arc<RwLock<Inner<E>>>,
) -> Result<(), ServerError> {
    let req: QueryRequest = serde_json::from_slice(&frame.data)?;
    if req.labels.is_empty() {
        return write_error(stream, frame.tx_id, "query requires >= 1 label").await;
    }

    let nodes = {
        let g = inner.read().await;
        let matched = g.store.list_by_labels(&req.labels)?;
        matched
            .into_iter()
            .filter(|n| g.health.get(&n.ip).map(|h| h.healthy).unwrap_or(false))
            .collect::<Vec<_>>()
    };

    let body = serde_json::to_vec(&QueryResult { nodes })?;
    tiny_frame::write_frame_plain(stream, MSG_QUERY_RESULT, frame.tx_id, &body).await?;
    Ok(())
}

async fn write_error(
    stream: &mut TcpStream,
    tx_id: u64,
    message: impl Into<String>,
) -> Result<(), ServerError> {
    let body = serde_json::to_vec(&ErrorBody {
        message: message.into(),
    })?;
    tiny_frame::write_frame_plain(stream, MSG_ERROR, tx_id, &body).await?;
    Ok(())
}
