use std::net::SocketAddr;
use std::sync::Arc;

use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::prom_proxy::protocol::{
    ErrorBody, MSG_ERROR, MSG_REMOTE_WRITE, MSG_REMOTE_WRITE_ACK, RemoteWriteAck,
};
use crate::tiny_frame::{self, CHACHA20POLY1305, Frame};

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Msg(String),
}

#[derive(Clone)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    /// Prometheus remote_write URL，例如 `http://127.0.0.1:9090/api/v1/write`。
    pub prometheus_url: String,
    /// 接受的请求 message_type，默认 [`MSG_REMOTE_WRITE`]。
    pub message_type: u8,
}

impl ServerConfig {
    pub fn new(listen: SocketAddr, prometheus_url: impl Into<String>) -> Self {
        Self {
            listen,
            prometheus_url: prometheus_url.into(),
            message_type: MSG_REMOTE_WRITE,
        }
    }
}

pub struct Server {
    config: ServerConfig,
    http: reqwest::Client,
}

impl Server {
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config,
            http: reqwest::Client::new(),
        }
    }

    pub fn spawn(self) -> JoinHandle<Result<(), ServerError>> {
        let (tx, _rx) = oneshot::channel::<SocketAddr>();
        self.spawn_with_ready(tx)
    }

    /// 启动后通过 oneshot 回传实际监听地址（`listen` 端口为 0 时有用）。
    pub fn spawn_with_addr(self) -> (JoinHandle<Result<(), ServerError>>, oneshot::Receiver<SocketAddr>) {
        let (tx, rx) = oneshot::channel();
        (self.spawn_with_ready(tx), rx)
    }

    fn spawn_with_ready(
        self,
        ready: oneshot::Sender<SocketAddr>,
    ) -> JoinHandle<Result<(), ServerError>> {
        tokio::spawn(async move {
            let listener = TcpListener::bind(self.config.listen).await?;
            let addr = listener.local_addr()?;
            let _ = ready.send(addr);

            let state = Arc::new(self);
            loop {
                let (stream, _) = listener.accept().await?;
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(e) = state.handle_conn(stream).await {
                        eprintln!("prom_proxy: connection error: {e}");
                    }
                });
            }
        })
    }

    async fn handle_conn(&self, mut stream: TcpStream) -> Result<(), ServerError> {
        let frame = tiny_frame::read_frame(&mut stream).await?;
        if frame.message_type != self.config.message_type {
            self.write_error(
                &mut stream,
                frame.tx_id,
                format!("unexpected message_type {}", frame.message_type),
            )
            .await?;
            return Ok(());
        }

        match self.forward(&frame).await {
            Ok(status) => {
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
                self.write_error(&mut stream, frame.tx_id, e.to_string())
                    .await?;
            }
        }
        Ok(())
    }

    async fn forward(&self, frame: &Frame) -> Result<u16, ServerError> {
        let resp = self
            .http
            .post(&self.config.prometheus_url)
            .header("Content-Encoding", "snappy")
            .header("Content-Type", "application/x-protobuf")
            .header("X-Prometheus-Remote-Write-Version", "0.1.0")
            .header("User-Agent", "proto4-prom-proxy/0.1.0")
            .body(frame.data.clone())
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
        &self,
        stream: &mut TcpStream,
        tx_id: u64,
        message: String,
    ) -> Result<(), ServerError> {
        let body = serde_json::to_vec(&ErrorBody { message })?;
        tiny_frame::write_frame(stream, MSG_ERROR, tx_id, &body, CHACHA20POLY1305).await?;
        Ok(())
    }
}
