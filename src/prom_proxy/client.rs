use std::net::SocketAddr;

use thiserror::Error;
use tokio::net::TcpStream;

use crate::prom_proxy::protocol::{
    ErrorBody, MSG_ERROR, MSG_REMOTE_WRITE, MSG_REMOTE_WRITE_ACK, RemoteWriteAck,
};
use crate::tiny_frame::{self, CHACHA20POLY1305};

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Protocol(String),
}

pub struct Client {
    next_tx: u64,
    message_type: u8,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    pub fn new() -> Self {
        Self {
            next_tx: 1,
            message_type: MSG_REMOTE_WRITE,
        }
    }

    /// 覆盖默认 `MSG_REMOTE_WRITE`，需与代理 / manifest 中的 message_type 一致。
    pub fn with_message_type(mut self, message_type: u8) -> Self {
        self.message_type = message_type;
        self
    }

    fn next_tx_id(&mut self) -> u64 {
        let id = self.next_tx;
        self.next_tx = self.next_tx.wrapping_add(1).max(1);
        id
    }

    /// 经 TCP + tiny_frame 将 remote_write body 发给代理，返回上游 HTTP status。
    ///
    /// `body` 应为 snappy 压缩的 protobuf WriteRequest（见 [`super::prepare_remote_write_body`]）。
    /// 使用前须配置 [`crate::tiny_frame::set_encrypt_key`]。
    pub async fn remote_write(
        &mut self,
        proxy: SocketAddr,
        body: &[u8],
    ) -> Result<u16, ClientError> {
        let tx_id = self.next_tx_id();
        let mut stream = TcpStream::connect(proxy).await?;
        tiny_frame::write_frame(
            &mut stream,
            self.message_type,
            tx_id,
            body,
            CHACHA20POLY1305,
        )
        .await?;

        let frame = tiny_frame::read_frame(&mut stream).await?;
        match frame.message_type {
            MSG_REMOTE_WRITE_ACK => {
                let ack: RemoteWriteAck = serde_json::from_slice(&frame.data)?;
                Ok(ack.status)
            }
            MSG_ERROR => {
                let err: ErrorBody = serde_json::from_slice(&frame.data)?;
                Err(ClientError::Protocol(err.message))
            }
            other => Err(ClientError::Protocol(format!(
                "unexpected message_type {other}"
            ))),
        }
    }

    /// 将未压缩 protobuf WriteRequest 做 snappy 后发送。
    pub async fn remote_write_protobuf(
        &mut self,
        proxy: SocketAddr,
        protobuf_write_request: &[u8],
    ) -> Result<u16, ClientError> {
        let body = crate::prom_proxy::prepare_remote_write_body(protobuf_write_request);
        self.remote_write(proxy, &body).await
    }

    /// 将 `prometheus` crate Gather 得到的 MetricFamily 编码并发送。
    pub async fn remote_write_families(
        &mut self,
        proxy: SocketAddr,
        mfs: &[prometheus::proto::MetricFamily],
    ) -> Result<u16, ClientError> {
        let protobuf = crate::prom_proxy::encode_metric_families(mfs)
            .map_err(|e| ClientError::Protocol(e.to_string()))?;
        self.remote_write_protobuf(proxy, &protobuf).await
    }
}
