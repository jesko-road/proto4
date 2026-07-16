use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use thiserror::Error;
use tokio::net::TcpStream;

use crate::dfinder::protocol::{
    ErrorBody, MSG_ERROR, MSG_QUERY, MSG_QUERY_RESULT, MSG_REGISTER, MSG_REGISTER_ACK, NodeExtra,
    NodeInfo, QueryRequest, QueryResult, RegisterRequest,
};
use crate::tiny_frame;

/// 客户端本地健康检测：拿到 registry 返回的列表后，再过滤出对本端真正可用的节点。
pub type LocalHealthCheck<E = ()> = Arc<
    dyn Fn(NodeInfo<E>) -> Pin<Box<dyn Future<Output = bool> + Send>> + Send + Sync,
>;

/// 将异步闭包包装为 [`LocalHealthCheck`]。
pub fn local_health_check<E, F, Fut>(f: F) -> LocalHealthCheck<E>
where
    E: NodeExtra,
    F: Fn(NodeInfo<E>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = bool> + Send + 'static,
{
    Arc::new(move |node| Box::pin(f(node)))
}

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Protocol(String),
}

pub struct ClientConfig<E: NodeExtra = ()> {
    pub health_check: LocalHealthCheck<E>,
}

impl<E: NodeExtra> Clone for ClientConfig<E> {
    fn clone(&self) -> Self {
        Self {
            health_check: Arc::clone(&self.health_check),
        }
    }
}

pub struct Client<E: NodeExtra = ()> {
    health_check: LocalHealthCheck<E>,
    next_tx: u64,
}

impl<E: NodeExtra> Client<E> {
    pub fn new(config: ClientConfig<E>) -> Self {
        Self {
            health_check: config.health_check,
            next_tx: 1,
        }
    }

    fn next_tx_id(&mut self) -> u64 {
        let id = self.next_tx;
        self.next_tx = self.next_tx.wrapping_add(1).max(1);
        id
    }

    /// 向目标 registry 注册本节点。服务端以连接 peer IP 作为节点 IP。
    pub async fn register(
        &mut self,
        registry: SocketAddr,
        port: u16,
        labels: Vec<String>,
        extra: E,
    ) -> Result<(), ClientError> {
        if labels.is_empty() {
            return Err(ClientError::Protocol(
                "register requires >= 1 label".into(),
            ));
        }
        let tx_id = self.next_tx_id();
        let mut stream = TcpStream::connect(registry).await?;
        let body = serde_json::to_vec(&RegisterRequest {
            port,
            labels,
            extra,
        })?;
        tiny_frame::write_frame_plain(&mut stream, MSG_REGISTER, tx_id, &body).await?;

        let frame = tiny_frame::read_frame(&mut stream).await?;
        match frame.message_type {
            MSG_REGISTER_ACK => Ok(()),
            MSG_ERROR => {
                let err: ErrorBody = serde_json::from_slice(&frame.data)?;
                Err(ClientError::Protocol(err.message))
            }
            other => Err(ClientError::Protocol(format!(
                "unexpected message_type {other}"
            ))),
        }
    }

    /// 向目标节点查询健康列表（至少 1 个 label），再用本地健康检测二次过滤。
    pub async fn query_healthy(
        &mut self,
        registry: SocketAddr,
        labels: Vec<String>,
    ) -> Result<Vec<NodeInfo<E>>, ClientError> {
        if labels.is_empty() {
            return Err(ClientError::Protocol("query requires >= 1 label".into()));
        }
        let tx_id = self.next_tx_id();
        let mut stream = TcpStream::connect(registry).await?;
        let body = serde_json::to_vec(&QueryRequest { labels })?;
        tiny_frame::write_frame_plain(&mut stream, MSG_QUERY, tx_id, &body).await?;

        let frame = tiny_frame::read_frame(&mut stream).await?;
        let remote = match frame.message_type {
            MSG_QUERY_RESULT => {
                let result: QueryResult<E> = serde_json::from_slice(&frame.data)?;
                result.nodes
            }
            MSG_ERROR => {
                let err: ErrorBody = serde_json::from_slice(&frame.data)?;
                return Err(ClientError::Protocol(err.message));
            }
            other => {
                return Err(ClientError::Protocol(format!(
                    "unexpected message_type {other}"
                )));
            }
        };

        let mut available = Vec::new();
        for node in remote {
            if (self.health_check)(node.clone()).await {
                available.push(node);
            }
        }
        Ok(available)
    }
}
