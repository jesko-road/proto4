use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// tiny_frame message types for dfinder.
pub const MSG_REGISTER: u8 = 1;
pub const MSG_REGISTER_ACK: u8 = 2;
pub const MSG_QUERY: u8 = 3;
pub const MSG_QUERY_RESULT: u8 = 4;
pub const MSG_ERROR: u8 = 5;

/// 用户自定义节点扩展字段需满足的约束。
pub trait NodeExtra:
    Clone + Default + Send + Sync + 'static + Serialize + DeserializeOwned
{
}

impl<T> NodeExtra for T where
    T: Clone + Default + Send + Sync + 'static + Serialize + DeserializeOwned
{
}

/// 节点基本信息。`E` 为使用者自定义扩展属性，默认 `()`。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E: Serialize",
    deserialize = "E: DeserializeOwned + Default"
))]
pub struct NodeInfo<E = ()> {
    pub ip: String,
    pub port: u16,
    pub labels: Vec<String>,
    /// 使用者扩展字段；协议/存储侧以 JSON 编解码。
    #[serde(default)]
    pub extra: E,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E: Serialize",
    deserialize = "E: DeserializeOwned + Default"
))]
pub struct RegisterRequest<E = ()> {
    pub port: u16,
    pub labels: Vec<String>,
    #[serde(default)]
    pub extra: E,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryRequest {
    pub labels: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "E: Serialize",
    deserialize = "E: DeserializeOwned + Default"
))]
pub struct QueryResult<E = ()> {
    pub nodes: Vec<NodeInfo<E>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    pub message: String,
}
