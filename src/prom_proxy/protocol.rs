use serde::{Deserialize, Serialize};

/// 客户端 → 代理：remote_write 请求体（已是 snappy 压缩的 protobuf）。
pub const MSG_REMOTE_WRITE: u8 = 10;
/// 代理 → 客户端：转发成功（含上游 HTTP 状态码）。
pub const MSG_REMOTE_WRITE_ACK: u8 = 11;
/// 代理 → 客户端：错误。
pub const MSG_ERROR: u8 = 12;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteWriteAck {
    /// Prometheus / 上游返回的 HTTP status code。
    pub status: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorBody {
    pub message: String,
}

/// 将未压缩的 protobuf `WriteRequest` bytes 做 Snappy block 压缩，得到可直接作为
/// remote_write HTTP body / tiny_frame payload 的字节。
pub fn prepare_remote_write_body(protobuf_write_request: &[u8]) -> Vec<u8> {
    snap::raw::Encoder::new()
        .compress_vec(protobuf_write_request)
        .expect("snappy compress")
}
