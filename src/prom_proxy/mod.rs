//! Prometheus remote_write 代理：客户端经 tiny_frame+TCP 上报，服务端 HTTP 转发到 Prometheus。
//!
//! - 客户端发送的 `body` 应为 Prometheus remote_write 的 HTTP body
//!   （protobuf `WriteRequest` + Snappy block 压缩），服务端原样 POST。
//! - 帧 payload 长度上限为 `u16::MAX`（加密后），大批次需自行切分。
//! - edge 计数持久化在 Redis Hash（默认 `prom_proxy:edges`）。

pub mod client;
pub mod edge;
pub mod encode;
pub mod protocol;
pub mod server;

pub use client::{Client, ClientError};
pub use edge::{DEFAULT_EDGE_HASH_KEY, EdgeError, EdgeStore, EdgeStoreBlocking};
pub use encode::{
    EncodeError, Label, Sample, TimeSeries, encode_metric_families, encode_write_request,
};
pub use protocol::{
    ErrorBody, MSG_ERROR, MSG_REMOTE_WRITE, MSG_REMOTE_WRITE_ACK, RemoteWriteAck,
    prepare_remote_write_body,
};
pub use server::{Server, ServerConfig, ServerError};

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Once;
    use std::sync::atomic::{AtomicU64, Ordering};

    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::tiny_frame::{self, KEY_LEN};

    static INIT_KEY: Once = Once::new();
    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn ensure_key() {
        INIT_KEY.call_once(|| {
            let _ = tiny_frame::ENCRYPT_KEY_CHACHA20POLY1305.set(Some([0x42; KEY_LEN]));
        });
    }

    fn test_redis_url() -> String {
        std::env::var("PROM_PROXY_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into())
    }

    async fn test_server(listen: SocketAddr, prometheus_url: String) -> Option<Server> {
        let redis_url = test_redis_url();
        let hash_key = format!(
            "prom_proxy:test:mod:{}",
            TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let edges = EdgeStore::connect(&redis_url, &hash_key).await.ok()?;
        edges.clear().await.ok();
        Server::new(
            ServerConfig::new(listen, prometheus_url, redis_url).edge_hash_key(hash_key),
        )
        .await
        .ok()
    }

    #[tokio::test]
    async fn proxy_forwards_body_and_returns_ack() {
        ensure_key();

        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/write"))
            .and(header("Content-Encoding", "snappy"))
            .and(header("Content-Type", "application/x-protobuf"))
            .and(header("X-Prometheus-Remote-Write-Version", "0.1.0"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&mock)
            .await;

        let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let Some(server) = test_server(listen, format!("{}/api/v1/write", mock.uri())).await
        else {
            return;
        };
        let (handle, ready) = server.spawn_with_addr();
        let addr = ready.await.unwrap();

        let protobuf = b"fake-write-request-protobuf";
        let body = prepare_remote_write_body(protobuf);

        let mut client = Client::new();
        let status = client.remote_write(addr, &body).await.unwrap();
        assert_eq!(status, 204);

        handle.abort();
    }

    #[tokio::test]
    async fn blocking_client_forwards_body_and_returns_ack() {
        ensure_key();

        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/write"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&mock)
            .await;

        let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let Some(server) = test_server(listen, format!("{}/api/v1/write", mock.uri())).await
        else {
            return;
        };
        let (handle, ready) = server.spawn_with_addr();
        let addr = ready.await.unwrap();

        let body = prepare_remote_write_body(b"fake-write-request-protobuf");
        let status = tokio::task::spawn_blocking(move || {
            let mut client = Client::new();
            client.remote_write_blocking(addr, &body)
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(status, 204);

        handle.abort();
    }

    #[tokio::test]
    async fn proxy_surfaces_upstream_error() {
        ensure_key();

        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/write"))
            .respond_with(ResponseTemplate::new(400).set_body_string("bad request"))
            .mount(&mock)
            .await;

        let Some(server) = test_server(
            "127.0.0.1:0".parse().unwrap(),
            format!("{}/api/v1/write", mock.uri()),
        )
        .await
        else {
            return;
        };
        let (handle, ready) = server.spawn_with_addr();
        let addr = ready.await.unwrap();

        let mut client = Client::new();
        let err = client.remote_write(addr, b"x").await.unwrap_err();
        assert!(err.to_string().contains("400"), "{err}");

        handle.abort();
    }
}
