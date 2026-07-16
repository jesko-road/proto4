//! 去中心化节点发现：节点可互为 registry，注册 / 按 label 查询健康节点。
//!
//! - 服务端：接受注册（peer IP 作为节点标识）、定时健康探测、过期注销；基本信息落 SQLite，健康状态在内存。
//! - 客户端：向目标节点注册自己；按 label 查询后，再用本地健康检测函数二次过滤。

mod protocol;
mod store;

pub mod client;
pub mod server;

pub use protocol::{NodeExtra, NodeInfo};

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use serde::{Deserialize, Serialize};

    use super::client::{Client, ClientConfig, local_health_check};
    use super::server::{Server, ServerConfig, health_probe};

    #[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
    struct Meta {
        region: String,
        weight: u32,
    }

    #[tokio::test]
    async fn register_and_query_with_label_and_local_filter() {
        let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server = Server::new(ServerConfig {
            listen,
            db_path: None,
            probe_interval: Duration::from_secs(60),
            offline_ttl: Duration::from_secs(3600),
            health_probe: health_probe(|_: super::NodeInfo| async { true }),
        })
        .unwrap();
        let (handle, ready) = server.spawn_with_addr();
        let addr = ready.await.unwrap();

        let mut client = Client::new(ClientConfig {
            health_check: local_health_check(|_: super::NodeInfo| async { true }),
        });

        client
            .register(addr, 9001, vec!["api".into(), "v1".into()], ())
            .await
            .unwrap();

        let nodes = client
            .query_healthy(addr, vec!["api".into()])
            .await
            .unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].port, 9001);
        assert!(nodes[0].labels.contains(&"api".into()));

        // local filter rejects all
        let mut picky = Client::new(ClientConfig {
            health_check: local_health_check(|_: super::NodeInfo| async { false }),
        });
        let filtered = picky
            .query_healthy(addr, vec!["api".into()])
            .await
            .unwrap();
        assert!(filtered.is_empty());

        // empty labels rejected
        let err = client
            .query_healthy(addr, vec![])
            .await
            .unwrap_err();
        assert!(err.to_string().contains(">= 1 label"));

        handle.abort();
    }

    #[tokio::test]
    async fn expires_unhealthy_nodes() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let alive = Arc::new(AtomicBool::new(true));
        let probe_flag = alive.clone();

        let server = Server::new(ServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            db_path: None,
            probe_interval: Duration::from_millis(30),
            offline_ttl: Duration::from_millis(80),
            health_probe: health_probe(move |_: super::NodeInfo| {
                let ok = probe_flag.load(Ordering::SeqCst);
                async move { ok }
            }),
        })
        .unwrap();
        let (handle, ready) = server.spawn_with_addr();
        let addr = ready.await.unwrap();

        let mut client = Client::new(ClientConfig {
            health_check: local_health_check(|_: super::NodeInfo| async { true }),
        });
        client
            .register(addr, 9002, vec!["svc".into()], ())
            .await
            .unwrap();

        let before = client
            .query_healthy(addr, vec!["svc".into()])
            .await
            .unwrap();
        assert_eq!(before.len(), 1);

        alive.store(false, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(250)).await;

        let after = client
            .query_healthy(addr, vec!["svc".into()])
            .await
            .unwrap();
        assert!(after.is_empty());

        handle.abort();
    }

    #[tokio::test]
    async fn custom_extra_roundtrip() {
        let server = Server::<Meta>::new(ServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            db_path: None,
            probe_interval: Duration::from_secs(60),
            offline_ttl: Duration::from_secs(3600),
            health_probe: health_probe(|n: super::NodeInfo<Meta>| async move {
                n.extra.weight > 0
            }),
        })
        .unwrap();
        let (handle, ready) = server.spawn_with_addr();
        let addr = ready.await.unwrap();

        let mut client = Client::<Meta>::new(ClientConfig {
            health_check: local_health_check(|n: super::NodeInfo<Meta>| async move {
                n.extra.region == "cn"
            }),
        });

        let meta = Meta {
            region: "cn".into(),
            weight: 10,
        };
        client
            .register(addr, 9003, vec!["api".into()], meta.clone())
            .await
            .unwrap();

        let nodes = client
            .query_healthy(addr, vec!["api".into()])
            .await
            .unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].extra, meta);

        handle.abort();
    }
}
