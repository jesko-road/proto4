//! edge 计数器持久化到 Redis（HINCRBY / HGETALL），重启与迁移不丢数据。
//!
//! - [`EdgeStore`]：async（`prom_proxy` 服务端使用）
//! - [`EdgeStoreBlocking`]：同步（边缘工具 / 无 tokio runtime 使用）

use redis::AsyncCommands;
use redis::Commands;
use redis::aio::ConnectionManager;
use thiserror::Error;

/// Redis Hash key，field = 业务 key，value = 累计计数。
pub const DEFAULT_EDGE_HASH_KEY: &str = "prom_proxy:edges";

#[derive(Debug, Error)]
pub enum EdgeError {
    #[error("redis: {0}")]
    Redis(#[from] redis::RedisError),
}

#[derive(Clone)]
pub struct EdgeStore {
    conn: ConnectionManager,
    hash_key: String,
}

impl EdgeStore {
    pub async fn connect(redis_url: &str, hash_key: impl Into<String>) -> Result<Self, EdgeError> {
        let client = redis::Client::open(redis_url)?;
        let conn = ConnectionManager::new(client).await?;
        Ok(Self {
            conn,
            hash_key: hash_key.into(),
        })
    }

    /// 对指定 field 累加 `delta`（Redis HINCRBY，只增）。
    pub async fn incr(&self, key: &str, delta: u64) -> Result<(), EdgeError> {
        if delta == 0 {
            return Ok(());
        }
        let mut conn = self.conn.clone();
        let _: i64 = conn.hincr(&self.hash_key, key, delta as i64).await?;
        Ok(())
    }

    /// 返回 Hash 中各 field 的累计总值。
    pub async fn totals(&self) -> Result<Vec<(String, u64)>, EdgeError> {
        let mut conn = self.conn.clone();
        let map: std::collections::HashMap<String, i64> = conn.hgetall(&self.hash_key).await?;
        Ok(map
            .into_iter()
            .filter_map(|(k, v)| (v >= 0).then_some((k, v as u64)))
            .collect())
    }

    #[cfg(test)]
    pub async fn clear(&self) -> Result<(), EdgeError> {
        let mut conn = self.conn.clone();
        let _: () = conn.del(&self.hash_key).await?;
        Ok(())
    }
}

/// 同步版 edge 计数器，不依赖 tokio runtime。
#[derive(Clone)]
pub struct EdgeStoreBlocking {
    client: redis::Client,
    hash_key: String,
}

impl EdgeStoreBlocking {
    pub fn connect(redis_url: &str, hash_key: impl Into<String>) -> Result<Self, EdgeError> {
        Ok(Self {
            client: redis::Client::open(redis_url)?,
            hash_key: hash_key.into(),
        })
    }

    /// 对指定 field 累加 `delta`（Redis HINCRBY，只增）。
    pub fn incr(&self, key: &str, delta: u64) -> Result<(), EdgeError> {
        if delta == 0 {
            return Ok(());
        }
        let mut conn = self.client.get_connection()?;
        let _: i64 = conn.hincr(&self.hash_key, key, delta as i64)?;
        Ok(())
    }

    /// 返回 Hash 中各 field 的累计总值。
    pub fn totals(&self) -> Result<Vec<(String, u64)>, EdgeError> {
        let mut conn = self.client.get_connection()?;
        let map: std::collections::HashMap<String, i64> = conn.hgetall(&self.hash_key)?;
        Ok(map
            .into_iter()
            .filter_map(|(k, v)| (v >= 0).then_some((k, v as u64)))
            .collect())
    }

    #[cfg(test)]
    pub fn clear(&self) -> Result<(), EdgeError> {
        let mut conn = self.client.get_connection()?;
        let _: () = conn.del(&self.hash_key)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_redis_url() -> Option<String> {
        std::env::var("PROM_PROXY_REDIS_URL")
            .ok()
            .or_else(|| Some("redis://127.0.0.1:6379".into()))
    }

    #[tokio::test]
    async fn redis_incr_accumulates_total() {
        let Some(url) = test_redis_url() else {
            return;
        };
        let hash_key = format!("prom_proxy:test:{}", std::process::id());
        let store = match EdgeStore::connect(&url, &hash_key).await {
            Ok(s) => s,
            Err(_) => return,
        };
        store.clear().await.ok();

        store.incr("a", 3).await.unwrap();
        store.incr("a", 2).await.unwrap();
        store.incr("b", 1).await.unwrap();
        let mut t = store.totals().await.unwrap();
        t.sort();
        assert_eq!(t, vec![("a".into(), 5), ("b".into(), 1)]);

        store.incr("a", 1).await.unwrap();
        let mut t = store.totals().await.unwrap();
        t.sort();
        assert_eq!(t, vec![("a".into(), 6), ("b".into(), 1)]);

        store.clear().await.ok();
    }

    #[test]
    fn blocking_redis_incr_accumulates_total() {
        let Some(url) = test_redis_url() else {
            return;
        };
        let hash_key = format!("prom_proxy:test:blocking:{}", std::process::id());
        let store = match EdgeStoreBlocking::connect(&url, &hash_key) {
            Ok(s) => s,
            Err(_) => return,
        };
        store.clear().ok();

        store.incr("a", 3).unwrap();
        store.incr("a", 2).unwrap();
        store.incr("b", 1).unwrap();
        let mut t = store.totals().unwrap();
        t.sort();
        assert_eq!(t, vec![("a".into(), 5), ("b".into(), 1)]);

        store.incr("a", 1).unwrap();
        let mut t = store.totals().unwrap();
        t.sort();
        assert_eq!(t, vec![("a".into(), 6), ("b".into(), 1)]);

        store.clear().ok();
    }
}
