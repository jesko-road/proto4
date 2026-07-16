use std::marker::PhantomData;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, params};
use thiserror::Error;

use crate::dfinder::protocol::{NodeExtra, NodeInfo};

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("store lock poisoned")]
    Poisoned,
}

pub struct NodeStore<E: NodeExtra = ()> {
    conn: Mutex<Connection>,
    _marker: PhantomData<E>,
}

impl<E: NodeExtra> NodeStore<E> {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        let store = Self {
            conn: Mutex::new(conn),
            _marker: PhantomData,
        };
        store.migrate()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()?;
        let store = Self {
            conn: Mutex::new(conn),
            _marker: PhantomData,
        };
        store.migrate()?;
        Ok(store)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>, StoreError> {
        self.conn.lock().map_err(|_| StoreError::Poisoned)
    }

    fn migrate(&self) -> Result<(), StoreError> {
        self.lock()?.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS nodes (
                ip TEXT PRIMARY KEY NOT NULL,
                port INTEGER NOT NULL,
                labels TEXT NOT NULL,
                extra TEXT NOT NULL DEFAULT 'null',
                updated_at INTEGER NOT NULL
            );
            "#,
        )?;
        Ok(())
    }

    pub fn upsert(&self, node: &NodeInfo<E>) -> Result<(), StoreError> {
        let labels_json = serde_json::to_string(&node.labels)?;
        let extra_json = serde_json::to_string(&node.extra)?;
        let now = now_secs();
        self.lock()?.execute(
            r#"
            INSERT INTO nodes (ip, port, labels, extra, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(ip) DO UPDATE SET
                port = excluded.port,
                labels = excluded.labels,
                extra = excluded.extra,
                updated_at = excluded.updated_at
            "#,
            params![
                node.ip,
                node.port as i64,
                labels_json,
                extra_json,
                now
            ],
        )?;
        Ok(())
    }

    pub fn remove(&self, ip: &str) -> Result<(), StoreError> {
        self.lock()?
            .execute("DELETE FROM nodes WHERE ip = ?1", params![ip])?;
        Ok(())
    }

    pub fn list_all(&self) -> Result<Vec<NodeInfo<E>>, StoreError> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare("SELECT ip, port, labels, extra FROM nodes")?;
        let rows = stmt.query_map([], |row| {
            let ip: String = row.get(0)?;
            let port: i64 = row.get(1)?;
            let labels: String = row.get(2)?;
            let extra: String = row.get(3)?;
            Ok((ip, port, labels, extra))
        })?;

        let mut out = Vec::new();
        for row in rows {
            let (ip, port, labels, extra) = row?;
            out.push(NodeInfo {
                ip,
                port: port as u16,
                labels: serde_json::from_str(&labels)?,
                extra: serde_json::from_str(&extra)?,
            });
        }
        Ok(out)
    }

    /// 返回至少匹配 `labels` 中全部 label 的节点（AND）。
    pub fn list_by_labels(&self, labels: &[String]) -> Result<Vec<NodeInfo<E>>, StoreError> {
        let all = self.list_all()?;
        Ok(all
            .into_iter()
            .filter(|n| labels.iter().all(|l| n.labels.contains(l)))
            .collect())
    }
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
