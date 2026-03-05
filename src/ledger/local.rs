use anyhow::{Context, Result};
use rusqlite::Connection;
use std::path::Path;

use super::event::AgentActionEvent;

/// Local SQLite-backed ledger for development and standalone use.
pub struct LocalLedger {
    conn: Connection,
}

impl LocalLedger {
    pub fn open(db_path: &Path) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
        }

        let conn = Connection::open(db_path)
            .with_context(|| format!("Failed to open database: {}", db_path.display()))?;

        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA foreign_keys = ON;"
        )?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS events (
                event_id        TEXT PRIMARY KEY,
                agent_id        TEXT NOT NULL,
                agent_version   TEXT NOT NULL,
                authorized_by   TEXT NOT NULL DEFAULT '',
                session_id      TEXT NOT NULL,
                timestamp       TEXT NOT NULL,
                tool_name       TEXT NOT NULL,
                tool_server     TEXT NOT NULL DEFAULT '',
                input_hash      TEXT NOT NULL,
                output_hash     TEXT NOT NULL DEFAULT '',
                policy_decision TEXT NOT NULL,
                policy_rule     TEXT NOT NULL DEFAULT '',
                latency_ms      INTEGER NOT NULL DEFAULT 0,
                prev_hash       TEXT NOT NULL DEFAULT '',
                event_hash      TEXT NOT NULL,
                signature       TEXT NOT NULL,
                proxy_key_id    TEXT NOT NULL,
                created_at      TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_events_agent_id ON events(agent_id);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_tool_name ON events(tool_name);
            CREATE INDEX IF NOT EXISTS idx_events_policy_decision ON events(policy_decision);"
        )?;

        Ok(Self { conn })
    }

    /// Append an event to the local ledger.
    pub fn append(&self, event: &AgentActionEvent) -> Result<()> {
        self.conn.execute(
            "INSERT INTO events (
                event_id, agent_id, agent_version, authorized_by, session_id,
                timestamp, tool_name, tool_server, input_hash, output_hash,
                policy_decision, policy_rule, latency_ms,
                prev_hash, event_hash, signature, proxy_key_id
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
            rusqlite::params![
                event.event_id,
                event.agent_id,
                event.agent_version,
                event.authorized_by,
                event.session_id,
                event.timestamp.to_rfc3339(),
                event.tool_name,
                event.tool_server,
                event.input_hash,
                event.output_hash,
                event.policy_decision,
                event.policy_rule,
                event.latency_ms,
                event.prev_hash,
                event.event_hash,
                event.signature,
                event.proxy_key_id,
            ],
        )?;
        Ok(())
    }

    /// Get the hash of the most recent event (for chain linking).
    pub fn last_event_hash(&self) -> Result<String> {
        let result: Option<String> = self.conn.query_row(
            "SELECT event_hash FROM events ORDER BY timestamp DESC, rowid DESC LIMIT 1",
            [],
            |row| row.get(0),
        ).optional()?;
        Ok(result.unwrap_or_default())
    }

    /// Query all events, optionally filtered.
    pub fn query_events(&self, limit: Option<u32>, agent_id: Option<&str>) -> Result<Vec<AgentActionEvent>> {
        let mut sql = String::from(
            "SELECT event_id, agent_id, agent_version, authorized_by, session_id,
                    timestamp, tool_name, tool_server, input_hash, output_hash,
                    policy_decision, policy_rule, latency_ms,
                    prev_hash, event_hash, signature, proxy_key_id
             FROM events"
        );

        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = vec![];

        if let Some(aid) = agent_id {
            sql.push_str(" WHERE agent_id = ?");
            params.push(Box::new(aid.to_string()));
        }

        sql.push_str(" ORDER BY timestamp ASC, rowid ASC");

        if let Some(lim) = limit {
            sql.push_str(&format!(" LIMIT {}", lim));
        }

        let mut stmt = self.conn.prepare(&sql)?;
        let events = stmt.query_map(rusqlite::params_from_iter(params.iter().map(|p| p.as_ref())), |row| {
            let ts_str: String = row.get(5)?;
            let timestamp = chrono::DateTime::parse_from_rfc3339(&ts_str)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now());

            Ok(AgentActionEvent {
                event_id: row.get(0)?,
                agent_id: row.get(1)?,
                agent_version: row.get(2)?,
                authorized_by: row.get(3)?,
                session_id: row.get(4)?,
                timestamp,
                tool_name: row.get(6)?,
                tool_server: row.get(7)?,
                input_hash: row.get(8)?,
                output_hash: row.get(9)?,
                policy_decision: row.get(10)?,
                policy_rule: row.get(11)?,
                latency_ms: row.get(12)?,
                prev_hash: row.get(13)?,
                event_hash: row.get(14)?,
                signature: row.get(15)?,
                proxy_key_id: row.get(16)?,
            })
        })?.collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(events)
    }

    /// Verify the hash chain integrity. Returns (total_events, broken_links).
    pub fn verify_chain(&self) -> Result<(usize, Vec<String>)> {
        let events = self.query_events(None, None)?;
        let mut broken = vec![];

        for (i, event) in events.iter().enumerate() {
            // Verify self-hash
            let computed = event.compute_hash();
            if computed != event.event_hash {
                broken.push(format!("Event {} has invalid self-hash", event.event_id));
            }

            // Verify chain link
            if i > 0 {
                let prev = &events[i - 1];
                if event.prev_hash != prev.event_hash {
                    broken.push(format!(
                        "Event {} has broken chain link (expected prev_hash={}, got={})",
                        event.event_id, prev.event_hash, event.prev_hash
                    ));
                }
            }
        }

        Ok((events.len(), broken))
    }

    /// Get summary statistics for the report.
    pub fn summary_stats(&self) -> Result<ReportStats> {
        let total: u64 = self.conn.query_row(
            "SELECT COUNT(*) FROM events", [], |r| r.get(0)
        )?;
        let blocked: u64 = self.conn.query_row(
            "SELECT COUNT(*) FROM events WHERE policy_decision = 'BLOCK'", [], |r| r.get(0)
        )?;
        let human_required: u64 = self.conn.query_row(
            "SELECT COUNT(*) FROM events WHERE policy_decision = 'HUMAN_REQUIRED'", [], |r| r.get(0)
        )?;
        let allowed: u64 = self.conn.query_row(
            "SELECT COUNT(*) FROM events WHERE policy_decision = 'ALLOW'", [], |r| r.get(0)
        )?;

        let unique_tools: u64 = self.conn.query_row(
            "SELECT COUNT(DISTINCT tool_name) FROM events", [], |r| r.get(0)
        )?;
        let unique_agents: u64 = self.conn.query_row(
            "SELECT COUNT(DISTINCT agent_id) FROM events", [], |r| r.get(0)
        )?;

        let first_event: Option<String> = self.conn.query_row(
            "SELECT MIN(timestamp) FROM events", [], |r| r.get(0)
        ).optional()?.flatten();
        let last_event: Option<String> = self.conn.query_row(
            "SELECT MAX(timestamp) FROM events", [], |r| r.get(0)
        ).optional()?.flatten();

        Ok(ReportStats {
            total_events: total,
            allowed,
            blocked,
            human_required,
            unique_tools,
            unique_agents,
            first_event,
            last_event,
        })
    }
}

pub struct ReportStats {
    pub total_events: u64,
    pub allowed: u64,
    pub blocked: u64,
    pub human_required: u64,
    pub unique_tools: u64,
    pub unique_agents: u64,
    #[allow(dead_code)]
    pub first_event: Option<String>,
    #[allow(dead_code)]
    pub last_event: Option<String>,
}

/// Extension trait for optional query results.
trait OptionalExt<T> {
    fn optional(self) -> Result<Option<T>, rusqlite::Error>;
}

impl<T> OptionalExt<T> for std::result::Result<T, rusqlite::Error> {
    fn optional(self) -> Result<Option<T>, rusqlite::Error> {
        match self {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }
}
