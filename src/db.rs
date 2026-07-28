use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct DeviceRecord {
    pub id: i64,
    pub ip: String,
    pub vendor: String,
    pub last_seen: i64,
    pub fields: Value,
}

impl DeviceRecord {
    pub fn last_seen_str(&self) -> String {
        use chrono::{Local, TimeZone};
        if self.last_seen == 0 {
            return "never".to_string();
        }
        match Local.timestamp_opt(self.last_seen, 0) {
            chrono::LocalResult::Single(dt) => dt.format("%Y-%m-%d %H:%M").to_string(),
            _ => "?".to_string(),
        }
    }

}

#[derive(Debug, Clone)]
pub struct TagRecord {
    pub instance_id: i64,
    pub name: String,
    pub tag_type: i64,
}

pub struct TypeChange {
    pub name: String,
    pub old_type: i64,
    pub new_type: i64,
}

pub struct TagDiff {
    pub added: Vec<TagRecord>,
    pub removed: Vec<TagRecord>,
    pub type_changed: Vec<TypeChange>,
}

impl TagDiff {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.type_changed.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct DataPoint {
    pub address: String,
    pub last_value: Option<String>,
}

pub struct ValueChange {
    pub address: String,
    pub old_value: Option<String>,
    pub new_value: String,
}

pub struct DataDiff {
    pub added: Vec<DataPoint>,
    pub removed: Vec<DataPoint>,
    pub value_changed: Vec<ValueChange>,
}

impl DataDiff {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.value_changed.is_empty()
    }
}

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn open(path: &PathBuf) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create DB dir {}", parent.display()))?;
        }
        let conn = Connection::open(path).with_context(|| format!("open database {}", path.display()))?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS devices (
                 id        INTEGER PRIMARY KEY AUTOINCREMENT,
                 ip        TEXT    NOT NULL UNIQUE,
                 vendor    TEXT    NOT NULL DEFAULT '',
                 last_seen INTEGER NOT NULL DEFAULT 0,
                 fields    TEXT    NOT NULL DEFAULT '{}'
             );
             CREATE TABLE IF NOT EXISTS device_tags (
                 id          INTEGER PRIMARY KEY AUTOINCREMENT,
                 ip          TEXT    NOT NULL,
                 instance_id INTEGER NOT NULL,
                 name        TEXT    NOT NULL,
                 tag_type    INTEGER NOT NULL,
                 first_seen  INTEGER NOT NULL DEFAULT 0,
                 last_seen   INTEGER NOT NULL DEFAULT 0,
                 UNIQUE(ip, instance_id)
             );
             CREATE TABLE IF NOT EXISTS device_data (
                 id         INTEGER PRIMARY KEY AUTOINCREMENT,
                 ip         TEXT    NOT NULL,
                 protocol   TEXT    NOT NULL,
                 address    TEXT    NOT NULL,
                 data_type  TEXT,
                 last_value TEXT,
                 first_seen INTEGER NOT NULL DEFAULT 0,
                 last_seen  INTEGER NOT NULL DEFAULT 0,
                 UNIQUE(ip, protocol, address)
             );
             CREATE TABLE IF NOT EXISTS log (
                 id      INTEGER PRIMARY KEY AUTOINCREMENT,
                 ts      INTEGER NOT NULL,
                 ip      TEXT    NOT NULL DEFAULT '',
                 message TEXT    NOT NULL
             );",
        )
        .context("initialize schema")?;
        Ok(Self { conn })
    }

    pub fn default_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("scadaver")
            .join("devices.db")
    }

    pub fn upsert_device(&self, ip: &str, vendor: &str, fields: &Value) -> Result<i64> {
        let ts = now_unix();
        let fields_json = serde_json::to_string(fields).unwrap_or_else(|_| "{}".into());
        self.conn.execute(
            "INSERT INTO devices (ip, vendor, last_seen, fields)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(ip) DO UPDATE SET
                 vendor    = excluded.vendor,
                 last_seen = excluded.last_seen,
                 fields    = excluded.fields",
            params![ip, vendor, ts, fields_json],
        )?;
        let id = self
            .conn
            .query_row("SELECT id FROM devices WHERE ip = ?1", params![ip], |r| {
                r.get(0)
            })?;
        Ok(id)
    }

    pub fn load_devices(&self) -> Result<Vec<DeviceRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ip, vendor, last_seen, fields FROM devices ORDER BY last_seen DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            let fields_str: String = r.get(4)?;
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, fields_str))
        })?;

        let mut devices = Vec::new();
        for row in rows {
            let (id, ip, vendor, last_seen, fields_str) = row?;
            let fields: Value =
                serde_json::from_str(&fields_str).unwrap_or(Value::Object(serde_json::Map::default()));
            devices.push(DeviceRecord {
                id,
                ip,
                vendor,
                last_seen,
                fields,
            });
        }
        Ok(devices)
    }

    pub fn delete_device(&self, id: i64) -> Result<()> {
        self.conn
            .execute("DELETE FROM devices WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Upsert a batch of tags for a device. Returns the diff vs the previous snapshot.
    pub fn upsert_tags(&self, ip: &str, tags: &[(i64, &str, i64)]) -> Result<TagDiff> {
        let now = now_unix();
        let existing = self.load_tags(ip)?;
        let mut existing_map: HashMap<i64, TagRecord> =
            existing.into_iter().map(|t| (t.instance_id, t)).collect();

        let mut added = Vec::new();
        let mut type_changed = Vec::new();

        for &(instance_id, name, tag_type) in tags {
            if let Some(old) = existing_map.remove(&instance_id) {
                if old.tag_type != tag_type {
                    type_changed.push(TypeChange {
                        name: name.to_string(),
                        old_type: old.tag_type,
                        new_type: tag_type,
                    });
                }
                self.conn.execute(
                    "UPDATE device_tags SET name=?1, tag_type=?2, last_seen=?3
                     WHERE ip=?4 AND instance_id=?5",
                    params![name, tag_type, now, ip, instance_id],
                )?;
            } else {
                added.push(TagRecord {
                    instance_id,
                    name: name.to_string(),
                    tag_type,
                });
                self.conn.execute(
                    "INSERT INTO device_tags (ip, instance_id, name, tag_type, first_seen, last_seen)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
                    params![ip, instance_id, name, tag_type, now],
                )?;
            }
        }

        // Tags that existed before but weren't in the current scan are removed
        let removed: Vec<TagRecord> = existing_map.into_values().collect();
        for t in &removed {
            self.conn.execute(
                "DELETE FROM device_tags WHERE ip=?1 AND instance_id=?2",
                params![ip, t.instance_id],
            )?;
        }

        Ok(TagDiff {
            added,
            removed,
            type_changed,
        })
    }

    pub fn load_tags(&self, ip: &str) -> Result<Vec<TagRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT instance_id, name, tag_type
             FROM device_tags WHERE ip=?1 ORDER BY instance_id",
        )?;
        let rows = stmt.query_map(params![ip], |r| {
            Ok(TagRecord {
                instance_id: r.get(0)?,
                name: r.get(1)?,
                tag_type: r.get(2)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Upsert a batch of data points for a device+protocol.
    /// Returns a diff vs the previous snapshot.
    pub fn upsert_data_points(
        &self,
        ip: &str,
        protocol: &str,
        points: &[(&str, Option<&str>, &str)],
    ) -> Result<DataDiff> {
        let now = now_unix();
        let existing = self.load_data_points(ip, protocol)?;
        let mut existing_map: HashMap<String, DataPoint> = existing
            .into_iter()
            .map(|p| (p.address.clone(), p))
            .collect();

        let mut added = Vec::new();
        let mut value_changed = Vec::new();

        for &(address, data_type, value) in points {
            let stored_value = normalize_data_value(protocol, value);
            if let Some(old) = existing_map.remove(address) {
                let old_value = old
                    .last_value
                    .as_deref()
                    .map(|v| normalize_data_value(protocol, v));
                if old_value.as_deref() != Some(stored_value.as_str()) {
                    value_changed.push(ValueChange {
                        address: address.to_string(),
                        old_value: old.last_value.clone(),
                        new_value: stored_value.clone(),
                    });
                }
                self.conn.execute(
                    "UPDATE device_data SET data_type=?1, last_value=?2, last_seen=?3
                     WHERE ip=?4 AND protocol=?5 AND address=?6",
                    params![data_type, stored_value, now, ip, protocol, address],
                )?;
            } else {
                added.push(DataPoint {
                    address: address.to_string(),
                    last_value: Some(stored_value.clone()),
                });
                self.conn.execute(
                    "INSERT INTO device_data (ip, protocol, address, data_type, last_value, first_seen, last_seen)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
                    params![ip, protocol, address, data_type, stored_value, now],
                )?;
            }
        }

        let removed: Vec<DataPoint> = existing_map.into_values().collect();
        for p in &removed {
            self.conn.execute(
                "DELETE FROM device_data WHERE ip=?1 AND protocol=?2 AND address=?3",
                params![ip, protocol, p.address],
            )?;
        }

        Ok(DataDiff {
            added,
            removed,
            value_changed,
        })
    }

    pub fn load_data_points(&self, ip: &str, protocol: &str) -> Result<Vec<DataPoint>> {
        let mut stmt = self.conn.prepare(
            "SELECT address, last_value
             FROM device_data WHERE ip=?1 AND protocol=?2 ORDER BY address",
        )?;
        let rows = stmt.query_map(params![ip, protocol], |r| {
            Ok(DataPoint {
                address: r.get(0)?,
                last_value: r.get(1)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn log(&self, ip: &str, message: &str) -> Result<()> {
        let ts = now_unix();
        self.conn.execute(
            "INSERT INTO log (ts, ip, message) VALUES (?1, ?2, ?3)",
            params![ts, ip, message],
        )?;
        Ok(())
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs().cast_signed())
}

fn normalize_data_value(protocol: &str, value: &str) -> String {
    if protocol.eq_ignore_ascii_case("modbus") {
        normalize_modbus_value(value)
    } else {
        value.to_string()
    }
}

fn normalize_modbus_value(value: &str) -> String {
    let trimmed = value.trim();
    let Some((decimal, hex_suffix)) = trimmed.split_once(" (0x") else {
        return trimmed.to_string();
    };
    let Some(hex) = hex_suffix.strip_suffix(')') else {
        return trimmed.to_string();
    };
    let Ok(decimal_value) = decimal.parse::<u16>() else {
        return trimmed.to_string();
    };
    let Ok(hex_value) = u16::from_str_radix(hex, 16) else {
        return trimmed.to_string();
    };
    if decimal_value == hex_value {
        decimal_value.to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memory_db() -> Database {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE device_data (
                 id         INTEGER PRIMARY KEY AUTOINCREMENT,
                 ip         TEXT    NOT NULL,
                 protocol   TEXT    NOT NULL,
                 address    TEXT    NOT NULL,
                 data_type  TEXT,
                 last_value TEXT,
                 first_seen INTEGER NOT NULL DEFAULT 0,
                 last_seen  INTEGER NOT NULL DEFAULT 0,
                 UNIQUE(ip, protocol, address)
             );",
        )
        .unwrap();
        Database { conn }
    }

    #[test]
    fn modbus_value_normalization_ignores_display_hex_churn() {
        let db = memory_db();
        let first = db
            .upsert_data_points(
                "127.0.0.1",
                "modbus",
                &[("HR40001", Some("UINT16"), "0 (0x0000)")],
            )
            .unwrap();
        assert_eq!(1, first.added.len());

        let second = db
            .upsert_data_points("127.0.0.1", "modbus", &[("HR40001", Some("UINT16"), "0")])
            .unwrap();
        assert!(second.value_changed.is_empty());

        let stored = db.load_data_points("127.0.0.1", "modbus").unwrap();
        assert_eq!(Some("0"), stored[0].last_value.as_deref());
    }

    #[test]
    fn modbus_table_prefixed_addresses_do_not_collide() {
        let db = memory_db();
        let diff = db
            .upsert_data_points(
                "127.0.0.1",
                "modbus",
                &[
                    ("HR40001", Some("UINT16"), "1"),
                    ("IR40001", Some("UINT16"), "2"),
                    ("CO10001", Some("BOOL"), "OFF"),
                    ("DI10001", Some("BOOL"), "ON"),
                ],
            )
            .unwrap();

        assert_eq!(4, diff.added.len());
        assert_eq!(4, db.load_data_points("127.0.0.1", "modbus").unwrap().len());
    }
}
