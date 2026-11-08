use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct DeviceRecord {
    pub id: i64,
    pub ip: String,
    pub vendor: String,
    pub last_seen: i64,
    pub fields: Value,
}

/// One protocol endpoint observed on a host.  The legacy `devices` table is a
/// host-level summary for the TUI/web; this record is the authoritative CLI
/// inventory used to resolve an endpoint without conflating services that
/// share an IP address.
#[derive(Debug, Clone)]
pub struct ProtocolRecord {
    pub protocol: String,
    pub port: Option<u16>,
    pub last_seen: i64,
    pub fields: Value,
}

impl DeviceRecord {
    pub fn last_seen_str(&self) -> String {
        if self.last_seen == 0 {
            return "never".to_string();
        }
        chrono::DateTime::from_timestamp(self.last_seen, 0).map_or_else(
            || "?".to_string(),
            |dt| dt.format("%Y-%m-%d %H:%M UTC").to_string(),
        )
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
    pub data_type: Option<String>,
    pub last_value: Option<String>,
    pub last_seen: i64,
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

#[derive(Debug, Clone)]
pub struct MemberRecord {
    pub path: String,
    pub writable: bool,
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
        let conn =
            Connection::open(path).with_context(|| format!("open database {}", path.display()))?;
        // Targeted/network scans can finish concurrently.  Let short SQLite
        // write locks clear instead of silently dropping an observation.
        conn.busy_timeout(Duration::from_secs(5))
            .context("configure database busy timeout")?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS devices (
                 id        INTEGER PRIMARY KEY AUTOINCREMENT,
                 ip        TEXT    NOT NULL UNIQUE,
                 vendor    TEXT    NOT NULL DEFAULT '',
                 last_seen INTEGER NOT NULL DEFAULT 0,
                 fields    TEXT    NOT NULL DEFAULT '{}'
             );
             CREATE TABLE IF NOT EXISTS device_protocols (
                 ip        TEXT    NOT NULL,
                 protocol  TEXT    NOT NULL,
                 port      INTEGER,
                 last_seen INTEGER NOT NULL DEFAULT 0,
                 fields    TEXT    NOT NULL DEFAULT '{}',
                 PRIMARY KEY(ip, protocol)
             );
             CREATE TABLE IF NOT EXISTS device_tags (
                 id          INTEGER PRIMARY KEY AUTOINCREMENT,
                 ip          TEXT    NOT NULL,
                 protocol    TEXT    NOT NULL DEFAULT 'legacy',
                 instance_id INTEGER NOT NULL,
                 name        TEXT    NOT NULL,
                 tag_type    INTEGER NOT NULL,
                 first_seen  INTEGER NOT NULL DEFAULT 0,
                 last_seen   INTEGER NOT NULL DEFAULT 0,
                 UNIQUE(ip, protocol, instance_id)
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
             CREATE TABLE IF NOT EXISTS device_tag_members (
                 id         INTEGER PRIMARY KEY AUTOINCREMENT,
                 ip         TEXT    NOT NULL,
                 protocol   TEXT    NOT NULL DEFAULT 'legacy',
                 path       TEXT    NOT NULL,
                 writable   INTEGER NOT NULL DEFAULT 1,
                 first_seen INTEGER NOT NULL DEFAULT 0,
                 last_seen  INTEGER NOT NULL DEFAULT 0,
                 UNIQUE(ip, protocol, path)
             );
             CREATE TABLE IF NOT EXISTS log (
                 id      INTEGER PRIMARY KEY AUTOINCREMENT,
                 ts      INTEGER NOT NULL,
                 ip      TEXT    NOT NULL DEFAULT '',
                 message TEXT    NOT NULL
             );",
        )
        .context("initialize schema")?;
        migrate_protocol_scoped_tables(&conn)?;
        migrate_device_inventory(&conn)?;
        Ok(Self { conn })
    }

    pub fn default_path() -> PathBuf {
        if let Some(path) = std::env::var_os("SCADAVER_DB_PATH").filter(|path| !path.is_empty()) {
            return PathBuf::from(path);
        }
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("scadaver")
            .join("devices.db")
    }

    /// Save a successful observation without losing other services discovered
    /// on the same host.  The host-level `devices` row remains a projection for
    /// existing TUI/web consumers, while `device_protocols` is authoritative
    /// for protocol-specific CLI target resolution.
    pub fn upsert_protocol_device(&self, ip: &str, protocol: &str, fields: &Value) -> Result<i64> {
        let protocol = canonical_protocol(protocol);
        if protocol == "multi" {
            let protocols = fields
                .get("protocols")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>();
            for child in protocols {
                if let Some(child_fields) = fields.get(child) {
                    let _ = self.upsert_protocol_device(ip, child, child_fields)?;
                }
            }
            return self.device_id(ip);
        }
        if !is_inventory_protocol(&protocol) {
            return self.upsert_device(ip, &protocol, fields);
        }

        let ts = now_unix();
        let mut merged = self
            .load_protocol(ip, &protocol)?
            .map_or_else(empty_object, |record| record.fields);
        merge_object(&mut merged, fields);
        let port = field_port(&merged);
        let fields_json = serde_json::to_string(&merged).unwrap_or_else(|_| "{}".into());
        self.conn.execute(
            "INSERT INTO device_protocols (ip, protocol, port, last_seen, fields)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(ip, protocol) DO UPDATE SET
                 port=excluded.port, last_seen=excluded.last_seen, fields=excluded.fields",
            params![ip, protocol, port, ts, fields_json],
        )?;

        let records = self.load_protocols(ip)?;
        let (vendor, projection) = project_host_inventory(&records);
        self.upsert_device_at(ip, &vendor, ts, &projection)
    }

    pub fn load_protocol(&self, ip: &str, protocol: &str) -> Result<Option<ProtocolRecord>> {
        let protocol = canonical_protocol(protocol);
        self.conn
            .query_row(
                "SELECT ip, protocol, port, last_seen, fields
                 FROM device_protocols WHERE ip=?1 AND protocol=?2",
                params![ip, protocol],
                protocol_record_from_row,
            )
            .optional()
            .context("load protocol inventory")
    }

    pub fn load_protocols(&self, ip: &str) -> Result<Vec<ProtocolRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT ip, protocol, port, last_seen, fields
             FROM device_protocols WHERE ip=?1 ORDER BY protocol",
        )?;
        let rows = stmt.query_map(params![ip], protocol_record_from_row)?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row?);
        }
        Ok(records)
    }

    pub fn protocol_age_secs(&self, ip: &str, protocol: &str) -> Result<Option<u64>> {
        let Some(record) = self.load_protocol(ip, protocol)? else {
            return Ok(None);
        };
        let now = now_unix();
        Ok(Some(now.saturating_sub(record.last_seen).cast_unsigned()))
    }

    pub fn upsert_device(&self, ip: &str, vendor: &str, fields: &Value) -> Result<i64> {
        let ts = now_unix();
        self.upsert_device_at(ip, vendor, ts, fields)
    }

    fn upsert_device_at(&self, ip: &str, vendor: &str, ts: i64, fields: &Value) -> Result<i64> {
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

    fn device_id(&self, ip: &str) -> Result<i64> {
        self.conn
            .query_row("SELECT id FROM devices WHERE ip=?1", params![ip], |r| {
                r.get(0)
            })
            .context("load device id")
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
            let fields: Value = serde_json::from_str(&fields_str)
                .unwrap_or(Value::Object(serde_json::Map::default()));
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
        let ip = self
            .conn
            .query_row("SELECT ip FROM devices WHERE id = ?1", params![id], |row| {
                row.get::<_, String>(0)
            })
            .optional()?;
        if let Some(ip) = ip {
            self.delete_device_by_ip(&ip)?;
        }
        Ok(())
    }

    pub fn delete_device_by_ip(&self, ip: &str) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        for table in [
            "device_protocols",
            "device_tags",
            "device_data",
            "device_tag_members",
            "log",
            "devices",
        ] {
            tx.execute(&format!("DELETE FROM {table} WHERE ip = ?1"), params![ip])?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Upsert a protocol-scoped tag snapshot.  Instance IDs are meaningful
    /// only within one protocol, so this prevents a multi-service host from
    /// deleting or changing another protocol's tags.
    pub fn upsert_tags_for_protocol(
        &self,
        ip: &str,
        protocol: &str,
        tags: &[(i64, &str, i64)],
    ) -> Result<TagDiff> {
        let protocol = canonical_protocol(protocol);
        let now = now_unix();
        let existing = self.load_tags_for_protocol(ip, &protocol)?;
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
                     WHERE ip=?4 AND protocol=?5 AND instance_id=?6",
                    params![name, tag_type, now, ip, protocol, instance_id],
                )?;
            } else {
                added.push(TagRecord {
                    instance_id,
                    name: name.to_string(),
                    tag_type,
                });
                self.conn.execute(
                    "INSERT INTO device_tags (ip, protocol, instance_id, name, tag_type, first_seen, last_seen)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
                    params![ip, protocol, instance_id, name, tag_type, now],
                )?;
            }
        }

        // Tags that existed before but weren't in the current scan are removed
        let removed: Vec<TagRecord> = existing_map.into_values().collect();
        for t in &removed {
            self.conn.execute(
                "DELETE FROM device_tags WHERE ip=?1 AND protocol=?2 AND instance_id=?3",
                params![ip, protocol, t.instance_id],
            )?;
        }

        Ok(TagDiff {
            added,
            removed,
            type_changed,
        })
    }

    pub fn load_tags(&self, ip: &str) -> Result<Vec<TagRecord>> {
        self.load_tags_for_protocol(ip, "legacy")
    }

    pub fn load_tags_for_protocol(&self, ip: &str, protocol: &str) -> Result<Vec<TagRecord>> {
        let protocol = canonical_protocol(protocol);
        let mut stmt = self.conn.prepare(
            "SELECT instance_id, name, tag_type
             FROM device_tags WHERE ip=?1 AND protocol=?2 ORDER BY instance_id",
        )?;
        let rows = stmt.query_map(params![ip, protocol], |r| {
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

    pub fn upsert_members_for_protocol(
        &self,
        ip: &str,
        protocol: &str,
        members: &[(&str, bool)],
    ) -> Result<()> {
        let protocol = canonical_protocol(protocol);
        let now = now_unix();
        self.conn.execute(
            "DELETE FROM device_tag_members WHERE ip=?1 AND protocol=?2",
            params![ip, protocol],
        )?;
        for &(path, writable) in members {
            self.conn.execute(
                "INSERT INTO device_tag_members (ip, protocol, path, writable, first_seen, last_seen)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
                params![ip, protocol, path, i64::from(writable), now],
            )?;
        }
        Ok(())
    }

    /// Load all struct-member leaves for `ip`, ordered by path.
    pub fn load_members(&self, ip: &str) -> Result<Vec<MemberRecord>> {
        self.load_members_for_protocol(ip, "legacy")
    }

    pub fn load_members_for_protocol(&self, ip: &str, protocol: &str) -> Result<Vec<MemberRecord>> {
        let protocol = canonical_protocol(protocol);
        let mut stmt = self.conn.prepare(
            "SELECT path, writable FROM device_tag_members
             WHERE ip=?1 AND protocol=?2 ORDER BY path",
        )?;
        let rows = stmt.query_map(params![ip, protocol], |r| {
            Ok(MemberRecord {
                path: r.get(0)?,
                writable: r.get::<_, i64>(1)? != 0,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Merge a batch of observed data points for a device+protocol.
    ///
    /// A normal CLI/TUI read is usually partial (for example, one Modbus table
    /// or one Mitsubishi address family), so it must not discard observations
    /// made by earlier reads.  Use [`Self::replace_data_points_snapshot`] only
    /// when the caller has an authoritative complete inventory.
    pub fn upsert_data_points(
        &self,
        ip: &str,
        protocol: &str,
        points: &[(&str, Option<&str>, &str)],
    ) -> Result<DataDiff> {
        self.store_data_points(ip, protocol, points, false)
    }

    /// Replace an authoritative complete data-point snapshot for a
    /// device+protocol.
    ///
    /// Unlike [`Self::upsert_data_points`], points absent from `points` are
    /// removed.  This is intentionally explicit because most live reads are
    /// incremental rather than complete snapshots.
    #[allow(dead_code)] // Reserved for callers with a proven complete snapshot.
    pub fn replace_data_points_snapshot(
        &self,
        ip: &str,
        protocol: &str,
        points: &[(&str, Option<&str>, &str)],
    ) -> Result<DataDiff> {
        self.store_data_points(ip, protocol, points, true)
    }

    /// Remove cached values for one device+protocol without touching its
    /// inventory, metadata, or values recorded for other protocols.
    ///
    /// Successful writes are acknowledgements, not proof that a device kept
    /// the requested value.  Callers should invalidate before the next live
    /// observation rather than presenting an old value as post-write truth.
    pub fn invalidate_data_points(&self, ip: &str, protocol: &str) -> Result<usize> {
        Ok(self.conn.execute(
            "DELETE FROM device_data WHERE ip=?1 AND protocol=?2",
            params![ip, canonical_protocol(protocol)],
        )?)
    }

    fn store_data_points(
        &self,
        ip: &str,
        protocol: &str,
        points: &[(&str, Option<&str>, &str)],
        replace_snapshot: bool,
    ) -> Result<DataDiff> {
        let protocol = canonical_protocol(protocol);
        let now = now_unix();
        let existing = self.load_data_points(ip, &protocol)?;
        let mut existing_map: HashMap<String, DataPoint> = existing
            .into_iter()
            .map(|p| (p.address.clone(), p))
            .collect();

        let mut added = Vec::new();
        let mut value_changed = Vec::new();

        for &(address, data_type, value) in points {
            let stored_value = normalize_data_value(&protocol, value);
            if let Some(old) = existing_map.remove(address) {
                let old_value = old
                    .last_value
                    .as_deref()
                    .map(|v| normalize_data_value(&protocol, v));
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
                    data_type: data_type.map(str::to_string),
                    last_value: Some(stored_value.clone()),
                    last_seen: now,
                });
                self.conn.execute(
                    "INSERT INTO device_data (ip, protocol, address, data_type, last_value, first_seen, last_seen)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
                    params![ip, protocol, address, data_type, stored_value, now],
                )?;
            }
        }

        let removed = if replace_snapshot {
            let removed: Vec<DataPoint> = existing_map.into_values().collect();
            for p in &removed {
                self.conn.execute(
                    "DELETE FROM device_data WHERE ip=?1 AND protocol=?2 AND address=?3",
                    params![ip, protocol, p.address],
                )?;
            }
            removed
        } else {
            Vec::new()
        };

        Ok(DataDiff {
            added,
            removed,
            value_changed,
        })
    }

    pub fn load_data_points(&self, ip: &str, protocol: &str) -> Result<Vec<DataPoint>> {
        let mut stmt = self.conn.prepare(
            "SELECT address, data_type, last_value, last_seen
             FROM device_data WHERE ip=?1 AND protocol=?2 ORDER BY address",
        )?;
        let rows = stmt.query_map(params![ip, protocol], |r| {
            Ok(DataPoint {
                address: r.get(0)?,
                data_type: r.get(1)?,
                last_value: r.get(2)?,
                last_seen: r.get(3)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn load_data_point(
        &self,
        ip: &str,
        protocol: &str,
        address: &str,
    ) -> Result<Option<DataPoint>> {
        self.conn
            .query_row(
                "SELECT address, data_type, last_value, last_seen
                 FROM device_data WHERE ip=?1 AND protocol=?2 AND address=?3",
                params![ip, canonical_protocol(protocol), address],
                |r| {
                    Ok(DataPoint {
                        address: r.get(0)?,
                        data_type: r.get(1)?,
                        last_value: r.get(2)?,
                        last_seen: r.get(3)?,
                    })
                },
            )
            .optional()
            .context("load cached data point")
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

fn protocol_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProtocolRecord> {
    let fields_str: String = row.get(4)?;
    Ok(ProtocolRecord {
        protocol: row.get(1)?,
        port: row.get(2)?,
        last_seen: row.get(3)?,
        fields: serde_json::from_str(&fields_str)
            .unwrap_or(Value::Object(serde_json::Map::default())),
    })
}

fn migrate_protocol_scoped_tables(conn: &Connection) -> Result<()> {
    if !table_has_column(conn, "device_tags", "protocol")? {
        conn.execute_batch(
            "BEGIN IMMEDIATE;
             ALTER TABLE device_tags RENAME TO device_tags_legacy;
             CREATE TABLE device_tags (
                 id          INTEGER PRIMARY KEY AUTOINCREMENT,
                 ip          TEXT    NOT NULL,
                 protocol    TEXT    NOT NULL DEFAULT 'legacy',
                 instance_id INTEGER NOT NULL,
                 name        TEXT    NOT NULL,
                 tag_type    INTEGER NOT NULL,
                 first_seen  INTEGER NOT NULL DEFAULT 0,
                 last_seen   INTEGER NOT NULL DEFAULT 0,
                 UNIQUE(ip, protocol, instance_id)
             );
             INSERT INTO device_tags (id, ip, protocol, instance_id, name, tag_type, first_seen, last_seen)
             SELECT id, ip, 'legacy', instance_id, name, tag_type, first_seen, last_seen
             FROM device_tags_legacy;
             DROP TABLE device_tags_legacy;
             COMMIT;",
        )
        .context("migrate device_tags to protocol scope")?;
    }

    if !table_has_column(conn, "device_tag_members", "protocol")? {
        conn.execute_batch(
            "BEGIN IMMEDIATE;
             ALTER TABLE device_tag_members RENAME TO device_tag_members_legacy;
             CREATE TABLE device_tag_members (
                 id         INTEGER PRIMARY KEY AUTOINCREMENT,
                 ip         TEXT    NOT NULL,
                 protocol   TEXT    NOT NULL DEFAULT 'legacy',
                 path       TEXT    NOT NULL,
                 writable   INTEGER NOT NULL DEFAULT 1,
                 first_seen INTEGER NOT NULL DEFAULT 0,
                 last_seen  INTEGER NOT NULL DEFAULT 0,
                 UNIQUE(ip, protocol, path)
             );
             INSERT INTO device_tag_members (id, ip, protocol, path, writable, first_seen, last_seen)
             SELECT id, ip, 'legacy', path, writable, first_seen, last_seen
             FROM device_tag_members_legacy;
             DROP TABLE device_tag_members_legacy;
             COMMIT;",
        )
        .context("migrate device_tag_members to protocol scope")?;
    }
    Ok(())
}

fn migrate_device_inventory(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare("SELECT ip, vendor, last_seen, fields FROM devices")?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;

    let mut legacy = Vec::new();
    for row in rows {
        legacy.push(row?);
    }
    drop(stmt);

    for (ip, vendor, last_seen, fields_json) in legacy {
        let fields: Value =
            serde_json::from_str(&fields_json).unwrap_or(Value::Object(serde_json::Map::default()));
        if vendor.eq_ignore_ascii_case("multi") {
            let protocols = fields
                .get("protocols")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str);
            for protocol in protocols {
                let protocol = canonical_protocol(protocol);
                if !is_inventory_protocol(&protocol) {
                    continue;
                }
                let child = fields.get(&protocol).cloned().unwrap_or_else(empty_object);
                insert_legacy_protocol(conn, &ip, &protocol, last_seen, &child)?;
            }
        } else {
            let protocol = canonical_protocol(&vendor);
            if is_inventory_protocol(&protocol) {
                insert_legacy_protocol(conn, &ip, &protocol, last_seen, &fields)?;
            }
        }
    }
    Ok(())
}

fn insert_legacy_protocol(
    conn: &Connection,
    ip: &str,
    protocol: &str,
    last_seen: i64,
    fields: &Value,
) -> Result<()> {
    let fields_json = serde_json::to_string(fields).unwrap_or_else(|_| "{}".into());
    conn.execute(
        "INSERT OR IGNORE INTO device_protocols (ip, protocol, port, last_seen, fields)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![ip, protocol, field_port(fields), last_seen, fields_json],
    )?;
    Ok(())
}

fn table_has_column(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for name in rows {
        if name?.eq_ignore_ascii_case(column) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn canonical_protocol(protocol: &str) -> String {
    match protocol.trim().to_ascii_lowercase().as_str() {
        "ads" => "beckhoff".into(),
        "enip" | "ethernet_ip" | "ethernet-ip" => "rockwell".into(),
        "fins" => "omron".into(),
        "modicon" => "schneider".into(),
        "opc-ua" => "opcua".into(),
        "s7" => "siemens".into(),
        "slmp" => "mitsubishi".into(),
        "webvisit" => "phoenix".into(),
        other => other.into(),
    }
}

fn is_inventory_protocol(protocol: &str) -> bool {
    matches!(
        protocol,
        "bacnet"
            | "beckhoff"
            | "dnp3"
            | "ewon"
            | "iec104"
            | "mitsubishi"
            | "modbus"
            | "mqtt"
            | "omron"
            | "opcua"
            | "phoenix"
            | "rockwell"
            | "schneider"
            | "siemens"
            | "snmp"
    )
}

fn empty_object() -> Value {
    Value::Object(serde_json::Map::default())
}

fn merge_object(target: &mut Value, incoming: &Value) {
    if !target.is_object() || !incoming.is_object() {
        *target = incoming.clone();
        return;
    }
    let Some(target_map) = target.as_object_mut() else {
        return;
    };
    let Some(incoming_map) = incoming.as_object() else {
        return;
    };
    for (key, incoming_value) in incoming_map {
        match target_map.get_mut(key) {
            Some(existing) => merge_object(existing, incoming_value),
            None => {
                target_map.insert(key.clone(), incoming_value.clone());
            }
        }
    }
}

fn field_port(fields: &Value) -> Option<u16> {
    [
        "port",
        "ads_port",
        "enip_port",
        "fins_port",
        "iec104_port",
        "modbus_port",
        "mqtt_port",
        "s7_port",
        "slmp_port",
        "snmp_port",
        "ewon_web_port",
        "ewon_modbus_port",
        "webvisit_port",
    ]
    .iter()
    .find_map(|key| {
        fields[key]
            .as_u64()
            .and_then(|value| u16::try_from(value).ok())
            .or_else(|| fields[key].as_str()?.parse().ok())
    })
}

fn project_host_inventory(records: &[ProtocolRecord]) -> (String, Value) {
    if let [record] = records {
        return (record.protocol.clone(), record.fields.clone());
    }

    let protocols = records
        .iter()
        .map(|record| Value::String(record.protocol.clone()))
        .collect();
    let mut fields = serde_json::Map::new();
    fields.insert("protocols".into(), Value::Array(protocols));
    for record in records {
        fields.insert(record.protocol.clone(), record.fields.clone());
    }
    ("multi".into(), Value::Object(fields))
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

    #[test]
    fn partial_upserts_retain_prior_observations() {
        let db = memory_db();
        db.upsert_data_points("127.0.0.1", "modbus", &[("hr:40001", Some("UINT16"), "1")])
            .unwrap();
        db.upsert_data_points("127.0.0.1", "modbus", &[("co:1", Some("BOOL"), "ON")])
            .unwrap();

        let points = db.load_data_points("127.0.0.1", "modbus").unwrap();
        assert_eq!(2, points.len());
        assert!(points.iter().any(|point| point.address == "hr:40001"));
        assert!(points.iter().any(|point| point.address == "co:1"));
    }

    #[test]
    fn explicit_snapshot_replacement_removes_omitted_points() {
        let db = memory_db();
        db.upsert_data_points(
            "127.0.0.1",
            "mitsubishi",
            &[("d:0", Some("UINT16"), "0"), ("m:0", Some("BOOL"), "OFF")],
        )
        .unwrap();

        let diff = db
            .replace_data_points_snapshot(
                "127.0.0.1",
                "mitsubishi",
                &[("d:0", Some("UINT16"), "42")],
            )
            .unwrap();

        assert_eq!(1, diff.removed.len());
        assert_eq!("m:0", diff.removed[0].address);
        let points = db.load_data_points("127.0.0.1", "mitsubishi").unwrap();
        assert_eq!(1, points.len());
        assert_eq!("d:0", points[0].address);
        assert_eq!(Some("42"), points[0].last_value.as_deref());
    }

    #[test]
    fn invalidation_is_scoped_to_one_protocol() {
        let db = memory_db();
        db.upsert_data_points("127.0.0.1", "modbus", &[("hr:40001", Some("UINT16"), "1")])
            .unwrap();
        db.upsert_data_points(
            "127.0.0.1",
            "rockwell",
            &[("tag:PUMP_RUN", Some("BOOL"), "true")],
        )
        .unwrap();

        assert_eq!(1, db.invalidate_data_points("127.0.0.1", "modbus").unwrap());
        assert!(db
            .load_data_points("127.0.0.1", "modbus")
            .unwrap()
            .is_empty());
        assert_eq!(
            1,
            db.load_data_points("127.0.0.1", "rockwell").unwrap().len()
        );
    }

    #[test]
    fn protocol_inventory_merges_services_without_overwriting_host_projection() {
        let path = std::env::temp_dir().join(format!(
            "scadaver-db-test-{}-{}.sqlite",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let db = Database::open(&path).unwrap();
        db.upsert_protocol_device(
            "127.0.0.1",
            "modbus",
            &serde_json::json!({"port": 1502, "modbus_port": 1502}),
        )
        .unwrap();
        db.upsert_protocol_device(
            "127.0.0.1",
            "rockwell",
            &serde_json::json!({"port": 14818, "enip_port": 14818}),
        )
        .unwrap();

        let records = db.load_protocols("127.0.0.1").unwrap();
        assert_eq!(2, records.len());
        assert_eq!(
            Some(1502),
            db.load_protocol("127.0.0.1", "modbus")
                .unwrap()
                .unwrap()
                .port
        );
        let host = db.load_devices().unwrap().into_iter().next().unwrap();
        assert_eq!("multi", host.vendor);
        assert_eq!(Some(2), host.fields["protocols"].as_array().map(Vec::len));

        db.upsert_tags_for_protocol("127.0.0.1", "rockwell", &[(1, "PUMP_RUN", 0x00c1)])
            .unwrap();
        db.upsert_tags_for_protocol("127.0.0.1", "modbus", &[(1, "hr:40001", 0)])
            .unwrap();
        assert_eq!(
            1,
            db.load_tags_for_protocol("127.0.0.1", "rockwell")
                .unwrap()
                .len()
        );
        assert_eq!(
            1,
            db.load_tags_for_protocol("127.0.0.1", "modbus")
                .unwrap()
                .len()
        );

        db.upsert_data_points("127.0.0.1", "modbus", &[("hr:40001", Some("UINT16"), "42")])
            .unwrap();
        db.delete_device(host.id).unwrap();
        assert!(db.load_devices().unwrap().is_empty());
        assert!(db.load_protocols("127.0.0.1").unwrap().is_empty());
        assert!(db
            .load_tags_for_protocol("127.0.0.1", "modbus")
            .unwrap()
            .is_empty());
        assert!(db
            .load_data_points("127.0.0.1", "modbus")
            .unwrap()
            .is_empty());

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = std::fs::remove_file(path.with_extension("sqlite-shm"));
    }
}
