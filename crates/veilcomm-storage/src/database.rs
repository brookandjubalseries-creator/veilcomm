//! SQLite database for VeilComm
//!
//! Stores contacts, messages, sessions, groups, and sender keys.

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::error::{Error, Result};

/// Parse an RFC 3339 timestamp string, returning a rusqlite-compatible error.
/// Suitable for use inside rusqlite row-mapping closures.
fn parse_timestamp_row(s: &str) -> std::result::Result<DateTime<Utc>, rusqlite::Error> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            Box::new(e),
        ))
}

/// Contact information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Contact {
    pub fingerprint: String,
    pub name: Option<String>,
    pub identity_key: Vec<u8>,
    pub verified: bool,
    pub created_at: DateTime<Utc>,
    pub last_seen: Option<DateTime<Utc>>,
}

/// Stored message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredMessage {
    pub id: String,
    pub contact_fingerprint: String,
    pub outgoing: bool,
    pub content: Vec<u8>, // Encrypted content
    pub timestamp: DateTime<Utc>,
    pub read: bool,
    pub delivery_status: String,
}

/// Stored session state
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredSession {
    pub peer_fingerprint: String,
    pub state: Vec<u8>, // Encrypted session state
    pub associated_data: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
}

/// Stored group information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredGroup {
    pub group_id: String,
    pub name: String,
    pub creator_fingerprint: String,
    pub created_at: DateTime<Utc>,
    pub max_members: u32,
}

/// Stored group member
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredGroupMember {
    pub group_id: String,
    pub fingerprint: String,
    pub name: Option<String>,
    pub role: String,
    pub joined_at: DateTime<Utc>,
}

/// Stored group message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredGroupMessage {
    pub id: String,
    pub group_id: String,
    pub sender_fingerprint: String,
    pub content: Vec<u8>,
    pub timestamp: DateTime<Utc>,
    pub read: bool,
}

/// Stored dead man's switch
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredDeadManSwitch {
    pub id: String,
    pub recipient_fingerprints: Vec<String>,
    pub message: String,
    pub check_in_interval_secs: i64,
    pub last_check_in: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub enabled: bool,
    pub triggered: bool,
}

/// Stored sender key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredSenderKey {
    pub group_id: String,
    pub member_fingerprint: String,
    pub chain_key: Vec<u8>,
    pub signing_public_key: Vec<u8>,
    pub chain_index: u32,
    pub skipped_keys: Vec<u8>,
    pub updated_at: DateTime<Utc>,
}

/// VeilComm database
pub struct Database {
    conn: Connection,
}

impl Database {
    /// Open or create a database at the given path
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path)?;
        let db = Self { conn };
        db.init_schema()?;
        Ok(db)
    }

    /// Create an in-memory database (for testing)
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn };
        db.init_schema()?;
        Ok(db)
    }

    /// Initialize the database schema
    fn init_schema(&self) -> Result<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS contacts (
                fingerprint TEXT PRIMARY KEY,
                name TEXT,
                identity_key BLOB NOT NULL,
                verified INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                last_seen TEXT
            );

            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                contact_fingerprint TEXT NOT NULL,
                outgoing INTEGER NOT NULL,
                content BLOB NOT NULL,
                timestamp TEXT NOT NULL,
                read INTEGER NOT NULL DEFAULT 0,
                delivery_status TEXT NOT NULL DEFAULT 'delivered',
                FOREIGN KEY (contact_fingerprint) REFERENCES contacts(fingerprint)
            );

            CREATE INDEX IF NOT EXISTS idx_messages_contact ON messages(contact_fingerprint);
            CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);

            CREATE TABLE IF NOT EXISTS sessions (
                peer_fingerprint TEXT PRIMARY KEY,
                state BLOB NOT NULL,
                associated_data BLOB NOT NULL,
                created_at TEXT NOT NULL,
                last_activity TEXT NOT NULL,
                FOREIGN KEY (peer_fingerprint) REFERENCES contacts(fingerprint)
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS groups (
                group_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                creator_fingerprint TEXT NOT NULL,
                created_at TEXT NOT NULL,
                max_members INTEGER NOT NULL DEFAULT 100
            );

            CREATE TABLE IF NOT EXISTS group_members (
                group_id TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                name TEXT,
                role TEXT NOT NULL DEFAULT 'member',
                joined_at TEXT NOT NULL,
                PRIMARY KEY (group_id, fingerprint),
                FOREIGN KEY (group_id) REFERENCES groups(group_id)
            );

            CREATE TABLE IF NOT EXISTS group_messages (
                id TEXT PRIMARY KEY,
                group_id TEXT NOT NULL,
                sender_fingerprint TEXT NOT NULL,
                content BLOB NOT NULL,
                timestamp TEXT NOT NULL,
                read INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (group_id) REFERENCES groups(group_id)
            );

            CREATE INDEX IF NOT EXISTS idx_group_messages_group ON group_messages(group_id);
            CREATE INDEX IF NOT EXISTS idx_group_messages_timestamp ON group_messages(timestamp);

            CREATE TABLE IF NOT EXISTS dead_man_switches (
                id TEXT PRIMARY KEY,
                recipient_fingerprints TEXT NOT NULL,
                message TEXT NOT NULL,
                check_in_interval_secs INTEGER NOT NULL,
                last_check_in TEXT NOT NULL,
                created_at TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                triggered INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS sender_keys (
                group_id TEXT NOT NULL,
                member_fingerprint TEXT NOT NULL,
                chain_key BLOB NOT NULL,
                signing_public_key BLOB NOT NULL,
                chain_index INTEGER NOT NULL DEFAULT 0,
                skipped_keys BLOB NOT NULL DEFAULT x'',
                updated_at TEXT NOT NULL,
                PRIMARY KEY (group_id, member_fingerprint)
            );
            "#,
        )?;

        // Migration: add delivery_status column if not exists
        // (for databases created before this column was added)
        let _ = self.conn.execute(
            "ALTER TABLE messages ADD COLUMN delivery_status TEXT NOT NULL DEFAULT 'delivered'",
            [],
        );

        Ok(())
    }

    // ==================== Contacts ====================

    /// Add a new contact
    pub fn add_contact(&self, contact: &Contact) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT INTO contacts (fingerprint, name, identity_key, verified, created_at, last_seen)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            params![
                contact.fingerprint,
                contact.name,
                contact.identity_key,
                contact.verified as i32,
                contact.created_at.to_rfc3339(),
                contact.last_seen.map(|t| t.to_rfc3339()),
            ],
        )?;
        Ok(())
    }

    /// Get a contact by fingerprint
    pub fn get_contact(&self, fingerprint: &str) -> Result<Option<Contact>> {
        let result = self
            .conn
            .query_row(
                r#"
                SELECT fingerprint, name, identity_key, verified, created_at, last_seen
                FROM contacts WHERE fingerprint = ?1
                "#,
                params![fingerprint],
                |row| {
                    let last_seen = if let Some(s) = row.get::<_, Option<String>>(5)? {
                        Some(parse_timestamp_row(&s)?)
                    } else {
                        None
                    };
                    Ok(Contact {
                        fingerprint: row.get(0)?,
                        name: row.get(1)?,
                        identity_key: row.get(2)?,
                        verified: row.get::<_, i32>(3)? != 0,
                        created_at: parse_timestamp_row(&row.get::<_, String>(4)?)?,
                        last_seen,
                    })
                },
            )
            .optional()?;
        Ok(result)
    }

    /// List all contacts
    pub fn list_contacts(&self) -> Result<Vec<Contact>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT fingerprint, name, identity_key, verified, created_at, last_seen
            FROM contacts ORDER BY name, fingerprint
            "#,
        )?;

        let contacts = stmt
            .query_map([], |row| {
                let last_seen = if let Some(s) = row.get::<_, Option<String>>(5)? {
                    Some(parse_timestamp_row(&s)?)
                } else {
                    None
                };
                Ok(Contact {
                    fingerprint: row.get(0)?,
                    name: row.get(1)?,
                    identity_key: row.get(2)?,
                    verified: row.get::<_, i32>(3)? != 0,
                    created_at: parse_timestamp_row(&row.get::<_, String>(4)?)?,
                    last_seen,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(contacts)
    }

    /// Update a contact's name
    pub fn update_contact_name(&self, fingerprint: &str, name: Option<&str>) -> Result<()> {
        let rows = self.conn.execute(
            "UPDATE contacts SET name = ?1 WHERE fingerprint = ?2",
            params![name, fingerprint],
        )?;

        if rows == 0 {
            return Err(Error::ContactNotFound(fingerprint.to_string()));
        }

        Ok(())
    }

    /// Mark a contact as verified
    pub fn verify_contact(&self, fingerprint: &str, verified: bool) -> Result<()> {
        let rows = self.conn.execute(
            "UPDATE contacts SET verified = ?1 WHERE fingerprint = ?2",
            params![verified as i32, fingerprint],
        )?;

        if rows == 0 {
            return Err(Error::ContactNotFound(fingerprint.to_string()));
        }

        Ok(())
    }

    /// Update contact's last seen time
    pub fn update_contact_last_seen(&self, fingerprint: &str) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "UPDATE contacts SET last_seen = ?1 WHERE fingerprint = ?2",
            params![now, fingerprint],
        )?;
        Ok(())
    }

    /// Remove a contact
    pub fn remove_contact(&self, fingerprint: &str) -> Result<()> {
        // Also remove associated messages and sessions
        self.conn.execute(
            "DELETE FROM messages WHERE contact_fingerprint = ?1",
            params![fingerprint],
        )?;
        self.conn.execute(
            "DELETE FROM sessions WHERE peer_fingerprint = ?1",
            params![fingerprint],
        )?;
        self.conn
            .execute("DELETE FROM contacts WHERE fingerprint = ?1", params![fingerprint])?;
        Ok(())
    }

    // ==================== Messages ====================

    /// Store a message
    pub fn store_message(&self, message: &StoredMessage) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT INTO messages (id, contact_fingerprint, outgoing, content, timestamp, read, delivery_status)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
            params![
                message.id,
                message.contact_fingerprint,
                message.outgoing as i32,
                message.content,
                message.timestamp.to_rfc3339(),
                message.read as i32,
                message.delivery_status,
            ],
        )?;
        Ok(())
    }

    /// Get messages for a contact
    pub fn get_messages(&self, contact_fingerprint: &str, limit: u32) -> Result<Vec<StoredMessage>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, contact_fingerprint, outgoing, content, timestamp, read, delivery_status
            FROM messages
            WHERE contact_fingerprint = ?1
            ORDER BY timestamp DESC
            LIMIT ?2
            "#,
        )?;

        let messages = stmt
            .query_map(params![contact_fingerprint, limit], |row| {
                Ok(StoredMessage {
                    id: row.get(0)?,
                    contact_fingerprint: row.get(1)?,
                    outgoing: row.get::<_, i32>(2)? != 0,
                    content: row.get(3)?,
                    timestamp: parse_timestamp_row(&row.get::<_, String>(4)?)?,
                    read: row.get::<_, i32>(5)? != 0,
                    delivery_status: row.get::<_, String>(6).unwrap_or_else(|_| "delivered".to_string()),
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(messages)
    }

    /// Mark messages as read
    pub fn mark_messages_read(&self, contact_fingerprint: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE messages SET read = 1 WHERE contact_fingerprint = ?1 AND outgoing = 0",
            params![contact_fingerprint],
        )?;
        Ok(())
    }

    /// Get unread message count
    pub fn unread_count(&self, contact_fingerprint: &str) -> Result<u32> {
        let count: u32 = self.conn.query_row(
            "SELECT COUNT(*) FROM messages WHERE contact_fingerprint = ?1 AND outgoing = 0 AND read = 0",
            params![contact_fingerprint],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Delete old messages (older than given timestamp)
    pub fn delete_old_messages(&self, before: DateTime<Utc>) -> Result<u32> {
        let rows = self.conn.execute(
            "DELETE FROM messages WHERE timestamp < ?1",
            params![before.to_rfc3339()],
        )?;
        Ok(rows as u32)
    }

    /// Update delivery status of a message
    pub fn update_delivery_status(&self, message_id: &str, status: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE messages SET delivery_status = ?1 WHERE id = ?2",
            params![status, message_id],
        )?;
        Ok(())
    }

    /// Get all pending messages (for retry)
    pub fn get_pending_messages(&self) -> Result<Vec<StoredMessage>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, contact_fingerprint, outgoing, content, timestamp, read, delivery_status
            FROM messages
            WHERE delivery_status IN ('pending', 'sent_to_dht')
            ORDER BY timestamp ASC
            "#,
        )?;

        let messages = stmt
            .query_map([], |row| {
                Ok(StoredMessage {
                    id: row.get(0)?,
                    contact_fingerprint: row.get(1)?,
                    outgoing: row.get::<_, i32>(2)? != 0,
                    content: row.get(3)?,
                    timestamp: parse_timestamp_row(&row.get::<_, String>(4)?)?,
                    read: row.get::<_, i32>(5)? != 0,
                    delivery_status: row.get(6)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(messages)
    }

    // ==================== Sessions ====================

    /// Store or update a session
    pub fn store_session(&self, session: &StoredSession) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT OR REPLACE INTO sessions (peer_fingerprint, state, associated_data, created_at, last_activity)
            VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
            params![
                session.peer_fingerprint,
                session.state,
                session.associated_data,
                session.created_at.to_rfc3339(),
                session.last_activity.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Get a session by peer fingerprint
    pub fn get_session(&self, peer_fingerprint: &str) -> Result<Option<StoredSession>> {
        let result = self
            .conn
            .query_row(
                r#"
                SELECT peer_fingerprint, state, associated_data, created_at, last_activity
                FROM sessions WHERE peer_fingerprint = ?1
                "#,
                params![peer_fingerprint],
                |row| {
                    Ok(StoredSession {
                        peer_fingerprint: row.get(0)?,
                        state: row.get(1)?,
                        associated_data: row.get(2)?,
                        created_at: parse_timestamp_row(&row.get::<_, String>(3)?)?,
                        last_activity: parse_timestamp_row(&row.get::<_, String>(4)?)?,
                    })
                },
            )
            .optional()?;
        Ok(result)
    }

    /// Delete a session
    pub fn delete_session(&self, peer_fingerprint: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM sessions WHERE peer_fingerprint = ?1",
            params![peer_fingerprint],
        )?;
        Ok(())
    }

    // ==================== Settings ====================

    /// Set a setting value
    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    /// Get a setting value
    pub fn get_setting(&self, key: &str) -> Result<Option<String>> {
        let result = self
            .conn
            .query_row(
                "SELECT value FROM settings WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?;
        Ok(result)
    }

    // ==================== Groups ====================

    /// Create a new group
    pub fn create_group(&self, group: &StoredGroup) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT INTO groups (group_id, name, creator_fingerprint, created_at, max_members)
            VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
            params![
                group.group_id,
                group.name,
                group.creator_fingerprint,
                group.created_at.to_rfc3339(),
                group.max_members,
            ],
        )?;
        Ok(())
    }

    /// Get a group by ID
    pub fn get_group(&self, group_id: &str) -> Result<Option<StoredGroup>> {
        let result = self
            .conn
            .query_row(
                "SELECT group_id, name, creator_fingerprint, created_at, max_members FROM groups WHERE group_id = ?1",
                params![group_id],
                |row| {
                    Ok(StoredGroup {
                        group_id: row.get(0)?,
                        name: row.get(1)?,
                        creator_fingerprint: row.get(2)?,
                        created_at: parse_timestamp_row(&row.get::<_, String>(3)?)?,
                        max_members: row.get(4)?,
                    })
                },
            )
            .optional()?;
        Ok(result)
    }

    /// List all groups
    pub fn list_groups(&self) -> Result<Vec<StoredGroup>> {
        let mut stmt = self.conn.prepare(
            "SELECT group_id, name, creator_fingerprint, created_at, max_members FROM groups ORDER BY name",
        )?;

        let groups = stmt
            .query_map([], |row| {
                Ok(StoredGroup {
                    group_id: row.get(0)?,
                    name: row.get(1)?,
                    creator_fingerprint: row.get(2)?,
                    created_at: parse_timestamp_row(&row.get::<_, String>(3)?)?,
                    max_members: row.get(4)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(groups)
    }

    /// Delete a group and all associated data
    pub fn delete_group(&self, group_id: &str) -> Result<()> {
        self.conn.execute("DELETE FROM group_messages WHERE group_id = ?1", params![group_id])?;
        self.conn.execute("DELETE FROM group_members WHERE group_id = ?1", params![group_id])?;
        self.conn.execute("DELETE FROM sender_keys WHERE group_id = ?1", params![group_id])?;
        self.conn.execute("DELETE FROM groups WHERE group_id = ?1", params![group_id])?;
        Ok(())
    }

    /// Add a member to a group
    pub fn add_group_member(&self, member: &StoredGroupMember) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT OR REPLACE INTO group_members (group_id, fingerprint, name, role, joined_at)
            VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
            params![
                member.group_id,
                member.fingerprint,
                member.name,
                member.role,
                member.joined_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Remove a member from a group
    pub fn remove_group_member(&self, group_id: &str, fingerprint: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM group_members WHERE group_id = ?1 AND fingerprint = ?2",
            params![group_id, fingerprint],
        )?;
        Ok(())
    }

    /// Get all members of a group
    pub fn get_group_members(&self, group_id: &str) -> Result<Vec<StoredGroupMember>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT group_id, fingerprint, name, role, joined_at
            FROM group_members WHERE group_id = ?1 ORDER BY joined_at
            "#,
        )?;

        let members = stmt
            .query_map(params![group_id], |row| {
                Ok(StoredGroupMember {
                    group_id: row.get(0)?,
                    fingerprint: row.get(1)?,
                    name: row.get(2)?,
                    role: row.get(3)?,
                    joined_at: parse_timestamp_row(&row.get::<_, String>(4)?)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(members)
    }

    /// Store a group message
    pub fn store_group_message(&self, message: &StoredGroupMessage) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT INTO group_messages (id, group_id, sender_fingerprint, content, timestamp, read)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            params![
                message.id,
                message.group_id,
                message.sender_fingerprint,
                message.content,
                message.timestamp.to_rfc3339(),
                message.read as i32,
            ],
        )?;
        Ok(())
    }

    /// Get messages for a group
    pub fn get_group_messages(&self, group_id: &str, limit: u32) -> Result<Vec<StoredGroupMessage>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, group_id, sender_fingerprint, content, timestamp, read
            FROM group_messages
            WHERE group_id = ?1
            ORDER BY timestamp DESC
            LIMIT ?2
            "#,
        )?;

        let messages = stmt
            .query_map(params![group_id, limit], |row| {
                Ok(StoredGroupMessage {
                    id: row.get(0)?,
                    group_id: row.get(1)?,
                    sender_fingerprint: row.get(2)?,
                    content: row.get(3)?,
                    timestamp: parse_timestamp_row(&row.get::<_, String>(4)?)?,
                    read: row.get::<_, i32>(5)? != 0,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(messages)
    }

    /// Mark group messages as read
    pub fn mark_group_messages_read(&self, group_id: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE group_messages SET read = 1 WHERE group_id = ?1 AND read = 0",
            params![group_id],
        )?;
        Ok(())
    }

    /// Get unread group message count
    pub fn unread_group_count(&self, group_id: &str) -> Result<u32> {
        let count: u32 = self.conn.query_row(
            "SELECT COUNT(*) FROM group_messages WHERE group_id = ?1 AND read = 0",
            params![group_id],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Store a sender key
    pub fn store_sender_key(&self, sk: &StoredSenderKey) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT OR REPLACE INTO sender_keys
                (group_id, member_fingerprint, chain_key, signing_public_key, chain_index, skipped_keys, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
            params![
                sk.group_id,
                sk.member_fingerprint,
                sk.chain_key,
                sk.signing_public_key,
                sk.chain_index,
                sk.skipped_keys,
                sk.updated_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Get a sender key
    pub fn get_sender_key(&self, group_id: &str, member_fingerprint: &str) -> Result<Option<StoredSenderKey>> {
        let result = self
            .conn
            .query_row(
                r#"
                SELECT group_id, member_fingerprint, chain_key, signing_public_key, chain_index, skipped_keys, updated_at
                FROM sender_keys WHERE group_id = ?1 AND member_fingerprint = ?2
                "#,
                params![group_id, member_fingerprint],
                |row| {
                    Ok(StoredSenderKey {
                        group_id: row.get(0)?,
                        member_fingerprint: row.get(1)?,
                        chain_key: row.get(2)?,
                        signing_public_key: row.get(3)?,
                        chain_index: row.get(4)?,
                        skipped_keys: row.get(5)?,
                        updated_at: parse_timestamp_row(&row.get::<_, String>(6)?)?,
                    })
                },
            )
            .optional()?;
        Ok(result)
    }

    /// Delete all sender keys for a group
    pub fn delete_sender_keys_for_group(&self, group_id: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM sender_keys WHERE group_id = ?1",
            params![group_id],
        )?;
        Ok(())
    }

    // ==================== Dead Man's Switches ====================

    /// Create a dead man's switch
    pub fn create_dead_man_switch(&self, dms: &StoredDeadManSwitch) -> Result<()> {
        let recipients_json = serde_json::to_string(&dms.recipient_fingerprints)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        self.conn.execute(
            r#"
            INSERT INTO dead_man_switches (id, recipient_fingerprints, message, check_in_interval_secs, last_check_in, created_at, enabled, triggered)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                dms.id,
                recipients_json,
                dms.message,
                dms.check_in_interval_secs,
                dms.last_check_in.to_rfc3339(),
                dms.created_at.to_rfc3339(),
                dms.enabled as i32,
                dms.triggered as i32,
            ],
        )?;
        Ok(())
    }

    /// Get a dead man's switch by ID
    pub fn get_dead_man_switch(&self, id: &str) -> Result<Option<StoredDeadManSwitch>> {
        let result = self
            .conn
            .query_row(
                "SELECT id, recipient_fingerprints, message, check_in_interval_secs, last_check_in, created_at, enabled, triggered FROM dead_man_switches WHERE id = ?1",
                params![id],
                |row| {
                    let recipients_json: String = row.get(1)?;
                    let recipients: Vec<String> = serde_json::from_str(&recipients_json)
                        .unwrap_or_default();
                    Ok(StoredDeadManSwitch {
                        id: row.get(0)?,
                        recipient_fingerprints: recipients,
                        message: row.get(2)?,
                        check_in_interval_secs: row.get(3)?,
                        last_check_in: parse_timestamp_row(&row.get::<_, String>(4)?)?,
                        created_at: parse_timestamp_row(&row.get::<_, String>(5)?)?,
                        enabled: row.get::<_, i32>(6)? != 0,
                        triggered: row.get::<_, i32>(7)? != 0,
                    })
                },
            )
            .optional()?;
        Ok(result)
    }

    /// List all dead man's switches
    pub fn list_dead_man_switches(&self) -> Result<Vec<StoredDeadManSwitch>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, recipient_fingerprints, message, check_in_interval_secs, last_check_in, created_at, enabled, triggered FROM dead_man_switches ORDER BY created_at",
        )?;

        let switches = stmt
            .query_map([], |row| {
                let recipients_json: String = row.get(1)?;
                let recipients: Vec<String> = serde_json::from_str(&recipients_json)
                    .unwrap_or_default();
                Ok(StoredDeadManSwitch {
                    id: row.get(0)?,
                    recipient_fingerprints: recipients,
                    message: row.get(2)?,
                    check_in_interval_secs: row.get(3)?,
                    last_check_in: parse_timestamp_row(&row.get::<_, String>(4)?)?,
                    created_at: parse_timestamp_row(&row.get::<_, String>(5)?)?,
                    enabled: row.get::<_, i32>(6)? != 0,
                    triggered: row.get::<_, i32>(7)? != 0,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(switches)
    }

    /// Update check-in time for a dead man's switch
    pub fn check_in_dead_man_switch(&self, id: &str) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "UPDATE dead_man_switches SET last_check_in = ?1 WHERE id = ?2",
            params![now, id],
        )?;
        Ok(())
    }

    /// Mark a dead man's switch as triggered
    pub fn trigger_dead_man_switch(&self, id: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE dead_man_switches SET triggered = 1, enabled = 0 WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }

    /// Delete a dead man's switch
    pub fn delete_dead_man_switch(&self, id: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM dead_man_switches WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }

    /// Toggle a dead man's switch enabled/disabled
    pub fn toggle_dead_man_switch(&self, id: &str, enabled: bool) -> Result<()> {
        self.conn.execute(
            "UPDATE dead_man_switches SET enabled = ?1 WHERE id = ?2",
            params![enabled as i32, id],
        )?;
        Ok(())
    }

    /// Get expired (overdue) dead man's switches that need triggering
    pub fn get_expired_dead_man_switches(&self) -> Result<Vec<StoredDeadManSwitch>> {
        let now = Utc::now();
        let all = self.list_dead_man_switches()?;
        Ok(all
            .into_iter()
            .filter(|dms| {
                dms.enabled
                    && !dms.triggered
                    && (now - dms.last_check_in).num_seconds() > dms.check_in_interval_secs
            })
            .collect())
    }

    /// Update sender key state (chain_key, chain_index, skipped_keys)
    pub fn update_sender_key_state(
        &self,
        group_id: &str,
        member_fingerprint: &str,
        chain_key: &[u8],
        chain_index: u32,
        skipped_keys: &[u8],
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            r#"
            UPDATE sender_keys SET chain_key = ?1, chain_index = ?2, skipped_keys = ?3, updated_at = ?4
            WHERE group_id = ?5 AND member_fingerprint = ?6
            "#,
            params![chain_key, chain_index, skipped_keys, now, group_id, member_fingerprint],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_contact() -> Contact {
        Contact {
            fingerprint: "abc123".to_string(),
            name: Some("Alice".to_string()),
            identity_key: vec![1, 2, 3, 4],
            verified: false,
            created_at: Utc::now(),
            last_seen: None,
        }
    }

    #[test]
    fn test_contact_crud() {
        let db = Database::in_memory().unwrap();
        let contact = create_test_contact();

        // Add
        db.add_contact(&contact).unwrap();

        // Get
        let retrieved = db.get_contact(&contact.fingerprint).unwrap().unwrap();
        assert_eq!(retrieved.name, contact.name);
        assert_eq!(retrieved.fingerprint, contact.fingerprint);

        // Update name
        db.update_contact_name(&contact.fingerprint, Some("Bob"))
            .unwrap();
        let updated = db.get_contact(&contact.fingerprint).unwrap().unwrap();
        assert_eq!(updated.name, Some("Bob".to_string()));

        // Verify
        db.verify_contact(&contact.fingerprint, true).unwrap();
        let verified = db.get_contact(&contact.fingerprint).unwrap().unwrap();
        assert!(verified.verified);

        // List
        let contacts = db.list_contacts().unwrap();
        assert_eq!(contacts.len(), 1);

        // Remove
        db.remove_contact(&contact.fingerprint).unwrap();
        let removed = db.get_contact(&contact.fingerprint).unwrap();
        assert!(removed.is_none());
    }

    #[test]
    fn test_messages() {
        let db = Database::in_memory().unwrap();
        let contact = create_test_contact();
        db.add_contact(&contact).unwrap();

        // Store messages
        for i in 0..5 {
            let msg = StoredMessage {
                id: format!("msg_{}", i),
                contact_fingerprint: contact.fingerprint.clone(),
                outgoing: i % 2 == 0,
                content: format!("Message {}", i).into_bytes(),
                timestamp: Utc::now(),
                read: false,
                delivery_status: "delivered".to_string(),
            };
            db.store_message(&msg).unwrap();
        }

        // Get messages
        let messages = db.get_messages(&contact.fingerprint, 10).unwrap();
        assert_eq!(messages.len(), 5);

        // Unread count (incoming messages only)
        let unread = db.unread_count(&contact.fingerprint).unwrap();
        assert_eq!(unread, 2); // Messages 1 and 3 are incoming

        // Mark as read
        db.mark_messages_read(&contact.fingerprint).unwrap();
        let unread = db.unread_count(&contact.fingerprint).unwrap();
        assert_eq!(unread, 0);
    }

    #[test]
    fn test_delivery_status() {
        let db = Database::in_memory().unwrap();
        let contact = create_test_contact();
        db.add_contact(&contact).unwrap();

        let msg = StoredMessage {
            id: "msg_pending".to_string(),
            contact_fingerprint: contact.fingerprint.clone(),
            outgoing: true,
            content: b"Hello".to_vec(),
            timestamp: Utc::now(),
            read: true,
            delivery_status: "pending".to_string(),
        };
        db.store_message(&msg).unwrap();

        // Check pending
        let pending = db.get_pending_messages().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].delivery_status, "pending");

        // Update status
        db.update_delivery_status("msg_pending", "sent_to_dht").unwrap();
        let pending = db.get_pending_messages().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].delivery_status, "sent_to_dht");

        // Mark delivered
        db.update_delivery_status("msg_pending", "delivered").unwrap();
        let pending = db.get_pending_messages().unwrap();
        assert_eq!(pending.len(), 0);
    }

    #[test]
    fn test_sessions() {
        let db = Database::in_memory().unwrap();
        let contact = create_test_contact();
        db.add_contact(&contact).unwrap();

        let session = StoredSession {
            peer_fingerprint: contact.fingerprint.clone(),
            state: vec![1, 2, 3, 4, 5],
            associated_data: vec![6, 7, 8],
            created_at: Utc::now(),
            last_activity: Utc::now(),
        };

        // Store
        db.store_session(&session).unwrap();

        // Get
        let retrieved = db.get_session(&contact.fingerprint).unwrap().unwrap();
        assert_eq!(retrieved.state, session.state);
        assert_eq!(retrieved.associated_data, session.associated_data);

        // Delete
        db.delete_session(&contact.fingerprint).unwrap();
        let deleted = db.get_session(&contact.fingerprint).unwrap();
        assert!(deleted.is_none());
    }

    #[test]
    fn test_settings() {
        let db = Database::in_memory().unwrap();

        db.set_setting("username", "alice").unwrap();
        let value = db.get_setting("username").unwrap();
        assert_eq!(value, Some("alice".to_string()));

        // Update
        db.set_setting("username", "bob").unwrap();
        let value = db.get_setting("username").unwrap();
        assert_eq!(value, Some("bob".to_string()));

        // Non-existent
        let missing = db.get_setting("nonexistent").unwrap();
        assert!(missing.is_none());
    }

    #[test]
    fn test_group_crud() {
        let db = Database::in_memory().unwrap();

        let group = StoredGroup {
            group_id: "grp-001".to_string(),
            name: "Test Group".to_string(),
            creator_fingerprint: "alice_fp".to_string(),
            created_at: Utc::now(),
            max_members: 100,
        };

        // Create
        db.create_group(&group).unwrap();

        // Get
        let retrieved = db.get_group("grp-001").unwrap().unwrap();
        assert_eq!(retrieved.name, "Test Group");
        assert_eq!(retrieved.creator_fingerprint, "alice_fp");

        // List
        let groups = db.list_groups().unwrap();
        assert_eq!(groups.len(), 1);

        // Delete
        db.delete_group("grp-001").unwrap();
        let deleted = db.get_group("grp-001").unwrap();
        assert!(deleted.is_none());
    }

    #[test]
    fn test_group_members() {
        let db = Database::in_memory().unwrap();

        let group = StoredGroup {
            group_id: "grp-001".to_string(),
            name: "Test Group".to_string(),
            creator_fingerprint: "alice_fp".to_string(),
            created_at: Utc::now(),
            max_members: 100,
        };
        db.create_group(&group).unwrap();

        // Add members
        let member1 = StoredGroupMember {
            group_id: "grp-001".to_string(),
            fingerprint: "alice_fp".to_string(),
            name: Some("Alice".to_string()),
            role: "admin".to_string(),
            joined_at: Utc::now(),
        };
        let member2 = StoredGroupMember {
            group_id: "grp-001".to_string(),
            fingerprint: "bob_fp".to_string(),
            name: Some("Bob".to_string()),
            role: "member".to_string(),
            joined_at: Utc::now(),
        };
        db.add_group_member(&member1).unwrap();
        db.add_group_member(&member2).unwrap();

        // Get members
        let members = db.get_group_members("grp-001").unwrap();
        assert_eq!(members.len(), 2);

        // Remove member
        db.remove_group_member("grp-001", "bob_fp").unwrap();
        let members = db.get_group_members("grp-001").unwrap();
        assert_eq!(members.len(), 1);
    }

    #[test]
    fn test_group_messages() {
        let db = Database::in_memory().unwrap();

        let group = StoredGroup {
            group_id: "grp-001".to_string(),
            name: "Test Group".to_string(),
            creator_fingerprint: "alice_fp".to_string(),
            created_at: Utc::now(),
            max_members: 100,
        };
        db.create_group(&group).unwrap();

        // Store messages
        for i in 0..3 {
            let msg = StoredGroupMessage {
                id: format!("gmsg_{}", i),
                group_id: "grp-001".to_string(),
                sender_fingerprint: if i % 2 == 0 { "alice_fp".to_string() } else { "bob_fp".to_string() },
                content: format!("Group message {}", i).into_bytes(),
                timestamp: Utc::now(),
                read: false,
            };
            db.store_group_message(&msg).unwrap();
        }

        // Get messages
        let messages = db.get_group_messages("grp-001", 10).unwrap();
        assert_eq!(messages.len(), 3);

        // Unread count
        let unread = db.unread_group_count("grp-001").unwrap();
        assert_eq!(unread, 3);

        // Mark read
        db.mark_group_messages_read("grp-001").unwrap();
        let unread = db.unread_group_count("grp-001").unwrap();
        assert_eq!(unread, 0);
    }

    #[test]
    fn test_dead_man_switch_crud() {
        let db = Database::in_memory().unwrap();

        let dms = StoredDeadManSwitch {
            id: "dms-001".to_string(),
            recipient_fingerprints: vec!["alice_fp".to_string(), "bob_fp".to_string()],
            message: "If you're reading this, I'm gone.".to_string(),
            check_in_interval_secs: 86400, // 24 hours
            last_check_in: Utc::now(),
            created_at: Utc::now(),
            enabled: true,
            triggered: false,
        };

        // Create
        db.create_dead_man_switch(&dms).unwrap();

        // Get
        let retrieved = db.get_dead_man_switch("dms-001").unwrap().unwrap();
        assert_eq!(retrieved.message, dms.message);
        assert_eq!(retrieved.recipient_fingerprints.len(), 2);

        // List
        let all = db.list_dead_man_switches().unwrap();
        assert_eq!(all.len(), 1);

        // Check-in
        db.check_in_dead_man_switch("dms-001").unwrap();

        // Toggle
        db.toggle_dead_man_switch("dms-001", false).unwrap();
        let toggled = db.get_dead_man_switch("dms-001").unwrap().unwrap();
        assert!(!toggled.enabled);

        // Trigger
        db.toggle_dead_man_switch("dms-001", true).unwrap();
        db.trigger_dead_man_switch("dms-001").unwrap();
        let triggered = db.get_dead_man_switch("dms-001").unwrap().unwrap();
        assert!(triggered.triggered);
        assert!(!triggered.enabled);

        // Delete
        db.delete_dead_man_switch("dms-001").unwrap();
        assert!(db.get_dead_man_switch("dms-001").unwrap().is_none());
    }

    #[test]
    fn test_sender_key_storage() {
        let db = Database::in_memory().unwrap();

        let sk = StoredSenderKey {
            group_id: "grp-001".to_string(),
            member_fingerprint: "alice_fp".to_string(),
            chain_key: vec![1, 2, 3, 4],
            signing_public_key: vec![5, 6, 7, 8],
            chain_index: 42,
            skipped_keys: vec![],
            updated_at: Utc::now(),
        };

        // Store
        db.store_sender_key(&sk).unwrap();

        // Get
        let retrieved = db.get_sender_key("grp-001", "alice_fp").unwrap().unwrap();
        assert_eq!(retrieved.chain_key, vec![1, 2, 3, 4]);
        assert_eq!(retrieved.chain_index, 42);

        // Update state
        db.update_sender_key_state("grp-001", "alice_fp", &[9, 10], 43, &[11, 12]).unwrap();
        let updated = db.get_sender_key("grp-001", "alice_fp").unwrap().unwrap();
        assert_eq!(updated.chain_key, vec![9, 10]);
        assert_eq!(updated.chain_index, 43);

        // Delete for group
        db.delete_sender_keys_for_group("grp-001").unwrap();
        let deleted = db.get_sender_key("grp-001", "alice_fp").unwrap();
        assert!(deleted.is_none());
    }
}
