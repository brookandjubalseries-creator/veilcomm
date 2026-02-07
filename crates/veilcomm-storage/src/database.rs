//! SQLite database for VeilComm
//!
//! Stores contacts, messages, and session state.

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
            "#,
        )?;

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
            INSERT INTO messages (id, contact_fingerprint, outgoing, content, timestamp, read)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            params![
                message.id,
                message.contact_fingerprint,
                message.outgoing as i32,
                message.content,
                message.timestamp.to_rfc3339(),
                message.read as i32,
            ],
        )?;
        Ok(())
    }

    /// Get messages for a contact
    pub fn get_messages(&self, contact_fingerprint: &str, limit: u32) -> Result<Vec<StoredMessage>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, contact_fingerprint, outgoing, content, timestamp, read
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
}
