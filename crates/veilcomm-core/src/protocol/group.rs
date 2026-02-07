//! Group chat protocol types
//!
//! Defines group management structures and actions for multi-party messaging.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Role of a group member
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroupRole {
    Admin,
    Member,
}

/// Information about a group
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupInfo {
    pub group_id: String,
    pub name: String,
    pub creator_fingerprint: String,
    pub created_at: DateTime<Utc>,
    pub max_members: u32,
}

/// A group member
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupMember {
    pub fingerprint: String,
    pub name: Option<String>,
    pub role: GroupRole,
    pub joined_at: DateTime<Utc>,
}

/// Actions that can be performed on a group
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GroupAction {
    /// Create a new group
    Create {
        group_info: GroupInfo,
        initial_members: Vec<String>,
    },
    /// Add a member to the group
    AddMember {
        fingerprint: String,
        name: Option<String>,
        added_by: String,
    },
    /// Remove a member from the group
    RemoveMember {
        fingerprint: String,
        removed_by: String,
    },
    /// A member leaves the group
    Leave {
        fingerprint: String,
    },
    /// Update the group name
    UpdateName {
        new_name: String,
        changed_by: String,
    },
}

impl GroupInfo {
    /// Create a new group
    pub fn new(name: String, creator_fingerprint: String) -> Self {
        Self {
            group_id: uuid::Uuid::new_v4().to_string(),
            name,
            creator_fingerprint,
            created_at: Utc::now(),
            max_members: 100,
        }
    }
}

impl GroupAction {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Serialization should not fail")
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        bincode::deserialize(bytes).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_info_creation() {
        let info = GroupInfo::new("Test Group".to_string(), "alice_fp".to_string());
        assert_eq!(info.name, "Test Group");
        assert_eq!(info.creator_fingerprint, "alice_fp");
        assert_eq!(info.max_members, 100);
        assert!(!info.group_id.is_empty());
    }

    #[test]
    fn test_group_action_serialization() {
        let action = GroupAction::AddMember {
            fingerprint: "bob_fp".to_string(),
            name: Some("Bob".to_string()),
            added_by: "alice_fp".to_string(),
        };
        let bytes = action.to_bytes();
        let restored = GroupAction::from_bytes(&bytes).unwrap();
        if let GroupAction::AddMember { fingerprint, name, added_by } = restored {
            assert_eq!(fingerprint, "bob_fp");
            assert_eq!(name, Some("Bob".to_string()));
            assert_eq!(added_by, "alice_fp");
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_group_role_equality() {
        assert_eq!(GroupRole::Admin, GroupRole::Admin);
        assert_ne!(GroupRole::Admin, GroupRole::Member);
    }
}
