// common/src/backup.rs
//
// Backup payload types shared between firmware and heartwoodd.
// The backup JSON is the plaintext inside the encrypted envelope.

use serde::{Deserialize, Serialize};

use crate::policy::ConnectSlot;

/// A master's metadata and connection slots for backup purposes.
/// Does NOT contain the master secret -- only enough to match
/// against a re-provisioned master by pubkey.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupMaster {
    pub slot: u8,
    pub label: String,
    /// Provisioning mode (0=Bunker, 1=TreeMnemonic, 2=TreeNsec).
    pub mode: u8,
    /// Hex-encoded x-only public key (64 chars).
    pub pubkey: String,
    pub connection_slots: Vec<ConnectSlot>,
}

/// The complete backup payload (plaintext, before encryption).
///
/// SECURITY: this struct contains the bridge secret in plaintext.
/// It must only exist in memory or inside an encrypted backup envelope.
/// Never serialise to disk, logs, or the wire without encrypting first.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupPayload {
    /// Unix timestamp (seconds) when the backup was created.
    pub created_at: u64,
    /// Hex-encoded SHA-256 of the bridge secret -- non-secret device fingerprint.
    pub device_id: String,
    pub masters: Vec<BackupMaster>,
    /// Hex-encoded bridge secret (64 chars). Included so the Pi-ESP32 link
    /// can be restored without re-pairing. Encrypted at rest in the backup envelope.
    pub bridge_secret: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::ConnectSlot;

    fn sample_slot(index: u8, label: &str) -> ConnectSlot {
        ConnectSlot {
            slot_index: index,
            label: label.to_string(),
            secret: "ab".repeat(32),
            current_pubkey: Some("cc".repeat(32)),
            allowed_methods: vec!["sign_event".to_string(), "get_public_key".to_string()],
            allowed_kinds: vec![1, 7],
            auto_approve: true,
            signing_approved: true,
        }
    }

    #[test]
    fn serde_roundtrip() {
        let payload = BackupPayload {
            created_at: 1_700_000_000,
            device_id: "dd".repeat(32),
            bridge_secret: "ee".repeat(32),
            masters: vec![BackupMaster {
                slot: 0,
                label: "Personal".to_string(),
                mode: 1,
                pubkey: "ff".repeat(32),
                connection_slots: vec![sample_slot(0, "nostrudel desktop")],
            }],
        };

        let json = serde_json::to_string(&payload).unwrap();
        let decoded: BackupPayload = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.created_at, 1_700_000_000);
        assert_eq!(decoded.device_id, "dd".repeat(32));
        assert_eq!(decoded.bridge_secret, "ee".repeat(32));
        assert_eq!(decoded.masters.len(), 1);

        let master = &decoded.masters[0];
        assert_eq!(master.slot, 0);
        assert_eq!(master.label, "Personal");
        assert_eq!(master.mode, 1);
        assert_eq!(master.pubkey, "ff".repeat(32));
        assert_eq!(master.connection_slots.len(), 1);
        assert_eq!(master.connection_slots[0].label, "nostrudel desktop");
        assert_eq!(master.connection_slots[0].slot_index, 0);
    }

    #[test]
    fn empty_masters_roundtrip() {
        let payload = BackupPayload {
            created_at: 1_600_000_000,
            device_id: "aa".repeat(32),
            bridge_secret: "bb".repeat(32),
            masters: vec![],
        };

        let json = serde_json::to_string(&payload).unwrap();
        let decoded: BackupPayload = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.created_at, 1_600_000_000);
        assert!(decoded.masters.is_empty());
    }

    #[test]
    fn multiple_masters_multiple_slots() {
        let payload = BackupPayload {
            created_at: 1_750_000_000,
            device_id: "11".repeat(32),
            bridge_secret: "22".repeat(32),
            masters: vec![
                BackupMaster {
                    slot: 0,
                    label: "Work".to_string(),
                    mode: 2,
                    pubkey: "33".repeat(32),
                    connection_slots: vec![
                        sample_slot(0, "Bark browser"),
                        sample_slot(1, "nostrudel desktop"),
                    ],
                },
                BackupMaster {
                    slot: 1,
                    label: "Personal".to_string(),
                    mode: 0,
                    pubkey: "44".repeat(32),
                    connection_slots: vec![],
                },
            ],
        };

        let json = serde_json::to_string(&payload).unwrap();
        let decoded: BackupPayload = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.masters.len(), 2);

        let work = &decoded.masters[0];
        assert_eq!(work.label, "Work");
        assert_eq!(work.mode, 2);
        assert_eq!(work.connection_slots.len(), 2);
        assert_eq!(work.connection_slots[0].label, "Bark browser");
        assert_eq!(work.connection_slots[1].label, "nostrudel desktop");

        let personal = &decoded.masters[1];
        assert_eq!(personal.label, "Personal");
        assert_eq!(personal.mode, 0);
        assert!(personal.connection_slots.is_empty());
    }
}
