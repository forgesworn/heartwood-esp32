//! Security policy for destructive persistent-state operations.
//!
//! This small, platform-independent model is shared with the ESP firmware so
//! host tests cover the exact wipe order and the resumable master-removal model
//! used on-device.

/// Independently writable regions that can restore signer state after reboot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistentRegion {
    /// Flash-time network/operator configuration written by the web flasher.
    FlashConfig,
    /// The complete ESP-IDF NVS partition (all namespaces and keys).
    Nvs,
}

/// Erase the seed source before NVS so a blank NVS can never be repopulated
/// from an old Wi-Fi/operator configuration on the following boot.
pub const PERSISTENT_WIPE_ORDER: [PersistentRegion; 2] =
    [PersistentRegion::FlashConfig, PersistentRegion::Nvs];

/// Fixed journal encoding (`HWRM`, version, fields, CRC32).
pub const REMOVAL_JOURNAL_LEN: usize = 18;
const REMOVAL_MAGIC: [u8; 4] = *b"HWRM";
const REMOVAL_VERSION: u8 = 1;
pub const NO_PERSONA_IN_FLIGHT: u8 = u8::MAX;

/// Durable phase of the slot-removal transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RemovalPhase {
    ShiftSlots = 0,
    RewritePersonas = 1,
    ClearPersonaTail = 2,
    ClearLastSlot = 3,
    ClearGlobalSlotState = 4,
    CommitMasterCount = 5,
    Complete = 6,
}

impl RemovalPhase {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::ShiftSlots),
            1 => Some(Self::RewritePersonas),
            2 => Some(Self::ClearPersonaTail),
            3 => Some(Self::ClearLastSlot),
            4 => Some(Self::ClearGlobalSlotState),
            5 => Some(Self::CommitMasterCount),
            6 => Some(Self::Complete),
            _ => None,
        }
    }
}

/// Cursor persisted after every idempotent removal step. Source slots and
/// persona entries are retained until they are no longer needed, so repeating
/// the step after a cut writes the same destination bytes again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemovalJournal {
    pub target: u8,
    pub original_master_count: u8,
    pub original_persona_count: u8,
    pub phase: RemovalPhase,
    pub next_master_destination: u8,
    pub persona_read: u8,
    pub persona_write: u8,
    pub persona_clear: u8,
    /// Original master slot of the persona currently being rewritten. This is
    /// persisted before an in-place rewrite so a cut cannot decrement it twice.
    pub persona_inflight_master_slot: u8,
}

impl RemovalJournal {
    pub fn new(target: u8, master_count: u8, persona_count: u8) -> Option<Self> {
        if master_count == 0 || target >= master_count {
            return None;
        }
        Some(Self {
            target,
            original_master_count: master_count,
            original_persona_count: persona_count,
            phase: RemovalPhase::ShiftSlots,
            next_master_destination: target,
            persona_read: 0,
            persona_write: 0,
            persona_clear: 0,
            persona_inflight_master_slot: NO_PERSONA_IN_FLIGHT,
        })
    }

    pub fn encode(self) -> [u8; REMOVAL_JOURNAL_LEN] {
        let mut encoded = [
            REMOVAL_MAGIC[0],
            REMOVAL_MAGIC[1],
            REMOVAL_MAGIC[2],
            REMOVAL_MAGIC[3],
            REMOVAL_VERSION,
            self.target,
            self.original_master_count,
            self.original_persona_count,
            self.phase as u8,
            self.next_master_destination,
            self.persona_read,
            self.persona_write,
            self.persona_clear,
            self.persona_inflight_master_slot,
            0,
            0,
            0,
            0,
        ];
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&encoded[..14]);
        encoded[14..18].copy_from_slice(&hasher.finalize().to_le_bytes());
        encoded
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != REMOVAL_JOURNAL_LEN
            || bytes[0..4] != REMOVAL_MAGIC
            || bytes[4] != REMOVAL_VERSION
        {
            return None;
        }
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&bytes[..14]);
        if bytes[14..18] != hasher.finalize().to_le_bytes() {
            return None;
        }
        let journal = Self {
            target: bytes[5],
            original_master_count: bytes[6],
            original_persona_count: bytes[7],
            phase: RemovalPhase::from_u8(bytes[8])?,
            next_master_destination: bytes[9],
            persona_read: bytes[10],
            persona_write: bytes[11],
            persona_clear: bytes[12],
            persona_inflight_master_slot: bytes[13],
        };
        if journal.original_master_count == 0
            || journal.target >= journal.original_master_count
            || journal.next_master_destination < journal.target
            || journal.next_master_destination >= journal.original_master_count
            || journal.persona_read > journal.original_persona_count
            || journal.persona_write > journal.persona_read
            || journal.persona_clear > journal.original_persona_count
            || (journal.persona_inflight_master_slot != NO_PERSONA_IN_FLIGHT
                && journal.persona_inflight_master_slot >= journal.original_master_count)
        {
            return None;
        }
        Some(journal)
    }
}

/// Map a slot-indexed record through removal: target-owned records disappear,
/// higher slots move down by one, and lower slots stay unchanged.
pub fn remap_master_slot(slot: u8, target: u8) -> Option<u8> {
    if slot == target {
        None
    } else if slot > target {
        Some(slot - 1)
    } else {
        Some(slot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wipe_order_prevents_flash_config_from_reseeding_blank_nvs() {
        assert_eq!(
            PERSISTENT_WIPE_ORDER,
            [PersistentRegion::FlashConfig, PersistentRegion::Nvs]
        );
    }

    #[test]
    fn slot_remap_handles_first_middle_and_last() {
        assert_eq!(remap_master_slot(0, 0), None);
        assert_eq!(remap_master_slot(1, 0), Some(0));
        assert_eq!(remap_master_slot(0, 1), Some(0));
        assert_eq!(remap_master_slot(1, 1), None);
        assert_eq!(remap_master_slot(2, 1), Some(1));
        assert_eq!(remap_master_slot(1, 2), Some(1));
        assert_eq!(remap_master_slot(2, 2), None);
    }

    #[test]
    fn journal_round_trip_and_validation() {
        let journal = RemovalJournal::new(1, 3, 4).unwrap();
        assert_eq!(RemovalJournal::decode(&journal.encode()), Some(journal));
        assert!(RemovalJournal::new(0, 0, 0).is_none());
        assert!(RemovalJournal::new(3, 3, 0).is_none());
        let mut malformed = journal.encode();
        malformed[8] = 99;
        assert!(RemovalJournal::decode(&malformed).is_none());
        let mut corrupt_but_structurally_valid = journal.encode();
        corrupt_but_structurally_valid[5] = 0;
        assert!(RemovalJournal::decode(&corrupt_but_structurally_valid).is_none());
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct Model {
        masters: [Option<u8>; 4],
        personas: [Option<u8>; 6],
        count: u8,
    }

    fn model_step(model: &mut Model, journal: &mut RemovalJournal) {
        match journal.phase {
            RemovalPhase::ShiftSlots => {
                if journal.next_master_destination + 1 < journal.original_master_count {
                    let dst = journal.next_master_destination as usize;
                    model.masters[dst] = model.masters[dst + 1];
                    journal.next_master_destination += 1;
                } else {
                    journal.phase = RemovalPhase::RewritePersonas;
                }
            }
            RemovalPhase::RewritePersonas => {
                if journal.persona_read < journal.original_persona_count {
                    let read = journal.persona_read as usize;
                    if journal.persona_inflight_master_slot == NO_PERSONA_IN_FLIGHT {
                        journal.persona_inflight_master_slot = model.personas[read].unwrap();
                    } else {
                        if let Some(mapped) = remap_master_slot(
                            journal.persona_inflight_master_slot,
                            journal.target,
                        ) {
                            model.personas[journal.persona_write as usize] = Some(mapped);
                            journal.persona_write += 1;
                        }
                        journal.persona_read += 1;
                        journal.persona_inflight_master_slot = NO_PERSONA_IN_FLIGHT;
                    }
                } else {
                    journal.persona_clear = journal.persona_write;
                    journal.phase = RemovalPhase::ClearPersonaTail;
                }
            }
            RemovalPhase::ClearPersonaTail => {
                if journal.persona_clear < journal.original_persona_count {
                    model.personas[journal.persona_clear as usize] = None;
                    journal.persona_clear += 1;
                } else {
                    journal.phase = RemovalPhase::ClearLastSlot;
                }
            }
            RemovalPhase::ClearLastSlot => {
                model.masters[(journal.original_master_count - 1) as usize] = None;
                journal.phase = RemovalPhase::ClearGlobalSlotState;
            }
            RemovalPhase::ClearGlobalSlotState => {
                journal.phase = RemovalPhase::CommitMasterCount;
            }
            RemovalPhase::CommitMasterCount => {
                model.count = journal.original_master_count - 1;
                journal.phase = RemovalPhase::Complete;
            }
            RemovalPhase::Complete => {}
        }
    }

    fn completed(target: u8) -> Model {
        let mut model = Model {
            masters: [Some(10), Some(11), Some(12), None],
            personas: [Some(0), Some(1), Some(2), Some(1), None, None],
            count: 3,
        };
        let mut journal = RemovalJournal::new(target, 3, 4).unwrap();
        while journal.phase != RemovalPhase::Complete {
            model_step(&mut model, &mut journal);
        }
        model
    }

    #[test]
    fn model_removes_first_middle_and_last_without_cross_binding() {
        assert_eq!(completed(0).masters, [Some(11), Some(12), None, None]);
        assert_eq!(completed(0).personas, [Some(0), Some(1), Some(0), None, None, None]);

        assert_eq!(completed(1).masters, [Some(10), Some(12), None, None]);
        assert_eq!(completed(1).personas, [Some(0), Some(1), None, None, None, None]);

        assert_eq!(completed(2).masters, [Some(10), Some(11), None, None]);
        assert_eq!(completed(2).personas, [Some(0), Some(1), Some(1), None, None, None]);
    }

    #[test]
    fn repeating_each_cut_step_is_idempotent() {
        let expected = completed(1);
        for cut_after in 0..16 {
            let mut model = Model {
                masters: [Some(10), Some(11), Some(12), None],
                personas: [Some(0), Some(1), Some(2), Some(1), None, None],
                count: 3,
            };
            let mut journal = RemovalJournal::new(1, 3, 4).unwrap();
            for _ in 0..cut_after {
                if journal.phase == RemovalPhase::Complete {
                    break;
                }
                model_step(&mut model, &mut journal);
            }

            // Simulate a cut after the current action's data write but before
            // its journal cursor write: run it on a throwaway cursor, then
            // resume with the durable pre-step cursor and repeat the action.
            if journal.phase != RemovalPhase::Complete {
                let durable = journal;
                model_step(&mut model, &mut journal);
                journal = durable;
            }
            while journal.phase != RemovalPhase::Complete {
                model_step(&mut model, &mut journal);
            }
            assert_eq!(model, expected, "cut after step {cut_after}");
        }
    }
}
