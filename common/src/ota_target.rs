//! Pre-approval check on where an OTA update would be written.
//!
//! The firmware asks the owner to hold the button only for an update that can
//! actually happen. Two things rule one out before the owner is bothered: there
//! is no slot to write to, or the image does not fit it.
//!
//! "No slot" is not the same as ESP-IDF returning no partition. On a table with
//! a single OTA app slot — the one-off Heltec V4's `legacy-nvs-bigapp` layout —
//! `esp_ota_get_next_update_partition` does not return NULL: it wraps around and
//! returns the first OTA slot, which is the one currently running. The old check
//! only looked for NULL, so it passed, the size check passed against the running
//! slot, the owner approved, and `esp_ota_begin` then refused with
//! `ESP_ERR_OTA_PARTITION_CONFLICT` (it will not erase the running image). The
//! owner was shown a card for an update that could never start, and the screen
//! stayed on APPROVED. Seen on real hardware on 2026-09-13.
//!
//! Pure so the case that bit us is pinned by a host test.

/// An app partition, by where it sits in flash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Slot {
    pub offset: u32,
    pub size: u32,
}

/// Why an OTA cannot be offered to the owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetRefusal {
    /// No slot other than the running one to write to.
    NoSpareSlot,
    /// The image is empty or larger than the slot.
    ImageTooLarge,
}

impl TargetRefusal {
    /// Reason text sent after the OTA status code. Wire-visible and matched by
    /// hosts, so it keeps the wording the firmware has always sent.
    pub fn reason(self) -> &'static str {
        match self {
            Self::NoSpareSlot => "No OTA partition",
            Self::ImageTooLarge => "Image too large",
        }
    }
}

/// Decide whether an image of `image_size` can be written to `next`, the slot
/// ESP-IDF proposes, given the offset of the slot currently `running`.
///
/// `running` is `None` only when the firmware cannot tell which slot it booted
/// from; that is treated as no conflict, matching ESP-IDF's own behaviour, and
/// `esp_ota_begin` remains the backstop.
pub fn check_ota_target(
    next: Option<Slot>,
    running: Option<u32>,
    image_size: u32,
) -> Result<Slot, TargetRefusal> {
    let slot = next.ok_or(TargetRefusal::NoSpareSlot)?;
    if running == Some(slot.offset) {
        return Err(TargetRefusal::NoSpareSlot);
    }
    if image_size == 0 || image_size > slot.size {
        return Err(TargetRefusal::ImageTooLarge);
    }
    Ok(slot)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OTA_0: Slot = Slot { offset: 0x10000, size: 0x200000 };
    const OTA_1: Slot = Slot { offset: 0x210000, size: 0x200000 };
    const BIGAPP: Slot = Slot { offset: 0x10000, size: 0x400000 };
    const IMAGE: u32 = 2_078_928; // v0.18.0-beta.8 app-heltec-v4.bin

    #[test]
    fn a_two_slot_board_updates_the_other_slot() {
        assert_eq!(check_ota_target(Some(OTA_1), Some(OTA_0.offset), IMAGE), Ok(OTA_1));
        assert_eq!(check_ota_target(Some(OTA_0), Some(OTA_1.offset), IMAGE), Ok(OTA_0));
    }

    #[test]
    fn a_single_slot_board_is_refused_before_the_owner_is_asked() {
        // The regression: ESP-IDF wraps around and proposes the running slot.
        // It is big enough, so the size check alone would have let it through.
        assert_eq!(
            check_ota_target(Some(BIGAPP), Some(BIGAPP.offset), IMAGE),
            Err(TargetRefusal::NoSpareSlot)
        );
        assert_eq!(TargetRefusal::NoSpareSlot.reason(), "No OTA partition");
    }

    #[test]
    fn no_proposed_slot_is_refused() {
        assert_eq!(check_ota_target(None, Some(0x10000), IMAGE), Err(TargetRefusal::NoSpareSlot));
        assert_eq!(check_ota_target(None, None, IMAGE), Err(TargetRefusal::NoSpareSlot));
    }

    #[test]
    fn a_spare_slot_is_still_refused_when_the_image_does_not_fit() {
        assert_eq!(
            check_ota_target(Some(OTA_1), Some(OTA_0.offset), OTA_1.size + 1),
            Err(TargetRefusal::ImageTooLarge)
        );
        assert_eq!(
            check_ota_target(Some(OTA_1), Some(OTA_0.offset), 0),
            Err(TargetRefusal::ImageTooLarge)
        );
        assert_eq!(check_ota_target(Some(OTA_1), Some(OTA_0.offset), OTA_1.size), Ok(OTA_1));
    }

    #[test]
    fn no_spare_slot_outranks_size() {
        // An oversized image on a single-slot board: the missing slot is the
        // real reason, and the one an operator can act on.
        assert_eq!(
            check_ota_target(Some(BIGAPP), Some(BIGAPP.offset), u32::MAX),
            Err(TargetRefusal::NoSpareSlot)
        );
    }

    #[test]
    fn an_unknown_running_slot_defers_to_esp_idf() {
        assert_eq!(check_ota_target(Some(OTA_1), None, IMAGE), Ok(OTA_1));
    }
}
