//! Admission rules for interactive approval asks waiting on the device button.
//!
//! Before #64 each button-required request ran its own approval window back to
//! back, so an app's startup burst could hold the signer for minutes at ~30 s
//! a request, and nothing else — not even a USB status probe — was served
//! while a card was up. The device now keeps one card open and remembers the
//! rest, which raises three questions this module answers, away from the
//! hardware, where they can be tested:
//!
//! * a second ask from the *same* client for the same identity joins the open
//!   card's batch, so one hold answers all of them;
//! * an ask from a *different* client waits its turn behind the card rather
//!   than being answered wrongly;
//! * beyond the caps, an ask is refused immediately instead of growing RAM on
//!   a device with none to spare.
//!
//! The batch cap is the security-relevant one: it is the most signatures a
//! single physical hold can ever authorise, and the card names the count so
//! the operator is never told "sign this" when they are approving eight.
//! Bearer-note cards go further and name the total (`note_cmd::batch_card`):
//! "release this 12-sat note" must never be the wording on a hold that
//! releases three notes worth a thousand.

use alloc::string::String;

/// Most asks one hold may authorise. The card shows the count, and the batch
/// is only ever one client asking for one identity.
pub const MAX_BATCH: usize = 8;

/// Most asks parked behind the open card, across all other clients.
pub const MAX_WAITING: usize = 4;

/// Who is asking, for which identity, and to do what.
///
/// All four must match for two asks to share a card. `kind_key` — the event
/// kind for a sign, else the method name, the same key the transient-allow
/// windows use — is what keeps the batch honest: the card has room to name one
/// kind and a count, so a hold must never cover a kind the operator was not
/// shown. A different client, a different identity or a different kind is a
/// separate decision and gets its own card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AskKey {
    pub master_slot: u8,
    pub client_hex: String,
    pub target_hex: String,
    pub kind_key: String,
}

impl AskKey {
    pub fn new(master_slot: u8, client_hex: String, target_hex: String, kind_key: String) -> Self {
        Self {
            master_slot,
            client_hex,
            target_hex,
            kind_key,
        }
    }
}

/// What to do with an incoming interactive ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Nothing is on screen: this ask opens the card.
    Open,
    /// Same asker, same identity as the open card: join its batch, and the
    /// operator's single hold answers this one too.
    Collapse,
    /// Someone else is mid-decision: wait for a card of its own.
    Wait,
    /// Caps reached — answer busy now rather than hold the client on a
    /// promise the device cannot keep.
    Busy,
}

/// Decide where an incoming ask goes.
///
/// `open` is the key of the card currently on screen (`None` when the screen
/// is free), `batch` how many asks that card already answers, and `waiting`
/// how many asks are queued behind it.
pub fn admit(open: Option<&AskKey>, batch: usize, waiting: usize, incoming: &AskKey) -> Admission {
    let Some(open) = open else {
        return Admission::Open;
    };
    if open == incoming {
        return if batch < MAX_BATCH {
            Admission::Collapse
        } else {
            Admission::Busy
        };
    }
    if waiting < MAX_WAITING {
        Admission::Wait
    } else {
        Admission::Busy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    fn key(slot: u8, client: &str, target: &str) -> AskKey {
        AskKey::new(slot, client.to_string(), target.to_string(), "1".to_string())
    }

    #[test]
    fn the_first_ask_opens_the_card() {
        assert_eq!(
            admit(None, 0, 0, &key(0, "aa", "bb")),
            Admission::Open
        );
    }

    #[test]
    fn the_same_client_asking_again_joins_the_open_card() {
        let open = key(0, "aa", "bb");
        assert_eq!(admit(Some(&open), 1, 0, &open.clone()), Admission::Collapse);
    }

    #[test]
    fn a_different_client_waits_for_its_own_card() {
        let open = key(0, "aa", "bb");
        assert_eq!(
            admit(Some(&open), 1, 0, &key(0, "cc", "bb")),
            Admission::Wait
        );
    }

    #[test]
    fn the_same_client_asking_for_a_different_identity_is_a_separate_decision() {
        let open = key(0, "aa", "bb");
        assert_eq!(
            admit(Some(&open), 1, 0, &key(0, "aa", "dd")),
            Admission::Wait
        );
    }

    #[test]
    fn a_different_master_slot_is_a_separate_decision() {
        let open = key(0, "aa", "bb");
        assert_eq!(
            admit(Some(&open), 1, 0, &key(1, "aa", "bb")),
            Admission::Wait
        );
    }

    #[test]
    fn a_different_event_kind_never_joins_a_batch_the_card_cannot_name() {
        let open = key(0, "aa", "bb");
        let other_kind = AskKey::new(0, "aa".into(), "bb".into(), "30023".into());
        assert_eq!(admit(Some(&open), 1, 0, &other_kind), Admission::Wait);
    }

    #[test]
    fn a_different_method_is_a_separate_decision() {
        let open = AskKey::new(0, "aa".into(), "bb".into(), "nip44_decrypt".into());
        let other = AskKey::new(0, "aa".into(), "bb".into(), "nip04_decrypt".into());
        assert_eq!(admit(Some(&open), 1, 0, &other), Admission::Wait);
    }

    #[test]
    fn one_hold_can_never_authorise_more_than_the_batch_cap() {
        let open = key(0, "aa", "bb");
        // The last admission that fits still collapses...
        assert_eq!(
            admit(Some(&open), MAX_BATCH - 1, 0, &open.clone()),
            Admission::Collapse
        );
        // ...and the one past the cap is refused rather than silently added.
        assert_eq!(
            admit(Some(&open), MAX_BATCH, 0, &open.clone()),
            Admission::Busy
        );
    }

    #[test]
    fn a_full_queue_answers_busy_instead_of_growing() {
        let open = key(0, "aa", "bb");
        assert_eq!(
            admit(Some(&open), 1, MAX_WAITING - 1, &key(0, "cc", "bb")),
            Admission::Wait
        );
        assert_eq!(
            admit(Some(&open), 1, MAX_WAITING, &key(0, "cc", "bb")),
            Admission::Busy
        );
    }

    #[test]
    fn a_full_queue_still_lets_the_open_cards_own_client_collapse() {
        // The batch has room, so the burst that is already being approved is
        // not punished for other clients filling the queue behind it.
        let open = key(0, "aa", "bb");
        assert_eq!(
            admit(Some(&open), 1, MAX_WAITING, &open.clone()),
            Admission::Collapse
        );
    }

    #[test]
    fn a_freed_screen_opens_for_whoever_asks_next() {
        assert_eq!(
            admit(None, 0, MAX_WAITING, &key(3, "ee", "ff")),
            Admission::Open
        );
    }
}
