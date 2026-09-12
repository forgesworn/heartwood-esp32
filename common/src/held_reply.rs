//! Approved replies that outlived the relay session they were meant for (#82).
//!
//! A NIP-46 reply is addressed to a client pubkey, not to a socket. The relay
//! loop nonetheless published one straight down the session the request came
//! in on, so a reconnect between the owner's hold and the publish threw the
//! answer away: the bench run that opened #82 shows the operator holding the
//! button, the card resolving, and the wallet reporting "did not answer in
//! time" for work the device had already done. The shape to design against is
//! *the device did the thing, the caller was told it timed out*.
//!
//! So an approved reply that cannot be published is kept here and offered to
//! the next session instead. What this module is NOT is a durable outbox:
//!
//! * **RAM only.** A held `heartwood_note_export` reply carries a `ck1`,
//!   which is spending authority. Nothing here is ever written to flash, and
//!   a reboot loses the queue, which is the correct outcome, because the
//!   spend grant that reply earned (`note_cmd::SpendGrant`) is RAM-only too
//!   and dies with it.
//! * **Bounded.** [`HELD_REPLY_MAX`] entries and [`HELD_REPLY_BYTE_BUDGET`]
//!   bytes, whichever binds first, for [`HELD_REPLY_TTL_SECS`]. A reply that
//!   cannot be delivered is dropped, never accumulated: the relay loop already
//!   sheds its secondary session when the largest free block falls below
//!   32 KB, and an outbox must not be what pushes it there.
//! * **Single client, single delivery.** [`HeldReplies::take`] hands a reply
//!   back only to the pubkey it was addressed to, and removes it as it does,
//!   so a second flush cannot publish it twice. The payload is a sealed,
//!   signed event whose NIP-44 ciphertext is already bound to that client's
//!   conversation key, so even a routing bug here could not disclose it to
//!   anyone else: the check is belt and braces over that.
//! * **Approved work only.** [`HeldReplies::hold`] takes the owner's
//!   [`Decision`] and refuses anything but [`Decision::Approved`], so the rule
//!   is enforced here rather than trusted to each call site. A denied, expired
//!   or refused request is answered with an error whose loss costs the caller
//!   nothing it did not already have (a timeout).

use alloc::string::String;
use alloc::vec::Vec;

/// Most replies held at once.
///
/// Four. One card can answer up to `approval_queue::MAX_BATCH` (8) asks, so a
/// collect of eight notes released on one hold could in principle strand
/// eight replies, but only if every one of them failed to publish, which
/// means the session died mid-batch and the earliest replies are the ones the
/// caller has already had. Four covers a reconnect that lands in the middle
/// of a batch while keeping the worst case a quarter of the byte budget's
/// reach, and the oldest goes first, which is the one whose caller has been
/// waiting longest and is most likely to have given up.
pub const HELD_REPLY_MAX: usize = 4;

/// Total bytes all held replies may occupy.
///
/// 4 KB. The relay loop sheds its secondary TLS session when the largest free
/// block drops under 32 KB (`SECONDARY_SHED_BLOCK`), so an outbox worth an
/// eighth of that margin cannot be the allocation that costs the device a
/// relay. A single reply larger than the whole budget is refused outright
/// rather than evicting everything else to make room for it.
pub const HELD_REPLY_BYTE_BUDGET: usize = 4 * 1024;

/// How long a reply may wait for a session, in seconds since boot.
///
/// Sixty. Two things bound it from opposite sides. Above: a held export reply
/// is a `ck1` sitting in RAM, so the residency wants to be as short as the
/// job allows, and it must not outlive the 120 s spend grant that the same
/// approval minted. A caller handed its secret with no grant left simply
/// holds the button again, but a caller handed one with seconds left has a
/// race it cannot see. Below: a primary reconnect backs off 3 s and a TLS
/// handshake on a slow link is seconds more, so anything under about half a
/// minute would miss the reconnect this exists to survive. Sixty sits between
/// them and is comfortably inside notecase's 75 s gated timeout, so a reply
/// delivered at the limit is still one its caller is waiting for.
pub const HELD_REPLY_TTL_SECS: u32 = 60;

/// Publication attempts a held reply gets before it is dropped.
///
/// Two. The first flush runs against a session that has just come up and may
/// still be on its way down; a second is worth having. A third is not. A
/// reply that two sessions in a row would not take is not going to be
/// delivered, and retrying it forever is exactly the accumulation the byte
/// budget exists to prevent.
pub const HELD_REPLY_MAX_ATTEMPTS: u8 = 2;

/// One approved reply waiting for a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldReply {
    /// The client this reply is addressed to. Also the key the NIP-44
    /// ciphertext inside `payload` is sealed under, so this is a routing
    /// label over a binding that is already cryptographic.
    pub client: [u8; 32],
    /// Which master's slot set the client is bound to, so a flush can check
    /// the pairing still exists before publishing.
    pub master_slot: u8,
    /// The NIP-46 request id, for logs.
    pub request_id: String,
    /// The serialised relay command, sealed and signed at approval time and
    /// ready to go out as-is. Held rather than rebuilt so the flush needs no
    /// signing key and cannot re-address it.
    pub payload: String,
    /// Seconds since boot when the approval happened.
    pub held_at: u32,
    /// Publication attempts so far.
    pub attempts: u8,
    /// The note whose spend grant this reply's DELIVERY earns (#137), if it
    /// is an export reply. Carried here because the grant must not exist
    /// until the `ck1` has reached its caller: a reply that expires, is
    /// dropped for a revoked client, or is lost to a reboot takes this with
    /// it and grants nothing. The grant is attributed to `client`, so it can
    /// only ever land on the pubkey the secret actually reached.
    pub earned: Option<String>,
}

impl HeldReply {
    /// Roughly what this entry costs the heap.
    pub fn weight(&self) -> usize {
        self.payload.len() + self.request_id.len() + 64
    }
}

/// What the owner decided about the request this reply answers.
///
/// The queue enforces this itself rather than trusting each call site to
/// remember: only work the owner approved is worth a second chance at
/// delivery. A denial or an expiry is an error response, and a caller that
/// never receives one simply times out, which is the same outcome by a
/// slower road. Holding refusals would also spend the bound on replies
/// nobody is waiting for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The owner held the button (or a guardian approved the park) and the
    /// device acted.
    Approved,
    /// Denied, expired, or refused before it ever reached a card.
    Refused,
}

/// What became of a hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HoldOutcome {
    /// Kept. `evicted` names any request ids dropped to make room, oldest
    /// first, so the caller can log what it gave up.
    Held { evicted: Vec<String> },
    /// Larger on its own than the whole byte budget: nothing was evicted and
    /// nothing was kept.
    TooLarge,
    /// Not approved work, so not held. Nothing was evicted.
    Refused,
}

/// The device's RAM-only outbox of approved replies (#82).
#[derive(Debug, Default)]
pub struct HeldReplies {
    held: Vec<HeldReply>,
}

impl HeldReplies {
    pub const fn new() -> Self {
        HeldReplies { held: Vec::new() }
    }

    /// Drop everything past [`HELD_REPLY_TTL_SECS`]. Returns how many went.
    ///
    /// Called on every relay pass, session or no session: the point of the
    /// TTL is that a `ck1` does not sit in RAM waiting for a network that is
    /// not coming back, and a device with no session at all is exactly the
    /// case where nothing else would ever look at the queue.
    pub fn expire(&mut self, now: u32) -> usize {
        let before = self.held.len();
        self.held
            .retain(|r| now.checked_sub(r.held_at).is_some_and(|age| age <= HELD_REPLY_TTL_SECS));
        before - self.held.len()
    }

    /// Keep a reply for the next session.
    ///
    /// Expired entries go first, then the oldest, until both the count and
    /// the byte budget have room. A reply that could not fit even in an empty
    /// queue is refused without disturbing what is already held.
    pub fn hold(&mut self, reply: HeldReply, decision: Decision, now: u32) -> HoldOutcome {
        if decision != Decision::Approved {
            return HoldOutcome::Refused;
        }
        if reply.weight() > HELD_REPLY_BYTE_BUDGET {
            return HoldOutcome::TooLarge;
        }
        self.expire(now);
        let mut evicted = Vec::new();
        while self.held.len() >= HELD_REPLY_MAX
            || self.bytes().saturating_add(reply.weight()) > HELD_REPLY_BYTE_BUDGET
        {
            // `held` is push-ordered and every insert appends, so index 0 is
            // always the oldest.
            let Some(dropped) = self.held.first().map(|r| r.request_id.clone()) else {
                break;
            };
            self.held.remove(0);
            evicted.push(dropped);
        }
        self.held.push(reply);
        HoldOutcome::Held { evicted }
    }

    /// Which client the next deliverable reply belongs to, expiring stale
    /// entries on the way. `None` when there is nothing to send.
    pub fn next_client(&mut self, now: u32) -> Option<[u8; 32]> {
        self.expire(now);
        self.held.first().map(|r| r.client)
    }

    /// Take the oldest live reply addressed to `client`, removing it.
    ///
    /// Removing on the way out is what makes delivery single-shot: a reply
    /// handed to a caller is no longer in the queue, so a second flush cannot
    /// publish it again. A caller whose transport then refused it may offer
    /// it back through [`HeldReplies::requeue`], which is bounded.
    ///
    /// A reply for some other client is never returned, whatever is at the
    /// head of the queue.
    pub fn take(&mut self, client: &[u8; 32], now: u32) -> Option<HeldReply> {
        self.expire(now);
        let at = self.held.iter().position(|r| r.client == *client)?;
        let mut reply = self.held.remove(at);
        reply.attempts = reply.attempts.saturating_add(1);
        Some(reply)
    }

    /// Offer a reply back after a failed publication.
    ///
    /// `false` means its attempts are spent and the caller should drop it.
    /// It goes back at the head, keeping the queue in age order.
    pub fn requeue(&mut self, reply: HeldReply) -> bool {
        if reply.attempts >= HELD_REPLY_MAX_ATTEMPTS {
            return false;
        }
        if self.held.len() >= HELD_REPLY_MAX {
            return false;
        }
        self.held.insert(0, reply);
        true
    }

    /// Drop every reply held for `client`. For a caller that has just revoked
    /// or re-bound the pairing underneath them. Returns how many went.
    pub fn drop_client(&mut self, client: &[u8; 32]) -> usize {
        let before = self.held.len();
        self.held.retain(|r| r.client != *client);
        before - self.held.len()
    }

    /// Total held bytes, against [`HELD_REPLY_BYTE_BUDGET`].
    pub fn bytes(&self) -> usize {
        self.held.iter().map(HeldReply::weight).sum()
    }

    pub fn len(&self) -> usize {
        self.held.len()
    }

    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn reply(id: &str, who: u8, at: u32) -> HeldReply {
        HeldReply {
            client: client(who),
            master_slot: 0,
            request_id: id.to_string(),
            payload: "x".repeat(200),
            held_at: at,
            attempts: 0,
            earned: None,
        }
    }

    fn earning(id: &str, who: u8, at: u32, note: &str) -> HeldReply {
        HeldReply { earned: Some(note.to_string()), ..reply(id, who, at) }
    }

    fn sized(id: &str, who: u8, at: u32, bytes: usize) -> HeldReply {
        HeldReply {
            payload: "x".repeat(bytes),
            ..reply(id, who, at)
        }
    }

    #[test]
    fn a_held_reply_comes_back_for_its_own_client() {
        let mut q = HeldReplies::new();
        assert!(matches!(
            q.hold(reply("r1", 1, 10), Decision::Approved, 10),
            HoldOutcome::Held { .. }
        ));
        assert_eq!(q.next_client(11), Some(client(1)));
        let taken = q.take(&client(1), 11).expect("held for this client");
        assert_eq!(taken.request_id, "r1");
        assert_eq!(taken.attempts, 1);
    }

    #[test]
    fn never_to_another_client() {
        let mut q = HeldReplies::new();
        q.hold(reply("r1", 1, 10), Decision::Approved, 10);
        // The head of the queue belongs to client 1, and asking as anyone
        // else gets nothing: not the head, and not a "closest match".
        assert_eq!(q.take(&client(2), 11), None);
        assert_eq!(q.take(&client(9), 11), None);
        assert_eq!(q.len(), 1);
        assert!(q.take(&client(1), 11).is_some());
    }

    #[test]
    fn a_second_client_is_served_from_its_own_entry() {
        let mut q = HeldReplies::new();
        q.hold(reply("r1", 1, 10), Decision::Approved, 10);
        q.hold(reply("r2", 2, 10), Decision::Approved, 10);
        assert_eq!(q.take(&client(2), 11).map(|r| r.request_id), Some("r2".to_string()));
        assert_eq!(q.take(&client(1), 11).map(|r| r.request_id), Some("r1".to_string()));
        assert!(q.is_empty());
    }

    #[test]
    fn delivered_once_and_only_once() {
        let mut q = HeldReplies::new();
        q.hold(reply("r1", 1, 10), Decision::Approved, 10);
        assert!(q.take(&client(1), 11).is_some());
        // Whatever the caller did with it, the queue no longer has it: a
        // second flush cannot republish the same approved reply.
        assert_eq!(q.take(&client(1), 11), None);
        assert_eq!(q.next_client(11), None);
        assert!(q.is_empty());
    }

    #[test]
    fn a_failed_publish_may_be_offered_back_but_not_forever() {
        let mut q = HeldReplies::new();
        q.hold(reply("r1", 1, 10), Decision::Approved, 10);
        let first = q.take(&client(1), 11).expect("held");
        assert_eq!(first.attempts, 1);
        assert!(q.requeue(first), "one failure is worth another session");
        let second = q.take(&client(1), 12).expect("still held");
        assert_eq!(second.attempts, HELD_REPLY_MAX_ATTEMPTS);
        assert!(!q.requeue(second), "attempts spent; the caller drops it");
        assert!(q.is_empty());
    }

    #[test]
    fn it_expires() {
        let mut q = HeldReplies::new();
        q.hold(reply("r1", 1, 100), Decision::Approved, 100);
        // On the boundary it is still deliverable.
        assert_eq!(q.next_client(100 + HELD_REPLY_TTL_SECS), Some(client(1)));
        assert_eq!(q.next_client(100 + HELD_REPLY_TTL_SECS + 1), None);
        assert!(q.is_empty(), "the ck1 does not linger past the window");
    }

    #[test]
    fn an_expired_reply_is_not_handed_to_its_client_either() {
        let mut q = HeldReplies::new();
        q.hold(reply("r1", 1, 100), Decision::Approved, 100);
        assert_eq!(q.take(&client(1), 100 + HELD_REPLY_TTL_SECS + 1), None);
    }

    #[test]
    fn a_clock_that_goes_backwards_expires_rather_than_holds() {
        let mut q = HeldReplies::new();
        q.hold(reply("r1", 1, 100), Decision::Approved, 100);
        // Seconds-since-boot cannot go backwards without a reboot, and a
        // reboot must not leave a reply deliverable.
        assert_eq!(q.next_client(5), None);
    }

    #[test]
    fn the_cap_holds_and_the_oldest_goes_first() {
        let mut q = HeldReplies::new();
        for i in 0..HELD_REPLY_MAX {
            q.hold(reply(&format!("r{i}"), 1, 10), Decision::Approved, 10);
        }
        assert_eq!(q.len(), HELD_REPLY_MAX);
        let outcome = q.hold(reply("newest", 1, 10), Decision::Approved, 10);
        assert_eq!(outcome, HoldOutcome::Held { evicted: vec!["r0".to_string()] });
        assert_eq!(q.len(), HELD_REPLY_MAX);
        // r0 is gone; r1 is now the oldest and "newest" is at the back.
        assert_eq!(q.take(&client(1), 10).map(|r| r.request_id), Some("r1".to_string()));
    }

    #[test]
    fn the_byte_budget_binds_before_the_count_does() {
        let mut q = HeldReplies::new();
        let big = HELD_REPLY_BYTE_BUDGET / 3;
        q.hold(sized("a", 1, 10, big), Decision::Approved, 10);
        q.hold(sized("b", 1, 10, big), Decision::Approved, 10);
        assert_eq!(q.len(), 2);
        assert!(q.bytes() <= HELD_REPLY_BYTE_BUDGET);
        // A third of the same size cannot fit beside them, so the oldest goes
        // even though the count cap has room to spare.
        let outcome = q.hold(sized("c", 1, 10, big), Decision::Approved, 10);
        assert_eq!(outcome, HoldOutcome::Held { evicted: vec!["a".to_string()] });
        assert!(q.bytes() <= HELD_REPLY_BYTE_BUDGET);
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn one_reply_too_large_for_the_budget_is_dropped_not_accumulated() {
        let mut q = HeldReplies::new();
        q.hold(reply("keeper", 1, 10), Decision::Approved, 10);
        let outcome = q.hold(sized("whale", 1, 10, HELD_REPLY_BYTE_BUDGET + 1), Decision::Approved, 10);
        assert_eq!(outcome, HoldOutcome::TooLarge);
        // And it did not cost the queue what it was already holding.
        assert_eq!(q.len(), 1);
        assert_eq!(q.take(&client(1), 10).map(|r| r.request_id), Some("keeper".to_string()));
    }

    #[test]
    fn holding_expires_stale_entries_rather_than_evicting_live_ones() {
        let mut q = HeldReplies::new();
        for i in 0..HELD_REPLY_MAX {
            q.hold(reply(&format!("old{i}"), 1, 10), Decision::Approved, 10);
        }
        let later = 10 + HELD_REPLY_TTL_SECS + 1;
        let outcome = q.hold(reply("fresh", 1, later), Decision::Approved, later);
        assert_eq!(outcome, HoldOutcome::Held { evicted: vec![] });
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn requeue_refuses_when_the_queue_filled_up_behind_it() {
        let mut q = HeldReplies::new();
        q.hold(reply("taken", 1, 10), Decision::Approved, 10);
        let in_flight = q.take(&client(1), 10).expect("held");
        for i in 0..HELD_REPLY_MAX {
            q.hold(reply(&format!("r{i}"), 1, 10), Decision::Approved, 10);
        }
        assert!(!q.requeue(in_flight), "a full queue is not made fuller");
        assert_eq!(q.len(), HELD_REPLY_MAX);
    }

    #[test]
    fn dropping_a_client_takes_only_that_clients_replies() {
        let mut q = HeldReplies::new();
        q.hold(reply("r1", 1, 10), Decision::Approved, 10);
        q.hold(reply("r2", 2, 10), Decision::Approved, 10);
        assert_eq!(q.drop_client(&client(1)), 1);
        assert_eq!(q.len(), 1);
        assert_eq!(q.take(&client(2), 10).map(|r| r.request_id), Some("r2".to_string()));
    }

    #[test]
    fn nothing_is_held_for_a_refused_request() {
        let mut q = HeldReplies::new();
        // A denial, an expiry and a busy refusal all arrive here as Refused,
        // and none of them is worth a second chance at delivery: the caller
        // times out, which is what it was getting anyway.
        let outcome = q.hold(reply("denied", 1, 10), Decision::Refused, 10);
        assert_eq!(outcome, HoldOutcome::Refused);
        assert!(q.is_empty());
        assert_eq!(q.next_client(10), None);
        assert_eq!(q.take(&client(1), 10), None);
    }

    #[test]
    fn a_refusal_never_evicts_an_approved_reply() {
        let mut q = HeldReplies::new();
        for i in 0..HELD_REPLY_MAX {
            q.hold(reply(&format!("r{i}"), 1, 10), Decision::Approved, 10);
        }
        // The queue is full. A refusal must not be the thing that pushes an
        // approved reply out of it.
        let outcome = q.hold(reply("denied", 1, 10), Decision::Refused, 10);
        assert_eq!(outcome, HoldOutcome::Refused);
        assert_eq!(q.len(), HELD_REPLY_MAX);
        assert_eq!(
            q.take(&client(1), 10).map(|r| r.request_id),
            Some("r0".to_string())
        );
    }

    #[test]
    fn a_held_export_reply_carries_what_its_delivery_earns() {
        // #137: the spend grant is armed by the delivery, not by the
        // dispatch, so the note id has to travel with the reply.
        let mut q = HeldReplies::new();
        q.hold(earning("r1", 1, 10, "note7"), Decision::Approved, 10);
        let taken = q.take(&client(1), 11).expect("held");
        assert_eq!(taken.earned.as_deref(), Some("note7"));
        assert_eq!(taken.client, client(1));
    }

    #[test]
    fn an_undelivered_reply_takes_its_earned_grant_with_it() {
        // Expired, evicted or dropped: the queue is the only place the note
        // id lives, so losing the reply loses the grant. That is the whole
        // point of arming on delivery.
        let mut q = HeldReplies::new();
        q.hold(earning("r1", 1, 100, "note7"), Decision::Approved, 100);
        assert_eq!(q.next_client(100 + HELD_REPLY_TTL_SECS + 1), None);
        assert!(q.is_empty());

        let mut q = HeldReplies::new();
        for i in 0..HELD_REPLY_MAX {
            q.hold(earning(&format!("r{i}"), 1, 10, &format!("note{i}")), Decision::Approved, 10);
        }
        q.hold(earning("newest", 1, 10, "note9"), Decision::Approved, 10);
        let taken = q.take(&client(1), 10).expect("held");
        assert_eq!(taken.earned.as_deref(), Some("note1"), "the evicted one came back");
    }

    #[test]
    fn a_fresh_queue_is_what_a_reboot_leaves() {
        // The queue has no constructor that reads anything: whatever was held
        // before a reboot is gone, which is the only acceptable outcome for a
        // payload carrying a ck1.
        let q = HeldReplies::new();
        assert!(q.is_empty());
        assert_eq!(q.bytes(), 0);
    }
}
