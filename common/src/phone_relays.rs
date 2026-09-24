// common/src/phone_relays.rs
//
// Phone unlock across a relay change: when and where a board tells its phones
// that its relay list moved. The message itself (a kind-24135 whose sealed `t`
// is "relays") is in `phone_unlock`; this module holds every decision around
// it, so the firmware only dials, signs and writes.
//
// A phone listens on every relay it has been told about (enrolment, and the
// list inside each message it opens). A board whose list moves to relays the
// phones never heard of would, the next time it restarts locked, announce
// where no phone listens. So the board keeps a record, [`TOLD_RELAYS_KEY`], of
// the list the phones were last pointed at, and while the live list has a
// relay that record lacks ("drift") it tells the phones on the OLD relays:
//
// - locked, it repeats each phone's lock announcement there ([`OldRelayDials`]:
//   only on an idle pass, well clear of the live relay's own announcements,
//   with a per-relay backoff so a dead relay decays to an hourly probe);
// - unlocked, it posts a relay update per phone there at the gaps of
//   [`RELAY_UPDATE_ROUNDS_SECS`] ([`UpdatePlan`]), then records the live list,
//   which ends the drift.
//
// Every relay change on this firmware takes effect through a restart, so the
// comparison runs once per boot ([`relays_at_boot`]) and needs no hook in any
// config path.
//
// Privacy. An update never goes out on a connection that carries the signer's
// own subscription (its `#p` filter names the signer), because that would tie
// each round, and the number of phones it holds, to a stable key. Every update
// goes out on its own publish-only connection. The firmware's session ceiling
// (two) still holds: the secondary relay steps aside for the dial, and when
// the primary and a pinned relay fill the ceiling the step is deferred
// ([`UpdateAction::Defer`]) rather than open a third TLS session.
//
// Writes. The record is one NVS blob, so every write is atomic: a power cut
// leaves the old or the new record, never a mixture. It is written when first
// needed, when a change only dropped relays, after each of the first five
// update rounds (so a board that restarts daily resumes instead of starting
// over and never converging), and once after the sixth, which also ends the
// drift: at most six writes per relay change. Network-trial boots write
// nothing, because the list may yet roll back.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::data_key::{BlobStore, StoreError};

/// NVS key: the relays the enrolled phones were last pointed at.
pub const TOLD_RELAYS_KEY: &str = "ph_relays";
/// A board's relay list holds at most eight (net_config), and so does this.
pub const MAX_TOLD_RELAYS: usize = 8;
const MAX_TOLD_URL_LEN: usize = 255;
const SET_TAG_HEX_LEN: usize = 16;

/// When an unlocked board posts a relay update, in seconds from its first
/// round. Relays keep no ephemeral event, so each round reaches only the
/// phones listening at that moment; the spacing covers a phone that is
/// reconnecting, asleep for an hour, or off overnight.
pub const RELAY_UPDATE_ROUNDS_SECS: [u64; 6] = [0, 120, 900, 3_600, 21_600, 86_400];
pub const ROUNDS: usize = RELAY_UPDATE_ROUNDS_SECS.len();

/// How long an unlocked board waits before trying a deferred dial again.
pub const DEFER_SECS: u64 = 30;

/// A locked board's old-relay announcements: at most one per relay per
/// interval, doubling per consecutive failure up to the cap.
pub const LOCKED_OLD_INTERVAL_SECS: u64 = 300;
pub const LOCKED_OLD_BACKOFF_MAX_SECS: u64 = 3_600;
/// No old-relay dial within this long after an announcement on the live
/// relay (a phone's answer usually follows it), nor this long before the
/// next one (so a dial never pushes an announcement ahead of a delivery that
/// arrived during it). A dial blocks for at most about 23 s.
pub const LOCKED_QUIET_AFTER_ANNOUNCE_SECS: u64 = 10;
pub const LOCKED_QUIET_BEFORE_ANNOUNCE_SECS: u64 = 30;

// ---------------------------------------------------------------------------
// Relay URLs
// ---------------------------------------------------------------------------

fn norm(u: &str) -> String {
    u.trim().trim_end_matches('/').to_ascii_lowercase()
}

/// Two relay URLs naming the same endpoint, ignoring case and a trailing
/// slash. The firmware's own comparison, so both sides agree on "the same".
pub fn same_relay(a: &str, b: &str) -> bool {
    norm(a) == norm(b)
}

/// A (trimmed) URL the record can hold: non-empty, bounded, and needing no
/// JSON escaping. Anything else is not a relay anyone listens on.
pub fn usable_relay(r: &str) -> bool {
    !r.is_empty()
        && r.len() <= MAX_TOLD_URL_LEN
        && !r.chars().any(|c| c == '"' || c == '\\' || c.is_control())
}

/// The usable relays of a list, trimmed and de-duplicated (first spelling
/// kept), at most [`MAX_TOLD_RELAYS`].
pub fn usable_relays(list: &[String]) -> Vec<String> {
    let mut kept: Vec<String> = Vec::new();
    for r in list.iter().map(|r| r.trim()) {
        if kept.len() == MAX_TOLD_RELAYS {
            break;
        }
        if usable_relay(r) && !kept.iter().any(|k| same_relay(k, r)) {
            kept.push(r.into());
        }
    }
    kept
}

/// Sixteen hex characters naming a relay set, whatever its order or
/// spelling. The record keeps the tag of the list an update is telling, so a
/// second change mid-update starts the rounds again.
pub fn set_tag(relays: &[String]) -> String {
    let mut normed: Vec<String> = usable_relays(relays).iter().map(|r| norm(r)).collect();
    normed.sort();
    let mut h = Sha256::new();
    for r in &normed {
        h.update(r.as_bytes());
        h.update(b"\n");
    }
    crate::hex::hex_encode(&h.finalize()[..SET_TAG_HEX_LEN / 2])
}

// ---------------------------------------------------------------------------
// The record
// ---------------------------------------------------------------------------

/// What [`TOLD_RELAYS_KEY`] holds: the relays the phones were last pointed
/// at, and, while an update is under way, how many rounds have gone out and
/// the tag of the list they are telling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToldRecord {
    pub relays: Vec<String>,
    pub rounds: usize,
    pub toward: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    r: Vec<String>,
    n: u8,
    t: String,
}

/// Largest encoded record: `{"r":[` eight quoted 255-byte URLs and seven
/// commas `],"n":5,"t":"<16 hex>"}`.
pub const MAX_TOLD_BLOB_LEN: usize = 5
    + (2 + MAX_TOLD_RELAYS * (MAX_TOLD_URL_LEN + 2) + (MAX_TOLD_RELAYS - 1))
    + 5
    + 1
    + 6
    + SET_TAG_HEX_LEN
    + 2;

impl ToldRecord {
    /// In step with `current`: no update under way.
    pub fn settled(current: &[String]) -> Self {
        ToldRecord { relays: usable_relays(current), rounds: 0, toward: set_tag(current) }
    }

    pub fn encode(&self) -> Vec<u8> {
        let wire = Wire {
            r: usable_relays(&self.relays),
            n: self.rounds.min(ROUNDS - 1) as u8,
            t: self.toward.clone(),
        };
        serde_json::to_vec(&wire).expect("strings always serialise")
    }

    /// `None` for anything [`ToldRecord::encode`] would not have written.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MAX_TOLD_BLOB_LEN {
            return None;
        }
        let w: Wire = serde_json::from_slice(bytes).ok()?;
        let ok = !w.r.is_empty()
            && w.r.len() <= MAX_TOLD_RELAYS
            && w.r.iter().all(|r| usable_relay(r) && r.trim() == r)
            && (w.n as usize) < ROUNDS
            && w.t.len() == SET_TAG_HEX_LEN
            && w.t.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        ok.then(|| ToldRecord { relays: w.r, rounds: w.n as usize, toward: w.t })
    }
}

/// How the live relay list stands against the one the phones were told.
#[derive(Debug, PartialEq, Eq)]
pub enum RelayDrift {
    /// No record (a board whose phones were enrolled by older firmware), or
    /// a damaged one. Record the live list.
    Unrecorded,
    /// The phones already know every live relay.
    InStep,
    /// As [`RelayDrift::InStep`], but the record still names relays the board
    /// dropped. Record the live list, so an old relay the owner let go of is
    /// not dialled for the next change.
    Shrunk,
    /// A live relay the phones were never told about. `old` is where they
    /// listen: the recorded list.
    Drifted { old: Vec<String> },
}

/// Compare the recorded list with the live one. Only usable live relays
/// count: a URL the record could never hold must not open a drift that no
/// write could ever close.
pub fn relay_drift(told: Option<&[String]>, current: &[String]) -> RelayDrift {
    let Some(told) = told else {
        return RelayDrift::Unrecorded;
    };
    let current = usable_relays(current);
    let known = |r: &String, list: &[String]| list.iter().any(|t| same_relay(t, r));
    if current.iter().any(|c| !known(c, told)) {
        RelayDrift::Drifted { old: usable_relays(told) }
    } else if told.iter().any(|t| !known(t, &current)) {
        RelayDrift::Shrunk
    } else {
        RelayDrift::InStep
    }
}

/// What a boot has to tell the phones: the old relays (empty: nothing) and
/// how many update rounds an earlier boot already sent for this change.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct BootRelays {
    pub old: Vec<String>,
    pub rounds_done: usize,
}

/// Run once per boot with the live relay list. A board with no phones, or no
/// usable live relay, reads and writes nothing. A missing, damaged or
/// shrunk record is rewritten from the live list, except on a network-trial
/// boot (`trial`), which writes nothing.
pub fn relays_at_boot<S: BlobStore>(
    store: &mut S,
    have_phones: bool,
    trial: bool,
    current: &[String],
) -> Result<BootRelays, StoreError> {
    if !have_phones || usable_relays(current).is_empty() {
        return Ok(BootRelays::default());
    }
    let record = store.get(TOLD_RELAYS_KEY)?.and_then(|b| ToldRecord::decode(&b));
    match relay_drift(record.as_ref().map(|r| r.relays.as_slice()), current) {
        RelayDrift::InStep => Ok(BootRelays::default()),
        RelayDrift::Unrecorded | RelayDrift::Shrunk => {
            if !trial {
                store.set(TOLD_RELAYS_KEY, &ToldRecord::settled(current).encode())?;
            }
            Ok(BootRelays::default())
        }
        RelayDrift::Drifted { old } => {
            let record = record.expect("a drift needs a record");
            let rounds_done = if record.toward == set_tag(current) { record.rounds } else { 0 };
            Ok(BootRelays { old, rounds_done })
        }
    }
}

/// Round `done` (counting from one) of telling `old` about `current` has
/// gone out. Before the last, the record keeps `old` and the count; after the
/// last, it becomes `current`, which ends the drift. Returns whether it did.
pub fn record_round<S: BlobStore>(
    store: &mut S,
    old: &[String],
    current: &[String],
    done: usize,
) -> Result<bool, StoreError> {
    if done >= ROUNDS {
        store.set(TOLD_RELAYS_KEY, &ToldRecord::settled(current).encode())?;
        Ok(true)
    } else {
        let record = ToldRecord { relays: usable_relays(old), rounds: done, toward: set_tag(current) };
        store.set(TOLD_RELAYS_KEY, &record.encode())?;
        Ok(false)
    }
}

/// At enrolment: the new phone was handed `current`. If it is the only phone
/// (`had_phones` false), the record is rewritten whatever it says: any record
/// left from before belongs to phones that are gone (a secret cleared or
/// changed, or a power cut between a revoke and its [`forget_told`]).
/// Otherwise it is written only if missing, so an update the other phones
/// are still owed is not cut short.
pub fn record_told_at_enrolment<S: BlobStore>(
    store: &mut S,
    had_phones: bool,
    current: &[String],
) -> Result<(), StoreError> {
    if !had_phones || store.get(TOLD_RELAYS_KEY)?.is_none() {
        store.set(TOLD_RELAYS_KEY, &ToldRecord::settled(current).encode())?;
    }
    Ok(())
}

/// The last phone is gone: nobody listens anywhere.
pub fn forget_told<S: BlobStore>(store: &mut S) -> Result<(), StoreError> {
    if store.get(TOLD_RELAYS_KEY)?.is_some() {
        store.remove(TOLD_RELAYS_KEY)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Unlocked: update rounds
// ---------------------------------------------------------------------------

/// The round schedule on a seconds clock (uptime). After a restart the first
/// remaining round goes out at once (the restart itself spaced it), then the
/// gaps of [`RELAY_UPDATE_ROUNDS_SECS`] apply again.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct UpdateRounds {
    done: usize,
    last_at: Option<u64>,
}

impl UpdateRounds {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn resume(done: usize) -> Self {
        Self { done: done.min(ROUNDS), last_at: None }
    }

    pub fn due(&self, now: u64) -> bool {
        if self.done >= ROUNDS {
            return false;
        }
        match self.last_at {
            None => true,
            Some(last) => {
                let gap = RELAY_UPDATE_ROUNDS_SECS[self.done] - RELAY_UPDATE_ROUNDS_SECS[self.done - 1];
                now >= last.saturating_add(gap)
            }
        }
    }

    /// A round went out at `now`, reaching the phones or not: an old relay
    /// that stays down must not keep the drift open for ever.
    pub fn mark_done(&mut self, now: u64) {
        self.last_at = Some(now);
        self.done = (self.done + 1).min(ROUNDS);
    }

    pub fn rounds_done(&self) -> usize {
        self.done
    }

    pub fn finished(&self) -> bool {
        self.done >= ROUNDS
    }
}

/// What the unlocked loop should do next for a relay update.
#[derive(Debug, PartialEq, Eq)]
pub enum UpdateAction {
    /// Nothing due.
    Wait,
    /// A round is due: load the phones and call [`UpdatePlan::begin_round`].
    StartRound,
    /// Dial `url` publish-only and post this round's updates, after closing
    /// the secondary session if `shed_secondary`.
    Dial { url: String, shed_secondary: bool },
    /// The primary and a pinned relay fill the session ceiling: call
    /// [`UpdatePlan::defer`] and try again later, rather than open a third
    /// TLS session.
    Defer,
    /// Every old relay of this round has been tried: call
    /// [`UpdatePlan::finish_round`] and persist with [`record_round`].
    FinishRound,
}

/// How a round's phone table looked when it began.
#[derive(Debug, PartialEq, Eq)]
pub enum RoundStart {
    Go,
    /// The last phone was revoked: nothing to tell anyone. The plan ends.
    NoPhones,
    /// The table cannot be read: the plan ends for this boot.
    Unreadable,
}

/// An unlocked board's relay update for one drift. RAM only; the round
/// count is persisted by the caller through [`record_round`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdatePlan {
    old: Vec<String>,
    rounds: UpdateRounds,
    queue: Option<Vec<String>>,
    reached: usize,
    retry_at: u64,
    over: bool,
}

impl UpdatePlan {
    pub fn new(old: Vec<String>, rounds_done: usize) -> Self {
        let rounds = UpdateRounds::resume(rounds_done);
        let over = old.is_empty() || rounds.finished();
        Self { old, rounds, queue: None, reached: 0, retry_at: 0, over }
    }

    pub fn old(&self) -> &[String] {
        &self.old
    }

    pub fn rounds_done(&self) -> usize {
        self.rounds.rounds_done()
    }

    /// Old relays this round has reached so far.
    pub fn reached(&self) -> usize {
        self.reached
    }

    /// Nothing more will ever be done this boot.
    pub fn is_over(&self) -> bool {
        self.over
    }

    /// `live` is how many relay sessions are open, `has_secondary` whether
    /// one of them is the redundant secondary, and `max_sessions` the
    /// firmware's ceiling. The dial itself is one more session.
    pub fn next_action(&self, now: u64, live: usize, has_secondary: bool, max_sessions: usize) -> UpdateAction {
        if self.over {
            return UpdateAction::Wait;
        }
        let Some(queue) = &self.queue else {
            return if self.rounds.due(now) { UpdateAction::StartRound } else { UpdateAction::Wait };
        };
        let Some(url) = queue.last() else {
            return UpdateAction::FinishRound;
        };
        if now < self.retry_at {
            return UpdateAction::Wait;
        }
        let staying = live.saturating_sub(usize::from(has_secondary));
        if staying + 1 > max_sessions {
            return UpdateAction::Defer;
        }
        UpdateAction::Dial { url: url.clone(), shed_secondary: has_secondary }
    }

    /// Begin the due round with the phone table as it is now (`Err`:
    /// unreadable; `Ok(n)`: n phones).
    pub fn begin_round(&mut self, phones: Result<usize, ()>) -> RoundStart {
        match phones {
            Ok(0) => {
                self.over = true;
                RoundStart::NoPhones
            }
            Err(()) => {
                self.over = true;
                RoundStart::Unreadable
            }
            Ok(_) => {
                self.queue = Some(self.old.iter().rev().cloned().collect());
                self.reached = 0;
                RoundStart::Go
            }
        }
    }

    /// The dial to the head of the queue happened: `true` when the relay
    /// took the connection and the events (whatever it then said).
    pub fn dialled(&mut self, reached: bool) {
        if let Some(q) = self.queue.as_mut() {
            q.pop();
        }
        self.reached += usize::from(reached);
    }

    /// Put the head of the queue off for [`DEFER_SECS`] (ceiling full, or a
    /// heap too tight to dial).
    pub fn defer(&mut self, now: u64) {
        self.retry_at = now.saturating_add(DEFER_SECS);
    }

    /// Close the round. Returns the rounds done so far, for [`record_round`].
    pub fn finish_round(&mut self, now: u64) -> usize {
        self.queue = None;
        self.rounds.mark_done(now);
        if self.rounds.finished() {
            self.over = true;
        }
        self.rounds.rounds_done()
    }
}

// ---------------------------------------------------------------------------
// Locked: old-relay announcements
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct OldRelay {
    url: String,
    fails: u32,
    next_at: u64,
}

/// A locked board's schedule for repeating its phone announcements on the
/// old relays: one dial per idle pass, well clear of the live relay's own
/// announcements, each relay at most once per [`LOCKED_OLD_INTERVAL_SECS`],
/// backing off per consecutive failure (pinned-relay style) so a dead relay
/// costs a blocked loop once an hour, not every five minutes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OldRelayDials {
    relays: Vec<OldRelay>,
}

impl OldRelayDials {
    pub fn new(old: &[String]) -> Self {
        Self {
            relays: usable_relays(old)
                .into_iter()
                .map(|url| OldRelay { url, fails: 0, next_at: 0 })
                .collect(),
        }
    }

    /// The old relay to dial on this pass, if any.
    ///
    /// - `idle`: this pass parsed no frame and read nothing from the live
    ///   relay, so no delivery is waiting behind the dial;
    /// - `last_announce`: when the live relay last carried an announcement
    ///   (`None`: not yet, so the phones' author is not out yet either);
    /// - `next_announce`: when the next one is due;
    /// - `live`: the live relay's URL, which needs no dial.
    pub fn next(&self, now: u64, idle: bool, last_announce: Option<u64>, next_announce: u64, live: &str) -> Option<&str> {
        let last = last_announce?;
        if !idle
            || now < last.saturating_add(LOCKED_QUIET_AFTER_ANNOUNCE_SECS)
            || now.saturating_add(LOCKED_QUIET_BEFORE_ANNOUNCE_SECS) > next_announce
        {
            return None;
        }
        self.relays
            .iter()
            .find(|r| r.next_at <= now && !same_relay(&r.url, live))
            .map(|r| r.url.as_str())
    }

    /// The dial to `url` at `now` reached the relay (`ok`) or failed.
    pub fn report(&mut self, url: &str, ok: bool, now: u64) {
        if let Some(r) = self.relays.iter_mut().find(|r| r.url == url) {
            if ok {
                r.fails = 0;
                r.next_at = now.saturating_add(LOCKED_OLD_INTERVAL_SECS);
            } else {
                r.fails = r.fails.saturating_add(1);
                let backoff = LOCKED_OLD_INTERVAL_SECS
                    .saturating_mul(1u64 << r.fails.min(8))
                    .min(LOCKED_OLD_BACKOFF_MAX_SECS);
                r.next_at = now.saturating_add(backoff);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Relay OK frames
// ---------------------------------------------------------------------------

/// Counts a relay's `["OK", <id>, <accepted>, <message>]` answers to the
/// events a publish-only connection sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OkTally {
    waiting: Vec<String>,
    accepted: usize,
}

impl OkTally {
    pub fn new(ids: Vec<String>) -> Self {
        Self { waiting: ids, accepted: 0 }
    }

    /// Feed one text frame from the relay. Anything that is not an OK for an
    /// event still waiting is ignored, so a repeat cannot count twice.
    pub fn feed(&mut self, raw: &[u8]) {
        let Ok((tag, id, ok, _)) = serde_json::from_slice::<(String, String, bool, serde_json::Value)>(raw) else {
            return;
        };
        if tag != "OK" {
            return;
        }
        if let Some(pos) = self.waiting.iter().position(|w| *w == id) {
            self.waiting.swap_remove(pos);
            self.accepted += usize::from(ok);
        }
    }

    pub fn done(&self) -> bool {
        self.waiting.is_empty()
    }

    pub fn accepted(&self) -> usize {
        self.accepted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    fn urls(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| String::from(*s)).collect()
    }

    /// A map that counts every read and write, and can be told to fail.
    #[derive(Default)]
    struct Store {
        map: alloc::collections::BTreeMap<String, Vec<u8>>,
        reads: core::cell::Cell<usize>,
        writes: usize,
        broken: bool,
    }

    impl BlobStore for Store {
        fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
            self.reads.set(self.reads.get() + 1);
            if self.broken {
                return Err(StoreError);
            }
            Ok(self.map.get(key).cloned())
        }
        fn set(&mut self, key: &str, value: &[u8]) -> Result<(), StoreError> {
            if self.broken {
                return Err(StoreError);
            }
            self.writes += 1;
            self.map.insert(key.into(), value.to_vec());
            Ok(())
        }
        fn remove(&mut self, key: &str) -> Result<(), StoreError> {
            if self.broken {
                return Err(StoreError);
            }
            self.writes += 1;
            self.map.remove(key);
            Ok(())
        }
    }

    impl Store {
        fn record(&self) -> Option<ToldRecord> {
            self.map.get(TOLD_RELAYS_KEY).map(|b| ToldRecord::decode(b).unwrap())
        }
        fn told(&self) -> Option<Vec<String>> {
            self.record().map(|r| r.relays)
        }
    }

    #[test]
    fn relay_drift_compares_as_the_firmware_does() {
        let told = urls(&["wss://a.example", "wss://b.example/"]);
        assert_eq!(relay_drift(None, &urls(&["wss://a.example"])), RelayDrift::Unrecorded);
        assert_eq!(
            relay_drift(Some(&told), &urls(&["WSS://A.example/", " wss://b.example"])),
            RelayDrift::InStep,
            "case, trailing slash and whitespace are the same relay"
        );
        assert_eq!(relay_drift(Some(&told), &urls(&["wss://b.example"])), RelayDrift::Shrunk);
        assert_eq!(
            relay_drift(Some(&told), &urls(&["wss://b.example", "wss://c.example"])),
            RelayDrift::Drifted { old: told.clone() },
            "one new relay is enough; the update goes to every old one"
        );
        assert_eq!(
            relay_drift(Some(&urls(&["wss://a.example", "wss://A.example/"])), &urls(&["wss://c.example"])),
            RelayDrift::Drifted { old: urls(&["wss://a.example"]) },
            "old relays are de-duplicated"
        );
    }

    #[test]
    fn an_unencodable_live_url_never_opens_a_drift() {
        let told = urls(&["wss://a.example"]);
        for odd in ["wss://q\"uote", "wss://back\\slash", "wss://ctl\u{7}", ""] {
            let current = urls(&["wss://a.example", odd]);
            assert_eq!(relay_drift(Some(&told), &current), RelayDrift::InStep, "{odd:?}");
        }
        // And a live list of nothing usable is left alone entirely.
        let mut store = Store::default();
        assert_eq!(
            relays_at_boot(&mut store, true, false, &urls(&["wss://q\"uote"])),
            Ok(BootRelays::default())
        );
        assert_eq!((store.reads.get(), store.writes), (0, 0));
    }

    #[test]
    fn the_record_round_trips_and_refuses_damage() {
        let rec = ToldRecord {
            relays: urls(&[" wss://a.example ", "", "wss://A.example/", "wss://q\"uote", "wss://b.example"]),
            rounds: 3,
            toward: set_tag(&urls(&["wss://c.example"])),
        };
        let back = ToldRecord::decode(&rec.encode()).unwrap();
        assert_eq!(back.relays, urls(&["wss://a.example", "wss://b.example"]));
        assert_eq!((back.rounds, back.toward.len()), (3, 16));

        let many: Vec<String> = (0..12).map(|i| format!("wss://r{i}.example")).collect();
        assert_eq!(ToldRecord::decode(&ToldRecord::settled(&many).encode()).unwrap().relays.len(), MAX_TOLD_RELAYS);

        let longest: Vec<String> =
            (0..8).map(|i| format!("wss://{i}{}", "x".repeat(MAX_TOLD_URL_LEN - 7))).collect();
        let full = ToldRecord { relays: longest.clone(), rounds: ROUNDS - 1, toward: set_tag(&longest) };
        assert_eq!(full.encode().len(), MAX_TOLD_BLOB_LEN, "the bound is exact");
        assert!(
            MAX_TOLD_BLOB_LEN <= crate::data_key::MAX_PHONES_BLOB_LEN,
            "the firmware reads it through the same bounded blob reader"
        );

        let tag = set_tag(&urls(&["wss://a"]));
        for bad in [
            String::from("not json"),
            String::from("[\"wss://a\"]"),
            format!(r#"{{"r":[],"n":0,"t":"{tag}"}}"#),
            format!(r#"{{"r":[" wss://a"],"n":0,"t":"{tag}"}}"#),
            format!(r#"{{"r":["wss://a"],"n":6,"t":"{tag}"}}"#),
            String::from(r#"{"r":["wss://a"],"n":0,"t":"XYZ"}"#),
            format!(r#"{{"r":["wss://a"],"n":0,"t":"{tag}","x":1}}"#),
        ] {
            assert_eq!(ToldRecord::decode(bad.as_bytes()), None, "{bad}");
        }
    }

    #[test]
    fn a_set_tag_ignores_order_and_spelling_only() {
        let a = set_tag(&urls(&["wss://a.example", "wss://b.example"]));
        assert_eq!(a, set_tag(&urls(&["WSS://B.example/", "wss://a.example", "wss://a.example"])));
        assert_ne!(a, set_tag(&urls(&["wss://a.example"])));
        assert_ne!(a, set_tag(&urls(&["wss://a.example", "wss://c.example"])));
    }

    #[test]
    fn the_boot_check_writes_only_when_the_record_changes() {
        let a = urls(&["wss://a.example"]);
        let ab = urls(&["wss://a.example", "wss://b.example"]);
        let c = urls(&["wss://c.example"]);

        // No phones, or no live relay: nothing read, nothing written.
        let mut store = Store::default();
        assert_eq!(relays_at_boot(&mut store, false, false, &a), Ok(BootRelays::default()));
        assert_eq!(relays_at_boot(&mut store, true, false, &[]), Ok(BootRelays::default()));
        assert_eq!((store.reads.get(), store.writes), (0, 0));

        // First boot with phones (enrolled by older firmware): record, once.
        assert_eq!(relays_at_boot(&mut store, true, false, &ab), Ok(BootRelays::default()));
        assert_eq!((store.told(), store.writes), (Some(ab.clone()), 1));
        assert_eq!(relays_at_boot(&mut store, true, false, &ab), Ok(BootRelays::default()));
        assert_eq!(store.writes, 1, "a board in step never writes");

        // The owner moves to c: every boot until the update is done reports
        // the old relays, and the boot check itself writes nothing.
        for _ in 0..3 {
            assert_eq!(
                relays_at_boot(&mut store, true, false, &c),
                Ok(BootRelays { old: ab.clone(), rounds_done: 0 })
            );
        }
        assert_eq!(store.writes, 1);

        // Dropping a relay needs no update, one write to forget it.
        let mut store = Store::default();
        store.map.insert(TOLD_RELAYS_KEY.into(), ToldRecord::settled(&ab).encode());
        assert_eq!(relays_at_boot(&mut store, true, false, &a), Ok(BootRelays::default()));
        assert_eq!((store.told(), store.writes), (Some(a.clone()), 1));

        // A damaged record is rewritten from the live list.
        store.map.insert(TOLD_RELAYS_KEY.into(), b"\xff\xfe".to_vec());
        assert_eq!(relays_at_boot(&mut store, true, false, &c), Ok(BootRelays::default()));
        assert_eq!(store.told(), Some(c.clone()));

        // A store that fails is an error, never "nothing to do".
        let mut broken = Store { broken: true, ..Store::default() };
        assert_eq!(relays_at_boot(&mut broken, true, false, &a), Err(StoreError));
    }

    #[test]
    fn a_network_trial_boot_writes_nothing() {
        let a = urls(&["wss://a.example"]);
        let ab = urls(&["wss://a.example", "wss://b.example"]);
        let c = urls(&["wss://c.example"]);
        let mut store = Store::default();
        assert_eq!(relays_at_boot(&mut store, true, true, &a), Ok(BootRelays::default()));
        assert_eq!(store.writes, 0, "unrecorded: left for a committed boot");
        store.map.insert(TOLD_RELAYS_KEY.into(), ToldRecord::settled(&ab).encode());
        assert_eq!(relays_at_boot(&mut store, true, true, &a), Ok(BootRelays::default()));
        assert_eq!(store.writes, 0, "shrunk: left as it is");
        assert_eq!(
            relays_at_boot(&mut store, true, true, &c),
            Ok(BootRelays { old: ab.clone(), rounds_done: 0 }),
            "a drift is still told (a phone may need to unlock the trial boot)"
        );
        assert_eq!(store.told(), Some(ab));
    }

    #[test]
    fn rounds_persist_resume_and_end_the_drift_in_six_writes() {
        let ab = urls(&["wss://a.example", "wss://b.example"]);
        let c = urls(&["wss://c.example"]);
        let mut store = Store::default();
        store.map.insert(TOLD_RELAYS_KEY.into(), ToldRecord::settled(&ab).encode());
        let before = store.writes;

        // Each boot sends one round and restarts: the record carries the
        // count, so the board converges instead of starting over.
        for round in 1..=ROUNDS {
            let boot = relays_at_boot(&mut store, true, false, &c).unwrap();
            assert_eq!(boot, BootRelays { old: ab.clone(), rounds_done: round - 1 });
            let mut plan = UpdatePlan::new(boot.old.clone(), boot.rounds_done);
            assert_eq!(plan.next_action(0, 1, false, 2), UpdateAction::StartRound, "resumes at once");
            assert_eq!(plan.begin_round(Ok(2)), RoundStart::Go);
            while let UpdateAction::Dial { .. } = plan.next_action(0, 1, false, 2) {
                plan.dialled(true);
            }
            assert_eq!(plan.next_action(0, 1, false, 2), UpdateAction::FinishRound);
            let done = plan.finish_round(0);
            assert_eq!(done, round);
            let ended = record_round(&mut store, plan.old(), &c, done).unwrap();
            assert_eq!(ended, round == ROUNDS);
            assert_eq!(plan.is_over(), round == ROUNDS);
        }
        assert_eq!(store.writes - before, ROUNDS, "one write per round, the last ends the drift");
        assert_eq!(store.told(), Some(c.clone()));
        assert_eq!(relays_at_boot(&mut store, true, false, &c), Ok(BootRelays::default()));
    }

    #[test]
    fn a_second_change_mid_update_starts_the_rounds_again() {
        let a = urls(&["wss://a.example"]);
        let c = urls(&["wss://c.example"]);
        let d = urls(&["wss://d.example"]);
        let mut store = Store::default();
        store.map.insert(TOLD_RELAYS_KEY.into(), ToldRecord::settled(&a).encode());
        record_round(&mut store, &a, &c, 4).unwrap();
        assert_eq!(relays_at_boot(&mut store, true, false, &c).unwrap().rounds_done, 4);
        assert_eq!(
            relays_at_boot(&mut store, true, false, &d),
            Ok(BootRelays { old: a.clone(), rounds_done: 0 }),
            "the phones on a have been told nothing about d"
        );
    }

    #[test]
    fn a_failed_final_write_repeats_the_last_round_next_boot() {
        let a = urls(&["wss://a.example"]);
        let c = urls(&["wss://c.example"]);
        let mut store = Store::default();
        store.map.insert(TOLD_RELAYS_KEY.into(), ToldRecord::settled(&a).encode());
        record_round(&mut store, &a, &c, ROUNDS - 1).unwrap();
        store.broken = true;
        assert_eq!(record_round(&mut store, &a, &c, ROUNDS), Err(StoreError));
        store.broken = false;
        assert_eq!(
            relays_at_boot(&mut store, true, false, &c),
            Ok(BootRelays { old: a.clone(), rounds_done: ROUNDS - 1 })
        );
    }

    #[test]
    fn enrolment_after_every_phone_left_replaces_a_stale_record() {
        let a = urls(&["wss://a.example"]);
        let c = urls(&["wss://c.example"]);
        // A stale record: its phones went (secret cleared, or a cut between
        // revoke's save and forget_told) and the board moved on to c.
        let mut store = Store::default();
        store.map.insert(TOLD_RELAYS_KEY.into(), ToldRecord::settled(&a).encode());
        record_told_at_enrolment(&mut store, false, &c).unwrap();
        assert_eq!(store.told(), Some(c.clone()), "the only phone knows c; nobody listens on a");
        assert_eq!(relays_at_boot(&mut store, true, false, &c), Ok(BootRelays::default()));

        // With other phones still owed an update, the record is kept.
        store.map.insert(TOLD_RELAYS_KEY.into(), ToldRecord::settled(&a).encode());
        record_told_at_enrolment(&mut store, true, &c).unwrap();
        assert_eq!(store.told(), Some(a.clone()));
        // With other phones and no record, it is written.
        store.map.clear();
        record_told_at_enrolment(&mut store, true, &c).unwrap();
        assert_eq!(store.told(), Some(c.clone()));

        forget_told(&mut store).unwrap();
        assert_eq!(store.told(), None);
        let writes = store.writes;
        forget_told(&mut store).unwrap();
        assert_eq!(store.writes, writes, "nothing to forget, nothing written");
        let mut broken = Store { broken: true, ..Store::default() };
        assert_eq!(record_told_at_enrolment(&mut broken, true, &c), Err(StoreError));
        assert_eq!(forget_told(&mut broken), Err(StoreError));
    }

    #[test]
    fn update_rounds_follow_the_schedule_and_stop() {
        let mut r = UpdateRounds::new();
        assert!(r.due(0) && r.due(5_000), "the first round goes out at once");
        let start = 1_000;
        r.mark_done(start);
        let mut last = start;
        for i in 1..ROUNDS {
            let gap = RELAY_UPDATE_ROUNDS_SECS[i] - RELAY_UPDATE_ROUNDS_SECS[i - 1];
            assert!(!r.finished());
            assert_eq!(r.rounds_done(), i);
            assert!(!r.due(last + gap - 1), "round {i} early");
            assert!(r.due(last + gap), "round {i} on time");
            last += gap;
            r.mark_done(last);
        }
        assert_eq!(last - start, RELAY_UPDATE_ROUNDS_SECS[ROUNDS - 1], "the table is cumulative");
        assert!(r.finished());
        assert!(!r.due(u64::MAX));
        assert!(RELAY_UPDATE_ROUNDS_SECS.windows(2).all(|w| w[0] < w[1]));

        let mut resumed = UpdateRounds::resume(3);
        assert!(resumed.due(0), "after a restart the next round goes out at once");
        resumed.mark_done(10);
        assert!(!resumed.due(10 + RELAY_UPDATE_ROUNDS_SECS[4] - RELAY_UPDATE_ROUNDS_SECS[3] - 1));
        assert!(!UpdateRounds::resume(ROUNDS).due(0));
    }

    #[test]
    fn the_plan_dials_publish_only_and_never_breaks_the_session_ceiling() {
        let old = urls(&["wss://a.example", "wss://b.example"]);
        let mut plan = UpdatePlan::new(old.clone(), 0);
        assert_eq!(plan.next_action(0, 1, false, 2), UpdateAction::StartRound);
        assert_eq!(plan.begin_round(Ok(1)), RoundStart::Go);

        // Primary alone: dial.
        assert_eq!(
            plan.next_action(0, 1, false, 2),
            UpdateAction::Dial { url: old[0].clone(), shed_secondary: false }
        );
        // Primary and secondary: the secondary steps aside.
        assert_eq!(
            plan.next_action(0, 2, true, 2),
            UpdateAction::Dial { url: old[0].clone(), shed_secondary: true }
        );
        // Primary and a pinned relay fill the ceiling: defer, never a third.
        assert_eq!(plan.next_action(0, 2, false, 2), UpdateAction::Defer);
        plan.defer(100);
        assert_eq!(plan.next_action(100 + DEFER_SECS - 1, 1, false, 2), UpdateAction::Wait);
        assert!(matches!(plan.next_action(100 + DEFER_SECS, 1, false, 2), UpdateAction::Dial { .. }));

        // Even a live session on an old relay is not used: every old relay is dialled.
        plan.dialled(true);
        assert_eq!(
            plan.next_action(200, 1, false, 2),
            UpdateAction::Dial { url: old[1].clone(), shed_secondary: false }
        );
        plan.dialled(false);
        assert_eq!(plan.reached(), 1);
        assert_eq!(plan.next_action(200, 1, false, 2), UpdateAction::FinishRound);
        assert_eq!(plan.finish_round(200), 1);
        assert_eq!(plan.next_action(201, 1, false, 2), UpdateAction::Wait);
        assert_eq!(plan.next_action(200 + 120, 1, false, 2), UpdateAction::StartRound);
    }

    #[test]
    fn the_plan_ends_with_no_phones_or_an_unreadable_table() {
        let old = urls(&["wss://a.example"]);
        let mut plan = UpdatePlan::new(old.clone(), 0);
        assert_eq!(plan.begin_round(Ok(0)), RoundStart::NoPhones);
        assert!(plan.is_over());
        assert_eq!(plan.next_action(10_000_000, 0, false, 2), UpdateAction::Wait);
        let mut plan = UpdatePlan::new(old.clone(), 2);
        assert_eq!(plan.begin_round(Err(())), RoundStart::Unreadable);
        assert!(plan.is_over());
        assert!(UpdatePlan::new(Vec::new(), 0).is_over(), "no old relays, nothing to do");
        assert!(UpdatePlan::new(old, ROUNDS).is_over());
    }

    #[test]
    fn locked_dials_wait_for_an_idle_pass_clear_of_announcements() {
        let old = urls(&["wss://a.example", "wss://live.example", "wss://b.example"]);
        let mut d = OldRelayDials::new(&old);
        let live = "wss://LIVE.example/";
        // Nothing before the first announcement.
        assert_eq!(d.next(100, true, None, 160, live), None);
        // The announce went out at 100; the next is due at 160.
        assert_eq!(d.next(105, true, Some(100), 160, live), None, "too soon after");
        assert_eq!(d.next(110, false, Some(100), 160, live), None, "a frame or a read this pass");
        assert_eq!(d.next(131, true, Some(100), 160, live), None, "too close to the next");
        assert_eq!(d.next(110, true, Some(100), 160, live), Some("wss://a.example"));
        assert_eq!(d.next(130, true, Some(100), 160, live), Some("wss://a.example"));

        // The live relay is never dialled; each relay rests an interval.
        d.report("wss://a.example", true, 110);
        assert_eq!(d.next(111, true, Some(100), 160, live), Some("wss://b.example"));
        d.report("wss://b.example", true, 111);
        assert_eq!(d.next(112, true, Some(100), 160, live), None);
        assert_eq!(
            d.next(110 + LOCKED_OLD_INTERVAL_SECS, true, Some(110 + LOCKED_OLD_INTERVAL_SECS - 20), 110 + LOCKED_OLD_INTERVAL_SECS + 40, live),
            Some("wss://a.example")
        );
    }

    #[test]
    fn a_dead_old_relay_backs_off_to_an_hourly_probe() {
        let mut d = OldRelayDials::new(&urls(&["wss://dead.example"]));
        let mut now = 0u64;
        let mut gaps = Vec::new();
        for _ in 0..8 {
            d.report("wss://dead.example", false, now);
            let next = d.relays[0].next_at;
            gaps.push(next - now);
            now = next;
        }
        assert_eq!(gaps[..4], [600, 1200, 2400, 3600]);
        assert!(gaps.iter().all(|g| *g <= LOCKED_OLD_BACKOFF_MAX_SECS));
        d.report("wss://dead.example", true, now);
        assert_eq!(d.relays[0].next_at - now, LOCKED_OLD_INTERVAL_SECS, "one success resets it");
    }

    #[test]
    fn ok_frames_are_counted_once_per_event() {
        let mut t = OkTally::new(urls(&["e1", "e2", "e3"]));
        t.feed(br#"["OK","e1",true,""]"#);
        t.feed(br#"["OK","e1",true,""]"#);
        t.feed(br#"["OK","e2",false,"blocked: no"]"#);
        t.feed(br#"["OK","zz",true,""]"#);
        t.feed(br#"["NOTICE","e3"]"#);
        t.feed(br#"["EVENT","e3",true,""]"#);
        t.feed(b"garbage");
        assert!(!t.done());
        assert_eq!(t.accepted(), 1);
        t.feed(br#"["OK","e3",true,"duplicate: already have it"]"#);
        assert!(t.done());
        assert_eq!(t.accepted(), 2);
    }
}
