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
//   one old relay per announce interval, in the pass straight after the live
//   announcement, with a per-relay backoff so a dead relay decays to an
//   hourly probe);
// - unlocked, it posts a relay update per phone there in six rounds over
//   about a day ([`UpdatePlan`], with random delays), then records the live
//   list, which ends the drift.
//
// Every relay change on this firmware takes effect through a restart, so the
// comparison runs once per boot ([`relays_at_boot`]) and needs no hook in any
// config path.
//
// What a relay can and cannot link. Each round has a fresh one-time author and
// fresh hints, so nothing inside the events ties one round to another, to a
// boot's lock announcements, or to a phone. What is not hidden is the board's
// IP address, which every relay it uses already sees, and timing. So an update
// never goes out on a connection that carries the signer's own subscription
// (its `#p` filter names the signer), it goes out on a publish-only
// connection of its own; the first round waits a random 2 to 20 minutes after
// the board comes online, and every gap in the schedule is randomised by a
// quarter either way, so the rounds neither sit beside the signer's REQ nor
// form a fixed, recognisable series. A relay that logs IP addresses can still
// see that the same address published a burst of 24135s some minutes after
// its signer reconnected; that is inherent in a board with one address.
//
// The firmware's session ceiling (two) always holds. The secondary relay
// closes for the round. When the primary and a pinned relay fill the ceiling
// the step waits ([`UpdateAction::Defer`]); after [`MAX_DEFER_SECS`] the pinned
// session steps aside for one dial, as the secondary does, so every board
// converges.
//
// Writes. The record is one NVS blob, so every write is atomic: a power cut
// leaves the old or the new record, never a mixture. It is written when first
// needed, when a change only dropped relays, after each of the first five
// update rounds (so a board that restarts daily resumes instead of starting
// over), and once after the sixth, which also ends the drift: six writes per
// relay change in the usual case. A round that dialled nothing (every relay
// given up for a tight heap) does not count, and the drift ends only once
// some round has had an event accepted; until then the sixth round repeats at
// its gap, writing only when the record changes. A round writes only while the stored record is
// still the one it works from: a revoke or an enrolment mid-plan ends the
// plan instead of being overwritten. Network-trial boots write nothing, and a
// record this firmware cannot read (damaged, or from newer firmware) is left
// as it is.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::data_key::{BlobStore, PhoneRecord, PhoneSet, StoreError};

/// NVS key: the relays the enrolled phones were last pointed at.
pub const TOLD_RELAYS_KEY: &str = "ph_relays";
/// A board's relay list holds at most eight (net_config), and so does this.
pub const MAX_TOLD_RELAYS: usize = 8;
const MAX_TOLD_URL_LEN: usize = 255;
const SET_TAG_HEX_LEN: usize = 16;

/// The update schedule's nominal offsets, in seconds from the first round.
/// Relays keep no ephemeral event, so each round reaches only the phones
/// listening at that moment; the spacing covers a phone that is
/// reconnecting, asleep for an hour, or off overnight. Each gap is
/// randomised by a quarter either way ([`jittered_gap`]).
pub const RELAY_UPDATE_ROUNDS_SECS: [u64; 6] = [0, 120, 900, 3_600, 21_600, 86_400];
pub const ROUNDS: usize = RELAY_UPDATE_ROUNDS_SECS.len();

/// The first round of a boot (a fresh update, or one resumed after a
/// restart) goes out a random 2 to 20 minutes after the board comes online.
pub const FIRST_ROUND_MIN_SECS: u64 = 120;
pub const FIRST_ROUND_MAX_SECS: u64 = 1_200;

/// How long an unlocked board waits before trying a deferred dial again.
pub const DEFER_SECS: u64 = 30;
/// How long a dial may wait on a full session ceiling before the pinned
/// session steps aside, or on a tight heap before the relay is given up for
/// this round.
pub const MAX_DEFER_SECS: u64 = 600;

/// A pinned session steps aside only once it has nothing buffered and has
/// been quiet this long, so a NIP-46 request in flight is not dropped.
pub const PINNED_QUIET_SECS: u64 = 5;

/// Whether the pinned session may close for a dial now: nothing buffered
/// (`rx_empty`, including no oversize frame being skipped) and nothing
/// received for [`PINNED_QUIET_SECS`]. Otherwise the plan tries again next
/// pass.
pub fn pinned_may_step_aside(rx_empty: bool, quiet_secs: u64) -> bool {
    rx_empty && quiet_secs >= PINNED_QUIET_SECS
}

/// A locked board's old-relay announcements: at most one per relay per
/// interval, doubling per consecutive failure up to the cap.
pub const LOCKED_OLD_INTERVAL_SECS: u64 = 300;
pub const LOCKED_OLD_BACKOFF_MAX_SECS: u64 = 3_600;

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
/// the tag of the list they are telling (empty when unknown).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToldRecord {
    pub relays: Vec<String>,
    pub rounds: usize,
    pub toward: String,
    /// Some round of this update has had an event accepted by an old relay.
    pub reached: bool,
}

/// Lenient on read: unknown fields are ignored and `n` / `t` may be absent,
/// so a record written by newer firmware still reads here.
#[derive(Serialize, Deserialize)]
struct Wire {
    r: Vec<String>,
    #[serde(default)]
    n: u8,
    #[serde(default)]
    t: String,
    #[serde(default)]
    a: bool,
}

/// Largest record this firmware writes: `{"r":[` eight quoted 255-byte URLs
/// and seven commas `],"n":5,"t":"<16 hex>","a":false}`.
pub const MAX_TOLD_BLOB_LEN: usize = 5
    + (2 + MAX_TOLD_RELAYS * (MAX_TOLD_URL_LEN + 2) + (MAX_TOLD_RELAYS - 1))
    + 5
    + 1
    + 6
    + SET_TAG_HEX_LEN
    + 1
    + 10
    + 1;
/// Largest record it reads: room for fields a newer firmware may add.
pub const MAX_TOLD_READ_LEN: usize = crate::data_key::MAX_PHONES_BLOB_LEN;

impl ToldRecord {
    /// In step with `current`: no update under way.
    pub fn settled(current: &[String]) -> Self {
        ToldRecord { relays: usable_relays(current), rounds: 0, toward: set_tag(current), reached: false }
    }

    pub fn encode(&self) -> Vec<u8> {
        let wire = Wire {
            r: usable_relays(&self.relays),
            n: self.rounds.min(ROUNDS - 1) as u8,
            t: self.toward.clone(),
            a: self.reached,
        };
        serde_json::to_vec(&wire).expect("strings always serialise")
    }

    /// `None` for anything this firmware cannot use.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MAX_TOLD_READ_LEN {
            return None;
        }
        let w: Wire = serde_json::from_slice(bytes).ok()?;
        let ok = !w.r.is_empty()
            && w.r.len() <= MAX_TOLD_RELAYS
            && w.r.iter().all(|r| usable_relay(r) && r.trim() == r)
            && (w.n as usize) < ROUNDS
            && (w.t.is_empty()
                || (w.t.len() == SET_TAG_HEX_LEN
                    && w.t.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))));
        ok.then(|| ToldRecord { relays: w.r, rounds: w.n as usize, toward: w.t, reached: w.a })
    }

    /// As it reads back after [`ToldRecord::encode`].
    fn stored(&self) -> Self {
        Self::decode(&self.encode()).expect("an encoded record decodes")
    }
}

/// How the live relay list stands against the one the phones were told.
#[derive(Debug, PartialEq, Eq)]
pub enum RelayDrift {
    /// No record: a board whose phones were enrolled by older firmware.
    /// Record the live list.
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

/// What a boot has to tell the phones: the old relays (empty: nothing), how
/// many update rounds an earlier boot already sent for this change, and the
/// record as it stood (every later write checks it is still there).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct BootRelays {
    pub old: Vec<String>,
    pub rounds_done: usize,
    /// An earlier round of this change had an event accepted.
    pub reached: bool,
    pub record: Option<ToldRecord>,
    /// A record was present but this firmware cannot read it; it was left
    /// untouched and nothing will be told this boot.
    pub unreadable: bool,
}

/// Run once per boot with the live relay list. A board with no phones, or no
/// usable live relay, reads and writes nothing. A missing or shrunk record is
/// rewritten from the live list, except on a network-trial boot (`trial`),
/// which writes nothing. A present record it cannot read is left untouched.
pub fn relays_at_boot<S: BlobStore>(
    store: &mut S,
    have_phones: bool,
    trial: bool,
    current: &[String],
) -> Result<BootRelays, StoreError> {
    if !have_phones || usable_relays(current).is_empty() {
        return Ok(BootRelays::default());
    }
    let record = match store.get(TOLD_RELAYS_KEY)? {
        None => None,
        Some(bytes) => match ToldRecord::decode(&bytes) {
            Some(r) => Some(r),
            None => return Ok(BootRelays { unreadable: true, ..BootRelays::default() }),
        },
    };
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
            let same_change = record.toward == set_tag(current);
            let rounds_done = if same_change { record.rounds } else { 0 };
            let reached = same_change && record.reached;
            Ok(BootRelays { old, rounds_done, reached, record: Some(record), unreadable: false })
        }
    }
}

/// Whether the stored record is still `expected`. A revoke of the last phone
/// removes it and an enrolment after that replaces it; either way a plan
/// working from the old record has nothing left to do.
pub fn record_is<S: BlobStore>(store: &S, expected: &ToldRecord) -> Result<bool, StoreError> {
    Ok(store.get(TOLD_RELAYS_KEY)?.and_then(|b| ToldRecord::decode(&b)).as_ref() == Some(expected))
}

/// What [`record_round`] did.
#[derive(Debug, PartialEq, Eq)]
pub enum RoundRecorded {
    /// The stored record is no longer the plan's: nothing written, the plan
    /// ends.
    Superseded,
    /// The count moved on; this is the record now stored.
    Progress(ToldRecord),
    /// The last round: the live list is recorded and the drift is over.
    Ended,
}

/// Round `done` (counting from one) of telling the phones about `current`
/// has gone out; `reached`: some round of this change has had an event
/// accepted. Writes only while the stored record is still `expected`, and
/// only when the record would change. The drift ends (the record becomes
/// `current`) only after the last round and only if `reached`; otherwise the
/// record keeps the old list and the count.
pub fn record_round<S: BlobStore>(
    store: &mut S,
    expected: &ToldRecord,
    current: &[String],
    done: usize,
    reached: bool,
) -> Result<RoundRecorded, StoreError> {
    if !record_is(store, expected)? {
        return Ok(RoundRecorded::Superseded);
    }
    if done >= ROUNDS && reached {
        store.set(TOLD_RELAYS_KEY, &ToldRecord::settled(current).encode())?;
        return Ok(RoundRecorded::Ended);
    }
    let next = ToldRecord {
        relays: expected.relays.clone(),
        rounds: done.min(ROUNDS - 1),
        toward: set_tag(current),
        reached,
    }
    .stored();
    if next != *expected {
        store.set(TOLD_RELAYS_KEY, &next.encode())?;
    }
    Ok(RoundRecorded::Progress(next))
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

/// The phones a dial may still address: those the round began with that are
/// still enrolled now. A phone revoked mid-round gets nothing from the next
/// dial, and one enrolled mid-round (handed the live list already) is not
/// added.
pub fn round_phones<'a>(round_ids: &'a [u32], table: &'a PhoneSet) -> impl Iterator<Item = &'a PhoneRecord> + 'a {
    table.records().iter().filter(move |r| round_ids.contains(&r.id))
}

// ---------------------------------------------------------------------------
// Unlocked: update rounds
// ---------------------------------------------------------------------------

/// A gap of the schedule, randomised to between three quarters and five
/// quarters of `gap` by `r`, a secure random draw.
pub fn jittered_gap(gap: u64, r: u32) -> u64 {
    gap * 3 / 4 + u64::from(r) % (gap / 2 + 1)
}

/// The round schedule on a seconds clock (uptime). Unarmed until the board
/// first comes online this boot; then the first remaining round is due a
/// random [`FIRST_ROUND_MIN_SECS`]..=[`FIRST_ROUND_MAX_SECS`] later, and each
/// later one a [`jittered_gap`] after the one before.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct UpdateRounds {
    done: usize,
    due_at: Option<u64>,
}

impl UpdateRounds {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn resume(done: usize) -> Self {
        Self { done: done.min(ROUNDS), due_at: None }
    }

    pub fn armed(&self) -> bool {
        self.due_at.is_some()
    }

    /// The board is online: schedule the first remaining round.
    pub fn arm(&mut self, now: u64, r: u32) {
        if self.due_at.is_none() {
            let span = FIRST_ROUND_MAX_SECS - FIRST_ROUND_MIN_SECS + 1;
            self.due_at = Some(now + FIRST_ROUND_MIN_SECS + u64::from(r) % span);
        }
    }

    pub fn due(&self, now: u64) -> bool {
        self.done < ROUNDS && self.due_at.is_some_and(|d| now >= d)
    }

    /// A round went out at `now`, reaching the phones or not: an old relay
    /// that stays down must not keep the drift open for ever. `r` draws the
    /// next gap.
    pub fn mark_done(&mut self, now: u64, r: u32) {
        self.done = (self.done + 1).min(ROUNDS);
        self.due_at = (self.done < ROUNDS).then(|| {
            let gap = RELAY_UPDATE_ROUNDS_SECS[self.done] - RELAY_UPDATE_ROUNDS_SECS[self.done - 1];
            now + jittered_gap(gap, r)
        });
    }

    /// The round did not count (it dialled nothing): the same round is due
    /// again a first-round delay from `now`.
    pub fn retry(&mut self, now: u64, r: u32) {
        let span = FIRST_ROUND_MAX_SECS - FIRST_ROUND_MIN_SECS + 1;
        self.due_at = Some(now + FIRST_ROUND_MIN_SECS + u64::from(r) % span);
    }

    /// The last round went out but no round has reached a relay yet: it
    /// repeats after the schedule's last gap.
    pub fn repeat_last(&mut self, now: u64, r: u32) {
        self.done = ROUNDS - 1;
        let gap = RELAY_UPDATE_ROUNDS_SECS[ROUNDS - 1] - RELAY_UPDATE_ROUNDS_SECS[ROUNDS - 2];
        self.due_at = Some(now + jittered_gap(gap, r));
    }

    pub fn rounds_done(&self) -> usize {
        self.done
    }

    pub fn finished(&self) -> bool {
        self.done >= ROUNDS
    }
}

/// How a round ended.
#[derive(Debug, PartialEq, Eq)]
pub enum RoundEnd {
    /// Every relay was given up without a dial (a tight heap): the round
    /// does not count and is due again later. Nothing to record.
    NotCounted,
    /// The round counts; record `done` with [`record_round`].
    Counted { done: usize },
}

/// The relay sessions the unlocked loop has open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sessions {
    pub live: usize,
    /// One of them is the redundant secondary.
    pub secondary: bool,
    /// One of them is a pinned (client-dictated) relay.
    pub pinned: bool,
}

/// Which session closes so a dial stays within the ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepAside {
    None,
    /// The secondary; it stays closed until the round ends.
    Secondary,
    /// The pinned relay, after [`MAX_DEFER_SECS`] of waiting; it redials
    /// after its usual backoff.
    Pinned,
}

/// What the unlocked loop should do next for a relay update.
#[derive(Debug, PartialEq, Eq)]
pub enum UpdateAction {
    /// Nothing due.
    Wait,
    /// The board is online for the first time this boot: call
    /// [`UpdatePlan::arm`] with a secure random draw.
    Arm,
    /// A round is due: check the record, load the phones and call
    /// [`UpdatePlan::begin_round`].
    StartRound,
    /// Dial `url` publish-only and post this round's updates, after closing
    /// the session `step_aside` names.
    Dial { url: String, step_aside: StepAside },
    /// The primary and a pinned relay fill the session ceiling: call
    /// [`UpdatePlan::defer`] and try again later, rather than open a third
    /// TLS session.
    Defer,
    /// Every old relay of this round has been tried: call
    /// [`UpdatePlan::finish_round`] and persist with [`record_round`].
    FinishRound,
}

/// How a round began.
#[derive(Debug, PartialEq, Eq)]
pub enum RoundStart {
    Go,
    /// The last phone was revoked: nothing to tell anyone. The plan ends.
    NoPhones,
    /// The phone table or the record cannot be read: the plan ends for this
    /// boot.
    Unreadable,
    /// The record changed under the plan (a revoke or an enrolment): the plan
    /// ends.
    Superseded,
}

/// An unlocked board's relay update for one drift. RAM only; the round
/// count is persisted by the caller through [`record_round`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdatePlan {
    old: Vec<String>,
    expected: ToldRecord,
    rounds: UpdateRounds,
    queue: Option<Vec<String>>,
    round_ids: Vec<u32>,
    reached: usize,
    attempted: usize,
    reached_any: bool,
    retry_at: u64,
    waiting_since: Option<u64>,
    heap_since: Option<u64>,
    over: bool,
}

impl UpdatePlan {
    /// The plan for this boot's drift, if there is one.
    pub fn from_boot(boot: BootRelays) -> Option<Self> {
        let expected = boot.record?;
        if boot.old.is_empty() {
            return None;
        }
        let rounds = UpdateRounds::resume(boot.rounds_done);
        let over = rounds.finished();
        Some(Self {
            old: boot.old,
            expected,
            rounds,
            queue: None,
            round_ids: Vec::new(),
            reached: 0,
            attempted: 0,
            reached_any: boot.reached,
            retry_at: 0,
            waiting_since: None,
            heap_since: None,
            over,
        })
    }

    pub fn old(&self) -> &[String] {
        &self.old
    }

    /// The record every write must still find.
    pub fn expected(&self) -> &ToldRecord {
        &self.expected
    }

    pub fn rounds_done(&self) -> usize {
        self.rounds.rounds_done()
    }

    /// Phone ids this round began with.
    pub fn round_ids(&self) -> &[u32] {
        &self.round_ids
    }

    /// Old relays this round has reached so far.
    pub fn reached(&self) -> usize {
        self.reached
    }

    /// A round is under way (the secondary stays closed meanwhile).
    pub fn in_round(&self) -> bool {
        self.queue.is_some()
    }

    /// Nothing more will ever be done this boot.
    pub fn is_over(&self) -> bool {
        self.over
    }

    pub fn arm(&mut self, now: u64, r: u32) {
        self.rounds.arm(now, r);
    }

    /// End the plan (the record changed, or cannot be read).
    pub fn end(&mut self) {
        self.over = true;
        self.queue = None;
    }

    pub fn next_action(&self, now: u64, sessions: Sessions, max_sessions: usize) -> UpdateAction {
        if self.over {
            return UpdateAction::Wait;
        }
        let Some(queue) = &self.queue else {
            return if !self.rounds.armed() {
                UpdateAction::Arm
            } else if self.rounds.due(now) {
                UpdateAction::StartRound
            } else {
                UpdateAction::Wait
            };
        };
        let Some(url) = queue.last() else {
            return UpdateAction::FinishRound;
        };
        if now < self.retry_at {
            return UpdateAction::Wait;
        }
        let staying = sessions.live.saturating_sub(usize::from(sessions.secondary));
        if staying < max_sessions {
            let step_aside = if sessions.secondary { StepAside::Secondary } else { StepAside::None };
            return UpdateAction::Dial { url: url.clone(), step_aside };
        }
        let waited_out = self.waiting_since.is_some_and(|w| now >= w.saturating_add(MAX_DEFER_SECS));
        if sessions.pinned && waited_out && staying - 1 < max_sessions {
            return UpdateAction::Dial { url: url.clone(), step_aside: StepAside::Pinned };
        }
        UpdateAction::Defer
    }

    /// Begin the due round. `record_current`: [`record_is`] against
    /// [`UpdatePlan::expected`]; `phone_ids`: the enrolled phones now.
    pub fn begin_round(&mut self, record_current: Result<bool, ()>, phone_ids: Result<Vec<u32>, ()>) -> RoundStart {
        let start = match (record_current, phone_ids) {
            (Err(()), _) | (_, Err(())) => RoundStart::Unreadable,
            (Ok(false), _) => RoundStart::Superseded,
            (Ok(true), Ok(ids)) if ids.is_empty() => RoundStart::NoPhones,
            (Ok(true), Ok(ids)) => {
                self.round_ids = ids;
                self.queue = Some(self.old.iter().rev().cloned().collect());
                self.reached = 0;
                self.attempted = 0;
                self.waiting_since = None;
                self.heap_since = None;
                RoundStart::Go
            }
        };
        if start != RoundStart::Go {
            self.end();
        }
        start
    }

    /// Some round of this change has had an event accepted.
    pub fn reached_any(&self) -> bool {
        self.reached_any
    }

    /// The dial to the head of the queue happened: `true` when the relay
    /// accepted at least one event. A dead relay still counts as dialled.
    pub fn dialled(&mut self, reached: bool) {
        self.attempted += 1;
        self.reached += usize::from(reached);
        self.reached_any |= reached;
        self.next_relay();
    }

    /// Move past the head of the queue without a dial (given up for the
    /// heap, or none of the round's phones is still enrolled).
    pub fn skip(&mut self) {
        self.next_relay();
    }

    fn next_relay(&mut self) {
        if let Some(q) = self.queue.as_mut() {
            q.pop();
        }
        self.waiting_since = None;
        self.heap_since = None;
        self.retry_at = 0;
    }

    /// Put the head of the queue off for [`DEFER_SECS`] because the session
    /// ceiling is full.
    pub fn defer(&mut self, now: u64) {
        self.retry_at = now.saturating_add(DEFER_SECS);
        self.waiting_since.get_or_insert(now);
    }

    /// The heap was too tight to dial. Waits [`DEFER_SECS`] at a time, on a
    /// clock of its own (a wait for the ceiling does not count towards it);
    /// after [`MAX_DEFER_SECS`] the relay is given up for this round without
    /// counting as dialled. Returns whether it was given up.
    pub fn heap_tight(&mut self, now: u64) -> bool {
        let since = *self.heap_since.get_or_insert(now);
        if now >= since.saturating_add(MAX_DEFER_SECS) {
            self.skip();
            true
        } else {
            self.retry_at = now.saturating_add(DEFER_SECS);
            false
        }
    }

    /// Close the round; `r` draws the next delay. A round that dialled no
    /// relay does not count. The last round ends the plan only if some round
    /// of this change reached a relay; otherwise it repeats at its gap.
    pub fn finish_round(&mut self, now: u64, r: u32) -> RoundEnd {
        self.queue = None;
        self.round_ids.clear();
        if self.attempted == 0 {
            self.rounds.retry(now, r);
            return RoundEnd::NotCounted;
        }
        if self.rounds.rounds_done() + 1 >= ROUNDS && !self.reached_any {
            self.rounds.repeat_last(now, r);
            return RoundEnd::Counted { done: ROUNDS - 1 };
        }
        self.rounds.mark_done(now, r);
        if self.rounds.finished() {
            self.over = true;
        }
        RoundEnd::Counted { done: self.rounds.rounds_done() }
    }

    /// [`record_round`] wrote `record`: later writes check for it.
    pub fn recorded(&mut self, record: ToldRecord) {
        self.expected = record;
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
/// old relays: at most one dial per announce interval, in the pass straight
/// after the live relay's announcement. No human can have answered that
/// announcement yet, and the dial ends well before the next one (a dial
/// blocks for at most about 35 s: TLS 10 s, WebSocket upgrade 10 s, one
/// stalled send 8 s, the OK wait 3 s plus one 1 s read, and DNS), so a
/// delivery that arrives during it is read before the board announces again.
/// Each relay rests [`LOCKED_OLD_INTERVAL_SECS`] after a dial, and doubles
/// that per consecutive failure up to [`LOCKED_OLD_BACKOFF_MAX_SECS`].
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

    /// The old relay to dial on this pass, if any. `just_announced`: this
    /// pass put the phones' announcement on the live relay `live`, which
    /// needs no dial.
    pub fn next(&self, now: u64, just_announced: bool, live: &str) -> Option<&str> {
        if !just_announced {
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
// Sapwood status ("phones not yet told" — plan G2's Sapwood follow-up,
// third bullet: "show 'phones not yet told' once firmware reports
// relay-update drift in get_status")
// ---------------------------------------------------------------------------
//
// FIRMWARE_INFO and get_status already report `at_rest` and
// `unlock_phone_count` (see `heartwood_common::at_rest_status`) so Sapwood
// stops inferring the encryption mode. This does the same for the one
// question those two fields cannot answer: does an enrolled phone still
// listen only on relays the board has since left? `phone_relays` answers it
// with the smallest honest shape — a mode, nothing else. A rounds-remaining
// count was considered and dropped: it would tell Sapwood how far through
// six best-effort delivery rounds the board is, which is useful for
// debugging this module but not for the one decision Sapwood makes on it
// ("does anyone need a nudge"), and it would need its own damage handling
// (`n` without a trustworthy `t` is already discarded on read, see
// `a_newer_or_sparser_record_still_reads`) for a number nobody asked for.
//
// `reached` decides "pending" vs "current", not "every round sent and the
// live list recorded". [`RoundRecorded::Ended`] (all rounds run, `record_round`
// stops repeating) is the mechanism's own idea of "finished" — six rounds of
// insurance against a phone that was briefly offline — but the risk this
// field exists to flag (a phone stranded on relays nobody publishes to any
// more) is gone the moment ONE old relay has accepted a delivery: that is
// the module's own definition of "reached the phones" (see the doc comment
// at the top of this file). Reporting "pending" for the remaining insurance
// rounds would tell the owner a phone might be stuck when the worst case is
// already closed.

/// How the board's enrolled phones stand against its current relay list. The
/// wire spelling ([`PhoneRelayStatus::wire`]) is the JSON value FIRMWARE_INFO
/// and get_status carry under `phone_relays` — never a relay URL, a phone id
/// or a round count, only this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhoneRelayStatus {
    /// No phones enrolled, no live relay to compare against, or the enrolled
    /// phones already know every relay this board uses (including once some
    /// old relay has accepted an update for a change still under way).
    Current,
    /// A live relay the phones were never told about, and no old relay has
    /// yet accepted a delivery that would tell them.
    Pending,
    /// A record exists but this firmware cannot read it (damaged, oversized,
    /// or a torn read) — distinct from no record at all, which is
    /// [`PhoneRelayStatus::Current`] (a board with nothing recorded has
    /// nothing known to be wrong: see [`RelayDrift::Unrecorded`]).
    Unknown,
}

impl PhoneRelayStatus {
    /// The wire spelling used by both FIRMWARE_INFO and get_status.
    pub const fn wire(self) -> &'static str {
        match self {
            PhoneRelayStatus::Current => "current",
            PhoneRelayStatus::Pending => "pending",
            PhoneRelayStatus::Unknown => "unknown",
        }
    }
}

/// What the caller found at [`TOLD_RELAYS_KEY`], read the way `relays_at_boot`
/// reads it but without ever writing: a status query must never repair or
/// settle a record, only report what is there. Firmware builds this from a
/// shared `&EspNvs` read (`blob_len` then `get_blob`, sized to the blob's own
/// length) rather than a [`BlobStore`], because the low-heap get_status
/// fallback runs behind a shared reference it can never promote to a mutable
/// one — the same reason `at_rest_status::resolve` reads its blobs directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordRead<'a> {
    /// The key is not present at all.
    Absent,
    /// The key is present but could not be read back intact (oversized,
    /// `blob_len` failed, or a short/torn read).
    Unreadable,
    /// Read back in full; may still fail to decode as a [`ToldRecord`].
    Present(&'a [u8]),
}

/// Classify the drift for Sapwood, purely from what is already known: whether
/// any phone is enrolled, the board's current relay list, and what
/// [`TOLD_RELAYS_KEY`] holds. Never writes. `have_phones` and an empty
/// `current` short-circuit to [`PhoneRelayStatus::Current`] before the record
/// is even inspected — exactly [`relays_at_boot`]'s own guard — so a damaged
/// record on a board with no phones, or no configured relay, is never
/// reported as a problem nobody can act on.
pub fn relay_status(have_phones: bool, current: &[String], record: RecordRead<'_>) -> PhoneRelayStatus {
    if !have_phones || usable_relays(current).is_empty() {
        return PhoneRelayStatus::Current;
    }
    let bytes = match record {
        RecordRead::Absent => return PhoneRelayStatus::Current,
        RecordRead::Unreadable => return PhoneRelayStatus::Unknown,
        RecordRead::Present(bytes) => bytes,
    };
    let Some(told) = ToldRecord::decode(bytes) else {
        return PhoneRelayStatus::Unknown;
    };
    match relay_drift(Some(&told.relays), current) {
        RelayDrift::Drifted { .. } if !told.reached => PhoneRelayStatus::Pending,
        _ => PhoneRelayStatus::Current,
    }
}

// ---------------------------------------------------------------------------
// Relay OK frames
// ---------------------------------------------------------------------------

/// Counts a relay's `["OK", <id>, <accepted>, <message>]` answers to the
/// events a publish-only connection sent, one [`OkTally::expect`] per event.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OkTally {
    waiting: Vec<String>,
    accepted: usize,
}

impl OkTally {
    pub fn new() -> Self {
        Self::default()
    }

    /// An event with this id was sent.
    pub fn expect(&mut self, id: String) {
        self.waiting.push(id);
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
        fn with(relays: &[String]) -> Self {
            let mut s = Store::default();
            s.map.insert(TOLD_RELAYS_KEY.into(), ToldRecord::settled(relays).encode());
            s
        }
    }

    fn drifted(old: &[String], rounds_done: usize, record: ToldRecord) -> BootRelays {
        BootRelays { old: old.to_vec(), rounds_done, reached: false, record: Some(record), unreadable: false }
    }

    const ONE: Sessions = Sessions { live: 1, secondary: false, pinned: false };

    /// Run a plan's round to the end with every dial reaching its relay.
    fn run_round(plan: &mut UpdatePlan, store: &Store, ids: &[u32], now: u64) {
        assert_eq!(plan.begin_round(record_is(store, plan.expected()).map_err(|_| ()), Ok(ids.to_vec())), RoundStart::Go);
        while let UpdateAction::Dial { .. } = plan.next_action(now, ONE, 2) {
            plan.dialled(true);
        }
        assert_eq!(plan.next_action(now, ONE, 2), UpdateAction::FinishRound);
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
        let mut store = Store::default();
        assert_eq!(
            relays_at_boot(&mut store, true, false, &urls(&["wss://q\"uote"])),
            Ok(BootRelays::default())
        );
        assert_eq!((store.reads.get(), store.writes), (0, 0));
    }

    #[test]
    fn the_record_round_trips_and_refuses_what_it_cannot_use() {
        let rec = ToldRecord {
            relays: urls(&[" wss://a.example ", "", "wss://A.example/", "wss://q\"uote", "wss://b.example"]),
            rounds: 3,
            toward: set_tag(&urls(&["wss://c.example"])),
            reached: true,
        };
        let back = ToldRecord::decode(&rec.encode()).unwrap();
        assert_eq!(back.relays, urls(&["wss://a.example", "wss://b.example"]));
        assert_eq!((back.rounds, back.toward.len(), back.reached), (3, 16, true));

        let many: Vec<String> = (0..12).map(|i| format!("wss://r{i}.example")).collect();
        assert_eq!(ToldRecord::decode(&ToldRecord::settled(&many).encode()).unwrap().relays.len(), MAX_TOLD_RELAYS);

        let longest: Vec<String> =
            (0..8).map(|i| format!("wss://{i}{}", "x".repeat(MAX_TOLD_URL_LEN - 7))).collect();
        let full = ToldRecord { relays: longest.clone(), rounds: ROUNDS - 1, toward: set_tag(&longest), reached: false };
        assert_eq!(full.encode().len(), MAX_TOLD_BLOB_LEN, "the bound is exact");
        assert!(MAX_TOLD_BLOB_LEN <= MAX_TOLD_READ_LEN);

        let tag = set_tag(&urls(&["wss://a"]));
        for bad in [
            String::from("not json"),
            String::from("[\"wss://a\"]"),
            format!(r#"{{"r":[],"n":0,"t":"{tag}"}}"#),
            format!(r#"{{"r":[" wss://a"],"n":0,"t":"{tag}"}}"#),
            format!(r#"{{"r":["wss://a"],"n":6,"t":"{tag}"}}"#),
            String::from(r#"{"r":["wss://a"],"n":0,"t":"XYZ"}"#),
            format!(r#"{{"n":0,"t":"{tag}"}}"#),
        ] {
            assert_eq!(ToldRecord::decode(bad.as_bytes()), None, "{bad}");
        }
    }

    #[test]
    fn a_newer_or_sparser_record_still_reads() {
        let tag = set_tag(&urls(&["wss://c"]));
        let newer = format!(r#"{{"r":["wss://a"],"n":2,"t":"{tag}","v":2,"extra":{{"x":1}}}}"#);
        assert_eq!(
            ToldRecord::decode(newer.as_bytes()),
            Some(ToldRecord { relays: urls(&["wss://a"]), rounds: 2, toward: tag.clone(), reached: false }),
            "unknown fields are ignored"
        );
        assert_eq!(
            ToldRecord::decode(br#"{"r":["wss://a"]}"#),
            Some(ToldRecord { relays: urls(&["wss://a"]), rounds: 0, toward: String::new(), reached: false }),
            "n, t and a default"
        );
        // Without a tag the count cannot be trusted for this change.
        let mut store = Store::default();
        store.map.insert(TOLD_RELAYS_KEY.into(), br#"{"r":["wss://a"],"n":4}"#.to_vec());
        assert_eq!(relays_at_boot(&mut store, true, false, &urls(&["wss://c"])).unwrap().rounds_done, 0);
    }

    #[test]
    fn an_unreadable_record_is_left_untouched() {
        let c = urls(&["wss://c.example"]);
        for junk in [&b"\xff\xfe"[..], br#"{"r":"not a list"}"#, br#"{"r":["wss://a"],"n":9}"#] {
            let mut store = Store::default();
            store.map.insert(TOLD_RELAYS_KEY.into(), junk.to_vec());
            let boot = relays_at_boot(&mut store, true, false, &c).unwrap();
            assert!(boot.unreadable && boot.old.is_empty() && boot.record.is_none());
            assert_eq!(store.writes, 0);
            assert_eq!(store.map[TOLD_RELAYS_KEY], junk.to_vec());
            assert_eq!(UpdatePlan::from_boot(boot), None);
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

        let mut store = Store::default();
        assert_eq!(relays_at_boot(&mut store, false, false, &a), Ok(BootRelays::default()));
        assert_eq!(relays_at_boot(&mut store, true, false, &[]), Ok(BootRelays::default()));
        assert_eq!((store.reads.get(), store.writes), (0, 0));

        assert_eq!(relays_at_boot(&mut store, true, false, &ab), Ok(BootRelays::default()));
        assert_eq!((store.told(), store.writes), (Some(ab.clone()), 1));
        assert_eq!(relays_at_boot(&mut store, true, false, &ab), Ok(BootRelays::default()));
        assert_eq!(store.writes, 1, "a board in step never writes");

        for _ in 0..3 {
            assert_eq!(
                relays_at_boot(&mut store, true, false, &c),
                Ok(drifted(&ab, 0, ToldRecord::settled(&ab)))
            );
        }
        assert_eq!(store.writes, 1);

        let mut store = Store::with(&ab);
        assert_eq!(relays_at_boot(&mut store, true, false, &a), Ok(BootRelays::default()));
        assert_eq!((store.told(), store.writes), (Some(a.clone()), 1));

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
        let mut store = Store::with(&ab);
        assert_eq!(relays_at_boot(&mut store, true, true, &a), Ok(BootRelays::default()));
        assert_eq!(store.writes, 0, "shrunk: left as it is");
        assert_eq!(
            relays_at_boot(&mut store, true, true, &c),
            Ok(drifted(&ab, 0, ToldRecord::settled(&ab))),
            "a drift is still told (a phone may need to unlock the trial boot)"
        );
    }

    #[test]
    fn rounds_persist_resume_and_end_the_drift_in_six_writes() {
        let ab = urls(&["wss://a.example", "wss://b.example"]);
        let c = urls(&["wss://c.example"]);
        let mut store = Store::with(&ab);
        let before = store.writes;

        // Each boot sends one round and restarts: the record carries the
        // count, so the board converges instead of starting over.
        for round in 1..=ROUNDS {
            let boot = relays_at_boot(&mut store, true, false, &c).unwrap();
            assert_eq!((boot.old.clone(), boot.rounds_done), (ab.clone(), round - 1));
            let mut plan = UpdatePlan::from_boot(boot).unwrap();
            assert_eq!(plan.next_action(0, ONE, 2), UpdateAction::Arm);
            plan.arm(0, 0);
            assert_eq!(plan.next_action(FIRST_ROUND_MIN_SECS - 1, ONE, 2), UpdateAction::Wait);
            assert_eq!(plan.next_action(FIRST_ROUND_MIN_SECS, ONE, 2), UpdateAction::StartRound);
            run_round(&mut plan, &store, &[7], FIRST_ROUND_MIN_SECS);
            let RoundEnd::Counted { done } = plan.finish_round(FIRST_ROUND_MIN_SECS, 0) else {
                panic!("a dialled round counts");
            };
            assert_eq!(done, round);
            match record_round(&mut store, plan.expected(), &c, done, plan.reached_any()).unwrap() {
                RoundRecorded::Progress(r) => {
                    assert!(round < ROUNDS);
                    plan.recorded(r);
                }
                RoundRecorded::Ended => assert_eq!(round, ROUNDS),
                RoundRecorded::Superseded => panic!("nothing changed the record"),
            }
            assert_eq!(plan.is_over(), round == ROUNDS);
        }
        assert_eq!(store.writes - before, ROUNDS, "one write per round, the last ends the drift");
        assert_eq!(store.told(), Some(c.clone()));
        assert_eq!(relays_at_boot(&mut store, true, false, &c), Ok(BootRelays::default()));
    }

    #[test]
    fn rounds_in_one_boot_follow_the_recorded_record() {
        let a = urls(&["wss://a.example"]);
        let c = urls(&["wss://c.example"]);
        let mut store = Store::with(&a);
        let mut plan = UpdatePlan::from_boot(relays_at_boot(&mut store, true, false, &c).unwrap()).unwrap();
        plan.arm(0, 0);
        let mut now = FIRST_ROUND_MIN_SECS;
        for round in 1..=ROUNDS {
            assert_eq!(plan.next_action(now, ONE, 2), UpdateAction::StartRound, "round {round}");
            run_round(&mut plan, &store, &[7], now);
            let RoundEnd::Counted { done } = plan.finish_round(now, 0) else {
                panic!("a dialled round counts");
            };
            match record_round(&mut store, plan.expected(), &c, done, plan.reached_any()).unwrap() {
                RoundRecorded::Progress(r) => plan.recorded(r),
                RoundRecorded::Ended => {}
                RoundRecorded::Superseded => panic!("round {round} superseded by its own write"),
            }
            now += 200_000;
        }
        assert!(plan.is_over());
        assert_eq!(store.told(), Some(c));
    }

    #[test]
    fn revoking_every_phone_then_enrolling_mid_plan_ends_the_plan() {
        let a = urls(&["wss://a.example"]);
        let c = urls(&["wss://c.example"]);
        let mut store = Store::with(&a);
        let mut plan = UpdatePlan::from_boot(relays_at_boot(&mut store, true, false, &c).unwrap()).unwrap();
        plan.arm(0, 0);
        run_round(&mut plan, &store, &[7], FIRST_ROUND_MIN_SECS);
        let RoundEnd::Counted { done } = plan.finish_round(FIRST_ROUND_MIN_SECS, 0) else {
            panic!("a dialled round counts");
        };
        let RoundRecorded::Progress(r) = record_round(&mut store, plan.expected(), &c, done, true).unwrap() else {
            panic!("first round records");
        };
        plan.recorded(r);

        // Mid-plan: the last phone is revoked (forget_told), then a new one
        // is enrolled on c (the only phone, so the record is replaced).
        forget_told(&mut store).unwrap();
        record_told_at_enrolment(&mut store, false, &c).unwrap();
        let fresh = store.record().unwrap();
        assert_eq!(fresh, ToldRecord::settled(&c));

        // The next round never starts, and a late record_round writes nothing.
        let writes = store.writes;
        assert_eq!(
            plan.begin_round(record_is(&store, plan.expected()).map_err(|_| ()), Ok(alloc::vec![9])),
            RoundStart::Superseded
        );
        assert!(plan.is_over());
        assert_eq!(record_round(&mut store, plan.expected(), &c, 2, true), Ok(RoundRecorded::Superseded));
        assert_eq!(store.writes, writes);
        assert_eq!(store.record(), Some(fresh), "the fresh record survives");
    }

    #[test]
    fn a_second_change_mid_update_starts_the_rounds_again() {
        let a = urls(&["wss://a.example"]);
        let c = urls(&["wss://c.example"]);
        let d = urls(&["wss://d.example"]);
        let mut store = Store::with(&a);
        let expected = ToldRecord::settled(&a);
        let RoundRecorded::Progress(_) = record_round(&mut store, &expected, &c, 4, true).unwrap() else {
            panic!("progress");
        };
        assert_eq!(relays_at_boot(&mut store, true, false, &c).unwrap().rounds_done, 4);
        let boot = relays_at_boot(&mut store, true, false, &d).unwrap();
        assert_eq!((boot.old, boot.rounds_done), (a.clone(), 0), "the phones on a know nothing of d");
    }

    #[test]
    fn a_failed_final_write_repeats_the_last_round_next_boot() {
        let a = urls(&["wss://a.example"]);
        let c = urls(&["wss://c.example"]);
        let mut store = Store::with(&a);
        let RoundRecorded::Progress(r) = record_round(&mut store, &ToldRecord::settled(&a), &c, ROUNDS - 1, true).unwrap()
        else {
            panic!("progress");
        };
        store.broken = true;
        assert_eq!(record_round(&mut store, &r, &c, ROUNDS, true), Err(StoreError));
        store.broken = false;
        let boot = relays_at_boot(&mut store, true, false, &c).unwrap();
        assert_eq!((boot.old, boot.rounds_done), (a, ROUNDS - 1));
    }

    #[test]
    fn enrolment_after_every_phone_left_replaces_a_stale_record() {
        let a = urls(&["wss://a.example"]);
        let c = urls(&["wss://c.example"]);
        let mut store = Store::with(&a);
        record_told_at_enrolment(&mut store, false, &c).unwrap();
        assert_eq!(store.told(), Some(c.clone()), "the only phone knows c; nobody listens on a");
        assert_eq!(relays_at_boot(&mut store, true, false, &c), Ok(BootRelays::default()));

        let mut store = Store::with(&a);
        record_told_at_enrolment(&mut store, true, &c).unwrap();
        assert_eq!(store.told(), Some(a.clone()), "other phones are still owed an update");
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
    fn a_dial_addresses_only_the_rounds_phones_still_enrolled() {
        let dk = [0xD0u8; 32];
        let mut table = PhoneSet::default();
        for id in [1u32, 2, 3] {
            table.enrol(id, "p", &[id as u8; 32], &dk, &[0u8; 12]).unwrap();
        }
        let round = [1u32, 2];
        let ids: Vec<u32> = round_phones(&round, &table).map(|r| r.id).collect();
        assert_eq!(ids, [1, 2], "3 enrolled mid-round is not added");
        table.revoke(2).unwrap();
        let ids: Vec<u32> = round_phones(&round, &table).map(|r| r.id).collect();
        assert_eq!(ids, [1], "2 revoked mid-round gets nothing from the next dial");
        table.revoke(1).unwrap();
        assert_eq!(round_phones(&round, &table).count(), 0);
    }

    #[test]
    fn the_schedule_is_armed_late_and_jittered() {
        let mut r = UpdateRounds::new();
        assert!(!r.armed() && !r.due(u64::MAX), "nothing before the board is online");
        r.arm(1_000, u32::MAX);
        assert!(r.armed());
        let first = 1_000 + FIRST_ROUND_MIN_SECS + u64::from(u32::MAX) % (FIRST_ROUND_MAX_SECS - FIRST_ROUND_MIN_SECS + 1);
        assert!(!r.due(first - 1) && r.due(first));
        r.arm(5_000, 0);
        assert!(!r.due(first - 1), "arming twice changes nothing");

        // Bounds of the first delay and of every gap.
        for draw in [0u32, 1, 7, 1_000, 65_535, u32::MAX] {
            let mut x = UpdateRounds::new();
            x.arm(0, draw);
            let d = (0..).find(|t| x.due(*t)).unwrap();
            assert!((FIRST_ROUND_MIN_SECS..=FIRST_ROUND_MAX_SECS).contains(&d), "first {d}");
            for i in 1..ROUNDS {
                let gap = RELAY_UPDATE_ROUNDS_SECS[i] - RELAY_UPDATE_ROUNDS_SECS[i - 1];
                let j = jittered_gap(gap, draw);
                assert!(j >= gap * 3 / 4 && j <= gap * 5 / 4, "gap {i}: {j} for {gap}");
            }
        }
        assert_ne!(jittered_gap(3_600, 1), jittered_gap(3_600, 2), "the draw moves it");

        let mut last = first;
        for i in 1..ROUNDS {
            assert_eq!(r.rounds_done(), i - 1);
            r.mark_done(last, 42);
            let gap = RELAY_UPDATE_ROUNDS_SECS[i] - RELAY_UPDATE_ROUNDS_SECS[i - 1];
            let next = last + jittered_gap(gap, 42);
            assert!(!r.due(next - 1) && r.due(next), "round {}", i + 1);
            last = next;
        }
        r.mark_done(last, 42);
        assert!(r.finished() && !r.due(u64::MAX));

        let mut resumed = UpdateRounds::resume(3);
        assert!(!resumed.due(0), "a resumed schedule waits to be armed too");
        resumed.arm(0, 0);
        assert!(resumed.due(FIRST_ROUND_MIN_SECS));
        assert!(!UpdateRounds::resume(ROUNDS).due(u64::MAX));
    }

    #[test]
    fn the_plan_never_breaks_the_session_ceiling_and_still_converges() {
        let old = urls(&["wss://a.example", "wss://b.example"]);
        let store = Store::with(&old);
        let mut plan = UpdatePlan::from_boot(drifted(&old, 0, ToldRecord::settled(&old))).unwrap();
        plan.arm(0, 0);
        let t = FIRST_ROUND_MIN_SECS;
        assert!(!plan.in_round());
        run_round_start(&mut plan, &store, t);
        assert!(plan.in_round());

        let primary = Sessions { live: 1, secondary: false, pinned: false };
        let with_secondary = Sessions { live: 2, secondary: true, pinned: false };
        let with_pinned = Sessions { live: 2, secondary: false, pinned: true };
        assert_eq!(plan.next_action(t, primary, 2), UpdateAction::Dial { url: old[0].clone(), step_aside: StepAside::None });
        assert_eq!(
            plan.next_action(t, with_secondary, 2),
            UpdateAction::Dial { url: old[0].clone(), step_aside: StepAside::Secondary }
        );

        // Primary plus pinned: defer, then after MAX_DEFER_SECS the pinned
        // session steps aside for one dial. Never a third session.
        assert_eq!(plan.next_action(t, with_pinned, 2), UpdateAction::Defer);
        plan.defer(t);
        assert_eq!(plan.next_action(t + DEFER_SECS - 1, with_pinned, 2), UpdateAction::Wait);
        assert_eq!(plan.next_action(t + DEFER_SECS, with_pinned, 2), UpdateAction::Defer);
        plan.defer(t + DEFER_SECS);
        let late = t + MAX_DEFER_SECS;
        assert_eq!(
            plan.next_action(late, with_pinned, 2),
            UpdateAction::Dial { url: old[0].clone(), step_aside: StepAside::Pinned }
        );
        plan.dialled(true);
        // The pinned relay is back: the wait starts afresh for the next relay.
        assert_eq!(plan.next_action(late, with_pinned, 2), UpdateAction::Defer);
        assert_eq!(plan.next_action(late, primary, 2), UpdateAction::Dial { url: old[1].clone(), step_aside: StepAside::None });

        // A tight heap waits on a clock of its own, then gives the relay up
        // without counting it as dialled.
        assert!(!plan.heap_tight(late));
        assert_eq!(plan.next_action(late + 1, primary, 2), UpdateAction::Wait);
        assert!(!plan.heap_tight(late + DEFER_SECS));
        assert!(plan.heap_tight(late + MAX_DEFER_SECS));
        assert_eq!(plan.reached(), 1);
        assert_eq!(plan.next_action(late + MAX_DEFER_SECS, primary, 2), UpdateAction::FinishRound);
        assert_eq!(
            plan.finish_round(late + MAX_DEFER_SECS, 0),
            RoundEnd::Counted { done: 1 },
            "one relay was dialled, so the round counts"
        );
        assert!(!plan.in_round());

        // A round whose every relay is given up for the heap, with no dial,
        // does not count: the drift stays open and the round comes back.
        let t2 = late + MAX_DEFER_SECS + 200_000;
        run_round_start(&mut plan, &store, t2);
        for _ in 0..old.len() {
            assert!(!plan.heap_tight(t2));
            assert!(plan.heap_tight(t2 + MAX_DEFER_SECS));
        }
        assert_eq!(plan.finish_round(t2 + MAX_DEFER_SECS, 0), RoundEnd::NotCounted);
        assert_eq!(plan.rounds_done(), 1);
        assert!(!plan.is_over());
        let back = t2 + MAX_DEFER_SECS;
        assert_eq!(plan.next_action(back + FIRST_ROUND_MIN_SECS - 1, primary, 2), UpdateAction::Wait);
        assert_eq!(plan.next_action(back + FIRST_ROUND_MIN_SECS, primary, 2), UpdateAction::StartRound);
    }

    #[test]
    fn a_heap_wait_after_the_pinned_steps_aside_starts_its_own_clock() {
        let old = urls(&["wss://a.example"]);
        let store = Store::with(&old);
        let mut plan = UpdatePlan::from_boot(drifted(&old, 0, ToldRecord::settled(&old))).unwrap();
        plan.arm(0, 0);
        let t = FIRST_ROUND_MIN_SECS;
        run_round_start(&mut plan, &store, t);
        let with_pinned = Sessions { live: 2, secondary: false, pinned: true };
        plan.defer(t);
        let late = t + MAX_DEFER_SECS;
        assert!(matches!(plan.next_action(late, with_pinned, 2), UpdateAction::Dial { step_aside: StepAside::Pinned, .. }));
        // The pinned relay closed, and then the heap was too tight to dial:
        // the ten minutes spent waiting for the ceiling do not count.
        assert!(!plan.heap_tight(late), "not given up at once");
        assert!(!plan.heap_tight(late + MAX_DEFER_SECS - 1));
        assert!(plan.heap_tight(late + MAX_DEFER_SECS));
    }

    #[test]
    fn a_drift_stays_open_until_some_round_reaches_a_relay() {
        let a = urls(&["wss://a.example"]);
        let c = urls(&["wss://c.example"]);
        let mut store = Store::with(&a);
        let mut plan = UpdatePlan::from_boot(relays_at_boot(&mut store, true, false, &c).unwrap()).unwrap();
        plan.arm(0, 0);
        let mut now = FIRST_ROUND_MIN_SECS;
        let mut writes = Vec::new();
        // Seven rounds, every dial reaching a dead relay.
        for _ in 0..ROUNDS + 1 {
            assert_eq!(plan.next_action(now, ONE, 2), UpdateAction::StartRound);
            assert_eq!(plan.begin_round(Ok(true), Ok(alloc::vec![7])), RoundStart::Go);
            plan.dialled(false);
            let RoundEnd::Counted { done } = plan.finish_round(now, 0) else {
                panic!("a dead relay was dialled; the round counts");
            };
            let before = store.writes;
            match record_round(&mut store, plan.expected(), &c, done, plan.reached_any()).unwrap() {
                RoundRecorded::Progress(r) => plan.recorded(r),
                other => panic!("the drift must stay open, got {other:?}"),
            }
            writes.push(store.writes - before);
            now += 200_000;
        }
        assert!(!plan.is_over());
        assert_eq!(plan.rounds_done(), ROUNDS - 1);
        assert_eq!(writes, [1, 1, 1, 1, 1, 0, 0], "the repeated last round writes nothing new");
        let boot = relays_at_boot(&mut store, true, false, &c).unwrap();
        assert_eq!((boot.rounds_done, boot.reached), (ROUNDS - 1, false));

        // One reached relay ends it.
        assert_eq!(plan.next_action(now, ONE, 2), UpdateAction::StartRound);
        assert_eq!(plan.begin_round(Ok(true), Ok(alloc::vec![7])), RoundStart::Go);
        plan.dialled(true);
        let RoundEnd::Counted { done } = plan.finish_round(now, 0) else { panic!() };
        assert_eq!(done, ROUNDS);
        assert_eq!(record_round(&mut store, plan.expected(), &c, done, plan.reached_any()), Ok(RoundRecorded::Ended));
        assert!(plan.is_over());
        // And record_round refuses to end an unreached drift on its own.
        let mut store = Store::with(&a);
        let r = ToldRecord::settled(&a);
        assert!(matches!(record_round(&mut store, &r, &c, ROUNDS, false), Ok(RoundRecorded::Progress(_))));
        assert_eq!(store.told(), Some(a));
    }

    #[test]
    fn a_reach_in_an_earlier_boot_counts_towards_the_end() {
        let a = urls(&["wss://a.example"]);
        let c = urls(&["wss://c.example"]);
        let mut store = Store::with(&a);
        for round in 1..=ROUNDS {
            let boot = relays_at_boot(&mut store, true, false, &c).unwrap();
            assert_eq!(boot.reached, round > 1);
            let mut plan = UpdatePlan::from_boot(boot).unwrap();
            plan.arm(0, 0);
            assert_eq!(plan.next_action(FIRST_ROUND_MIN_SECS, ONE, 2), UpdateAction::StartRound);
            assert_eq!(plan.begin_round(Ok(true), Ok(alloc::vec![7])), RoundStart::Go);
            plan.dialled(round == 1);
            let RoundEnd::Counted { done } = plan.finish_round(FIRST_ROUND_MIN_SECS, 0) else { panic!() };
            let got = record_round(&mut store, plan.expected(), &c, done, plan.reached_any()).unwrap();
            assert_eq!(matches!(got, RoundRecorded::Ended), round == ROUNDS);
        }
        assert_eq!(store.told(), Some(c));
    }

    #[test]
    fn the_pinned_steps_aside_only_when_quiet() {
        assert!(!pinned_may_step_aside(false, 60), "a buffered frame waits");
        assert!(!pinned_may_step_aside(true, PINNED_QUIET_SECS - 1), "something just arrived");
        assert!(pinned_may_step_aside(true, PINNED_QUIET_SECS));
    }

    fn run_round_start(plan: &mut UpdatePlan, store: &Store, now: u64) {
        assert_eq!(plan.next_action(now, ONE, 2), UpdateAction::StartRound);
        assert_eq!(plan.begin_round(record_is(store, plan.expected()).map_err(|_| ()), Ok(alloc::vec![1])), RoundStart::Go);
        assert_eq!(plan.round_ids(), &[1]);
    }

    #[test]
    fn the_plan_ends_with_no_phones_an_unreadable_table_or_record() {
        let old = urls(&["wss://a.example"]);
        let boot = || drifted(&old, 0, ToldRecord::settled(&old));
        let mut plan = UpdatePlan::from_boot(boot()).unwrap();
        assert_eq!(plan.begin_round(Ok(true), Ok(Vec::new())), RoundStart::NoPhones);
        assert!(plan.is_over());
        assert_eq!(plan.next_action(u64::MAX, ONE, 2), UpdateAction::Wait);
        let mut plan = UpdatePlan::from_boot(boot()).unwrap();
        assert_eq!(plan.begin_round(Ok(true), Err(())), RoundStart::Unreadable);
        assert!(plan.is_over());
        let mut plan = UpdatePlan::from_boot(boot()).unwrap();
        assert_eq!(plan.begin_round(Err(()), Ok(alloc::vec![1])), RoundStart::Unreadable);
        assert!(plan.is_over());
        assert_eq!(UpdatePlan::from_boot(BootRelays::default()), None);
        assert!(UpdatePlan::from_boot(drifted(&old, ROUNDS, ToldRecord::settled(&old))).unwrap().is_over());
    }

    #[test]
    fn locked_dials_follow_the_announcement_one_per_interval() {
        let old = urls(&["wss://a.example", "wss://live.example", "wss://b.example"]);
        let mut d = OldRelayDials::new(&old);
        let live = "wss://LIVE.example/";
        assert_eq!(d.next(100, false, live), None, "only in the pass that announced");
        assert_eq!(d.next(100, true, live), Some("wss://a.example"));
        d.report("wss://a.example", true, 100);
        assert_eq!(d.next(160, true, live), Some("wss://b.example"), "the live relay is never dialled");
        d.report("wss://b.example", true, 160);
        assert_eq!(d.next(220, true, live), None, "each relay rests an interval");
        assert_eq!(d.next(100 + LOCKED_OLD_INTERVAL_SECS, true, live), Some("wss://a.example"));
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
        let mut t = OkTally::new();
        assert!(t.done());
        for id in ["e1", "e2", "e3"] {
            t.expect(id.into());
        }
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

    // -----------------------------------------------------------------
    // relay_status (Sapwood's "phones not yet told")
    // -----------------------------------------------------------------

    #[test]
    fn no_phones_is_current_whatever_the_record_says() {
        let current = urls(&["wss://c.example"]);
        assert_eq!(relay_status(false, &current, RecordRead::Absent), PhoneRelayStatus::Current);
        assert_eq!(relay_status(false, &current, RecordRead::Unreadable), PhoneRelayStatus::Current);
        let junk = b"not json";
        assert_eq!(relay_status(false, &current, RecordRead::Present(junk)), PhoneRelayStatus::Current);
        let drifted = ToldRecord { relays: urls(&["wss://a.example"]), rounds: 0, toward: String::new(), reached: false };
        let bytes = drifted.encode();
        assert_eq!(relay_status(false, &current, RecordRead::Present(&bytes)), PhoneRelayStatus::Current);
    }

    #[test]
    fn no_live_relay_is_current_whatever_the_record_says() {
        let drifted = ToldRecord { relays: urls(&["wss://a.example"]), rounds: 0, toward: String::new(), reached: false };
        let bytes = drifted.encode();
        assert_eq!(relay_status(true, &[], RecordRead::Present(&bytes)), PhoneRelayStatus::Current);
        assert_eq!(relay_status(true, &urls(&["wss://q\"uote"]), RecordRead::Present(&bytes)), PhoneRelayStatus::Current);
    }

    #[test]
    fn no_record_at_all_is_current_not_pending() {
        // A board whose phones were enrolled before this record existed, or
        // one that has never changed relays: nothing is known to be wrong
        // (RelayDrift::Unrecorded). The boot check settles a baseline; a
        // status read never should.
        let current = urls(&["wss://c.example"]);
        assert_eq!(relay_status(true, &current, RecordRead::Absent), PhoneRelayStatus::Current);
    }

    #[test]
    fn an_unreadable_record_is_unknown() {
        let current = urls(&["wss://c.example"]);
        assert_eq!(relay_status(true, &current, RecordRead::Unreadable), PhoneRelayStatus::Unknown);
    }

    #[test]
    fn a_present_but_undecodable_record_is_unknown() {
        let current = urls(&["wss://c.example"]);
        for junk in [&b"not json"[..], br#"{"r":"not a list"}"#, br#"{"r":["wss://a"],"n":9}"#] {
            assert_eq!(relay_status(true, &current, RecordRead::Present(junk)), PhoneRelayStatus::Unknown, "{junk:?}");
        }
    }

    #[test]
    fn in_step_or_shrunk_is_current() {
        let told = ToldRecord::settled(&urls(&["wss://a.example", "wss://b.example"]));
        let bytes = told.encode();
        // In step: the live list is exactly what was recorded.
        assert_eq!(
            relay_status(true, &urls(&["wss://a.example", "wss://b.example"]), RecordRead::Present(&bytes)),
            PhoneRelayStatus::Current
        );
        // Shrunk: the board dropped a relay the phones still know about.
        assert_eq!(
            relay_status(true, &urls(&["wss://a.example"]), RecordRead::Present(&bytes)),
            PhoneRelayStatus::Current
        );
    }

    #[test]
    fn a_fresh_drift_with_nothing_accepted_is_pending() {
        let told = ToldRecord { relays: urls(&["wss://a.example"]), rounds: 2, toward: String::new(), reached: false };
        let bytes = told.encode();
        assert_eq!(
            relay_status(true, &urls(&["wss://a.example", "wss://c.example"]), RecordRead::Present(&bytes)),
            PhoneRelayStatus::Pending
        );
    }

    #[test]
    fn a_drift_once_any_old_relay_has_accepted_is_current_even_mid_update() {
        // Rounds still short of ROUNDS, but the module's own definition of
        // "reached the phones" (see the file doc comment) is already met:
        // the remaining rounds are insurance, not the risk this field flags.
        let told = ToldRecord { relays: urls(&["wss://a.example"]), rounds: 1, toward: String::new(), reached: true };
        let bytes = told.encode();
        assert_eq!(
            relay_status(true, &urls(&["wss://a.example", "wss://c.example"]), RecordRead::Present(&bytes)),
            PhoneRelayStatus::Current
        );
    }

    #[test]
    fn wire_spellings_match_the_plan() {
        assert_eq!(PhoneRelayStatus::Current.wire(), "current");
        assert_eq!(PhoneRelayStatus::Pending.wire(), "pending");
        assert_eq!(PhoneRelayStatus::Unknown.wire(), "unknown");
    }

    #[test]
    fn phone_relays_is_never_a_delegate_key() {
        // A per-identity delegate never sees device-wide at-rest state
        // (DELEGATE_STATUS_KEYS/DELEGATE_STATUS_FALLBACK_KEYS already exclude
        // `at_rest` and `unlock_phone_count`); `phone_relays` is the same
        // kind of device-wide fact and must stay off both lists too.
        assert!(!crate::at_rest_status::DELEGATE_STATUS_KEYS.contains(&"phone_relays"));
        assert!(!crate::at_rest_status::DELEGATE_STATUS_FALLBACK_KEYS.contains(&"phone_relays"));
        assert!(!crate::at_rest_status::DELEGATE_STATUS_KEYS.contains(&"at_rest"));
        assert!(!crate::at_rest_status::DELEGATE_STATUS_FALLBACK_KEYS.contains(&"at_rest"));
    }
}
