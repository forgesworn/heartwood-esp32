//! The note-locker wire commands — lnurl-vault's JSON protocol over a
//! [`crate::note_store::NoteStore`].
//!
//! One JSON command object in, one JSON response object out, exactly the
//! contract lnurl-wallet's `device.ts` client speaks: every response carries
//! a boolean `ok`, failures carry `error` (a fixed code) and optionally a
//! human-readable `message`. This module is transport-blind — the firmware
//! wraps each message in a `FRAME_TYPE_NOTE_CMD`/`NOTE_RESP` serial frame,
//! and a future relay path carries the same objects inside
//! `heartwood_note_*` NIP-46 extensions.
//!
//! Physical gating is injected. The dispatcher below asks the hook before
//! any gated command touches the store, handing it the command kind and the
//! note's metadata so the screen can show what is actually being decided.
//! Which kinds gate is the firmware's policy; the vault gates disclosure
//! (`export_secret`) and the destructive commands (`mark_spent`, `discard`,
//! `rename`, `delete`) — the latter because a host marking a CONFIRMED note
//! spent locks its value forever, which is why "destructive" includes
//! commands that delete nothing.
//!
//! One exception, and only one: a `mark_spent` may ride the `export_secret`
//! hold that just released the SAME note to the SAME client, once, inside a
//! short window ([`SpendGrant`], #129). A collect is those two commands back
//! to back, and by the time the second runs the mint has already burned the
//! note, so the second card bought a press and nothing else.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde_json::{json, Map, Value};
use zeroize::Zeroize;

use crate::hex::{hex_decode, hex_encode};
use crate::note_store::{NoteError, NoteMeta, NoteState, NoteStorage, NoteStore, Peer, SECRET_LEN};
use crate::trust::TrustList;

/// Which command is asking for physical approval, so the OLED can name the
/// action rather than showing a generic prompt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatedCmd {
    ExportSecret,
    MarkSpent,
    Discard,
    Rename,
    Delete,
    /// Seal the secret to another pubkey on-device (note_wrap.rs). A
    /// disclosure, like export, but the host never sees the plaintext.
    Send,
    /// Add a sender whose wraps are stored without a hold (trust.rs). Not
    /// about a note, so it goes through `approve_trust`, not `approve`.
    Trust,
}

impl GatedCmd {
    pub fn as_str(&self) -> &'static str {
        match self {
            GatedCmd::ExportSecret => "export_secret",
            GatedCmd::MarkSpent => "mark_spent",
            GatedCmd::Discard => "discard",
            GatedCmd::Rename => "rename",
            GatedCmd::Delete => "delete",
            GatedCmd::Send => "send",
            GatedCmd::Trust => "trust",
        }
    }
}

/// Builds the signed kind-1059 event for `send`: `(secret, note, recipient)`
/// in, the wrap as JSON out. Injected because it needs the signing identity,
/// an RNG and a clock the dispatcher does not have. `None` on a surface with
/// no identity to seal as (direct USB), where `send` answers `bad_request`.
pub type WrapFn<'a> =
    &'a mut dyn FnMut(&[u8; SECRET_LEN], &NoteMeta, &[u8; 32]) -> Result<Value, &'static str>;

/// The owner's answer to a gated command. `Unavailable` is the vault's
/// `display_unavailable`: the device could not ask, which is deliberately
/// distinct from a refusal — nobody declined, and a client that cannot tell
/// the difference sends its owner hunting for a button they were never
/// shown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Approval {
    Approved,
    Declined,
    TimedOut,
    Unavailable,
}

/// Which surface a command arrived on, so a grant can never cross from one
/// to another. The cable is one identity because physical possession is its
/// whole pairing; a relay client is its slot pubkey.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantClient {
    /// The USB cable (NOTE_CMD frames). Whoever holds the cable is the client.
    Cable,
    /// A relay client, by the pubkey its connection slot is bound to.
    Relay([u8; 32]),
}

/// How long after an approved `export_secret` that note's `mark_spent` may
/// run with no card of its own, in seconds (#129).
///
/// Two minutes. What the window has to cover is one mint round trip: the
/// wallet melts the `ck1` it was just handed, then writes the device record
/// off, which on a slow mint over a slow link is tens of seconds, not one,
/// and a batch collect runs several of those back to back. It is
/// deliberately far shorter than someone walking away: a grant that outlived
/// the owner's attention would be a card they never saw for a command they
/// never watched. Measured on the same seconds-since-boot stamp the notes
/// carry, so a reboot cannot extend it; the grants are gone by then anyway.
pub const SPEND_GRANT_WINDOW_SECS: u32 = 120;

/// How many exports may be riding at once. Matches
/// [`crate::approval_queue::MAX_BATCH`], the most gated asks one card already
/// answers: a wallet that released eight notes on one hold leaves eight
/// grants, and writes the eight records off on none. The oldest is evicted
/// past that, which costs a card, never a secret.
pub const MAX_SPEND_GRANTS: usize = crate::approval_queue::MAX_BATCH;

/// One note's permission to be marked spent without a card of its own.
struct Grant {
    id: String,
    client: GrantClient,
    /// The stamp the export was approved at (seconds since boot).
    granted_at: u32,
}

/// Single-use permission for `mark_spent` to ride the `export_secret`
/// approval that just happened (#129).
///
/// A collect is two gated commands, release the secret then write the
/// record off, so the owner used to hold the button twice for one note. By
/// the time the second one runs the mint has already burned the note, so the
/// device record is worthless and the card guards only against a paired
/// client lying "that one is spent" to hide live money from its owner: a
/// nuisance, not theft, and it cost a press on every single collect.
///
/// So an approved export leaves a grant behind, and the `mark_spent` for THAT
/// note, from THAT client, inside a short window, runs without asking again.
/// The grant never widens: not to another note, not to another client, not to
/// `discard`, `send` or `delete`, and a declined, timed-out or failed export
/// leaves none. It is consumed by the first `mark_spent` attempt for its note
/// whether that attempt succeeds or fails, and it lives in RAM only and
/// never in NVS, so a reboot between the two halves brings the card back.
#[derive(Default)]
pub struct SpendGrant {
    live: Vec<Grant>,
}

impl SpendGrant {
    pub const fn new() -> Self {
        SpendGrant { live: Vec::new() }
    }

    /// Record what an approved export just earned. Re-exporting a note
    /// replaces its grant rather than adding a second one, so one note can
    /// never be behind two grants.
    pub fn grant(&mut self, id: &str, client: GrantClient, now: u32) {
        self.live.retain(|g| g.id != id);
        if self.live.len() >= MAX_SPEND_GRANTS {
            self.live.remove(0);
        }
        self.live.push(Grant { id: id.to_string(), client, granted_at: now });
    }

    /// Spend the grant for `id`, if this client has a live one. `true` means
    /// the caller may skip the card.
    ///
    /// A matching grant is removed either way, which is what makes it single
    /// use, and it is why a timed-out grant answers `false` here rather than
    /// being left to be found again. A grant for some OTHER note is left
    /// alone: this attempt is not the one it was minted for.
    pub fn take(&mut self, id: &str, client: GrantClient, now: u32) -> bool {
        let Some(at) = self.live.iter().position(|g| g.id == id && g.client == client) else {
            return false;
        };
        let grant = self.live.remove(at);
        // Monotonic: `now` going backwards means something other than the
        // boot clock supplied it, which is not a window this can measure.
        now.checked_sub(grant.granted_at)
            .is_some_and(|elapsed| elapsed <= SPEND_GRANT_WINDOW_SECS)
    }

    /// Drop every grant. For a caller that has just changed what "this
    /// client" means underneath them.
    pub fn clear(&mut self) {
        self.live.clear();
    }

    /// How many grants are live. Diagnostics and tests only.
    pub fn len(&self) -> usize {
        self.live.len()
    }

    pub fn is_empty(&self) -> bool {
        self.live.is_empty()
    }
}

/// Everything the firmware injects into one command dispatch. Kept as a
/// struct so the signature survives the relay path growing extra context.
pub struct NoteCmdContext<'a> {
    pub store: &'a mut NoteStore,
    pub storage: &'a mut dyn NoteStorage,
    pub rng: &'a mut dyn FnMut(&mut [u8]),
    /// Asked before any gated command runs. Firmware policy decides per kind
    /// whether to put a card up or answer `Approved` immediately; the
    /// dispatcher itself gates everything in [`GatedCmd`].
    pub approve: &'a mut dyn FnMut(GatedCmd, &NoteMeta) -> Approval,
    /// The device's live spend grants (#129). An approved `export_secret`
    /// leaves one here; the `mark_spent` for that note, from that client,
    /// inside [`SPEND_GRANT_WINDOW_SECS`], spends it instead of raising a
    /// second card. RAM only on the firmware, so a reboot brings the card
    /// back. See [`SpendGrant`].
    pub grant: &'a mut SpendGrant,
    /// Which surface this dispatch is serving, so a grant earned on the
    /// cable can never be spent by a relay client or the other way round.
    pub client: GrantClient,
    pub wrap: Option<WrapFn<'a>>,
    /// Senders whose wraps are stored without a hold. Persisted through
    /// `storage.save_trust`; a refusal there is `storage_full`.
    pub trust: &'a mut TrustList,
    /// Asked before a sender is trusted: the card names the key, not a note.
    pub approve_trust: &'a mut dyn FnMut(&[u8; 32]) -> Approval,
    /// Asked before a mint's LUD-25 subtree is stored: the card names the
    /// HOST, not a note and not the node.
    ///
    /// It is a hold rather than a quiet write because of what the node is:
    /// whoever supplied it can derive every note secret this device will ever
    /// hold at that mint. The card cannot show the owner the node — 64 bytes
    /// of hex is not something anyone checks off a panel — so it shows the one
    /// thing they can check, which is which mint they were expecting to set up.
    #[cfg(feature = "cash")]
    pub approve_cash: &'a mut dyn FnMut(&str) -> Approval,
    /// Seconds since some fixed epoch for created_at/updated_at. Boot time is
    /// fine — informational, never authoritative (the mint's state is).
    pub now: u32,
    /// `get_info` passthroughs.
    pub fw_version: &'a str,
    pub board: &'a str,
    /// The `storage` string `get_info` reports (`ok`, `full`, `unavailable`,
    /// `index_unreadable`, ...). The firmware owns the diagnosis; this layer
    /// only forwards it.
    pub storage_state: &'a str,
    /// Which mints this device can derive seed-recoverable note secrets for.
    ///
    /// Absent on a build without the `cash` feature (the lx106, whose DRAM
    /// cannot hold a second BIP-32 walk), and on one that simply has nothing
    /// provisioned. Either way `new_secret` without a `host` behaves as it
    /// always has.
    #[cfg(feature = "cash")]
    pub cash: &'a mut crate::cash_store::CashRegistry,
    /// The secret key of the identity this request is served as: the npub a
    /// lightning address belongs to, and so the root of the address branches
    /// its payments are minted to (`cash_key.rs`). `None` on a surface with
    /// no identity (direct USB), where the commands that need it answer
    /// `bad_request`, as `send` does without a `wrap`.
    #[cfg(feature = "cash")]
    pub identity: Option<&'a [u8; 32]>,
}

/// Hard ceiling on notes per `list_notes` page. A vault-protocol client
/// pages via `next_offset`, so a small page size costs round trips, not
/// completeness — and keeps the response inside one serial frame.
pub const LIST_PAGE_MAX: usize = 8;

fn ok() -> Value {
    json!({"ok": true})
}

fn err(code: &str) -> Value {
    json!({"ok": false, "error": code})
}

fn err_msg(code: &str, message: &str) -> Value {
    json!({"ok": false, "error": code, "message": message})
}

fn note_err(e: NoteError) -> Value {
    err(e.code())
}

/// Turn a command's optional `host` into a draw against that mint's ladder.
///
/// No `host` means no derivation: the secret comes from the RNG exactly as it
/// always did. That is not a fallback, it is the documented old behaviour, and
/// a client that has not been taught about mints keeps working unchanged.
///
/// A `host` that is NOT provisioned is refused rather than quietly drawn at
/// random. The caller asked for a note its seed phrase could find again; a
/// random one would satisfy the request and silently not be that, and nobody
/// would learn otherwise until a restore came up empty.
#[cfg(feature = "cash")]
fn cash_draw<'a>(
    registry: &'a mut crate::cash_store::CashRegistry,
    host: Option<&'a str>,
) -> Result<Option<crate::note_store::CashDraw<'a>>, Value> {
    let Some(host) = host else { return Ok(None) };
    if registry.get(host).is_none() {
        return Err(err_msg(
            "bad_request",
            "no cash node is provisioned for that host - provision_cash_node first",
        ));
    }
    Ok(Some(crate::note_store::CashDraw { registry, host }))
}

fn approval_err(a: Approval) -> Option<Value> {
    match a {
        Approval::Approved => None,
        Approval::Declined => Some(err("user_declined")),
        Approval::TimedOut => Some(err("timeout")),
        Approval::Unavailable => Some(err("display_unavailable")),
    }
}

fn meta_json(m: &NoteMeta) -> Value {
    let mut obj = Map::new();
    obj.insert("id".into(), Value::String(m.id.clone()));
    obj.insert("state".into(), Value::String(m.state.as_str().to_string()));
    obj.insert("amount_msat".into(), json!(m.amount_msat));
    obj.insert("host".into(), Value::String(m.host.clone()));
    obj.insert("label".into(), Value::String(m.label.clone()));
    if !m.sig.is_empty() {
        obj.insert("sig".into(), Value::String(m.sig.clone()));
    }
    obj.insert(
        "parent_ids".into(),
        Value::Array(m.parent_ids.iter().map(|p| Value::String(p.clone())).collect()),
    );
    obj.insert("created_at".into(), json!(m.created_at));
    obj.insert("updated_at".into(), json!(m.updated_at));
    match m.peer {
        None => {}
        Some(Peer::From(pk)) => {
            obj.insert("from".into(), Value::String(hex_encode(&pk)));
        }
        Some(Peer::To(pk)) => {
            obj.insert("sent_to".into(), Value::String(hex_encode(&pk)));
        }
    }
    // A key note is filed at the mint under its public key, which is what a
    // wallet looks it up by (`?p=`) and checks its certificate against.
    if let Some(key) = m.key {
        obj.insert("p".into(), Value::String(crate::encoding::encode_cp1(&key.pubkey)));
        obj.insert("index".into(), json!(key.index));
    }
    Value::Object(obj)
}

fn str_field<'a>(cmd: &'a Value, key: &str) -> Option<&'a str> {
    cmd.get(key).and_then(Value::as_str)
}

fn u64_field(cmd: &Value, key: &str) -> Option<u64> {
    cmd.get(key).and_then(Value::as_u64)
}

fn pubkey_field(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    hex_decode(hex).ok().and_then(|v| v.try_into().ok())
}

fn parent_ids(cmd: &Value) -> Result<Vec<String>, Value> {
    match cmd.get("parent_ids") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| v.as_str().map(|s| s.to_string()).ok_or_else(|| err("bad_request")))
            .collect(),
        Some(_) => Err(err("bad_request")),
    }
}

/// Longest `tag` a client may send, in bytes. Matches `lnurl-vault`'s
/// `TAG_MAX_LEN` and the fixed buffer behind it, so one client driving either
/// device gets the same answer to the same tag.
pub const TAG_MAX_LEN: usize = 32;

/// Dispatch one command message (already parsed from its transport frame).
/// Always returns a response object — an unparseable or unknown command is a
/// `bad_request` response, never silence, because the client's only timeout
/// is the long physical-confirm one.
///
/// A command may carry `tag`, echoed verbatim on whatever answers it. The
/// wire has no request ids, so without one a reply that is never coming looks
/// exactly like a slow one, and a late reply looks exactly like the reply to
/// the next command — which is why a client's own timeout had to be fatal, and
/// why this firmware poisons a serial session after one (#102). A tag makes
/// that survivable: the client keeps the stream open, retires the straggler by
/// its tag when it turns up, and retries an idempotent command whose reply
/// arrived torn. Same field, same limit and same refusal as `lnurl-vault`'s
/// dispatcher, because one CLI drives both devices and a protocol that is
/// almost the same on each is worse than one that differs openly.
pub fn handle_note_cmd(ctx: &mut NoteCmdContext<'_>, msg: &str) -> Value {
    let cmd: Value = match serde_json::from_str(msg) {
        Ok(v) => v,
        // No tag to echo: nothing here parsed. A client correlating replies
        // treats a line with no tag as not being the answer to anything it
        // tagged, which is exactly right for a line the device could not read.
        Err(_) => return err_msg("bad_request", "not a JSON object"),
    };

    // Read before anything can answer, so even a refusal carries it: a client
    // correlating replies needs its errors matched too. A tag that cannot be
    // echoed as given is refused outright rather than echoed truncated or
    // coerced, which would match nothing the client sent — and that refusal
    // carries no tag, for the same reason.
    let tag = match cmd.get("tag") {
        None => None,
        Some(Value::String(value)) if !value.is_empty() && value.len() <= TAG_MAX_LEN => {
            Some(value.clone())
        }
        Some(_) => {
            return err_msg(
                "bad_request",
                "tag must be a non-empty string of at most 32 characters",
            )
        }
    };

    let mut response = dispatch(ctx, &cmd);
    if let (Some(tag), Some(obj)) = (tag, response.as_object_mut()) {
        obj.insert("tag".into(), Value::String(tag));
    }
    response
}

/// The command itself. Split out from [`handle_note_cmd`] so that every
/// top-level reply — a success, an error, a listing page — leaves through one
/// place and none can miss the tag.
fn dispatch(ctx: &mut NoteCmdContext<'_>, cmd: &Value) -> Value {
    let Some(name) = str_field(cmd, "cmd") else {
        return err_msg("bad_request", "missing cmd");
    };

    match name {
        "get_info" => {
            let (note_count, pending_count) = ctx.store.counts();
            json!({
                "ok": true,
                "fw_version": ctx.fw_version,
                "board": ctx.board,
                "storage": ctx.storage_state,
                "note_count": note_count,
                "pending_count": pending_count,
                "received_count": ctx.store.received_count(),
                "trusted_count": ctx.trust.len(),
            })
        }

        // ---- trusted senders: wraps from these are stored without a hold ----
        "list_trusted" => json!({
            "ok": true,
            "trusted": ctx.trust.iter().map(|k| Value::String(hex_encode(k))).collect::<Vec<_>>(),
        }),

        "trust" => {
            let Some(pubkey) = str_field(&cmd, "pubkey").and_then(pubkey_field) else {
                return err_msg("bad_request", "pubkey must be 32 bytes of hex");
            };
            if cmd.get("remove").and_then(Value::as_bool) == Some(true) {
                // Withdrawing trust only ever adds a hold back; no button.
                let was = ctx.trust.remove(&pubkey);
                if was && ctx.storage.save_trust(&ctx.trust.encode()).is_err() {
                    return err("storage_full");
                }
                return json!({"ok": true, "trusted": false, "changed": was});
            }
            if ctx.trust.contains(&pubkey) {
                return json!({"ok": true, "trusted": true, "changed": false});
            }
            if ctx.trust.len() >= crate::trust::MAX_TRUSTED {
                return err_msg("bad_request", "trust list full");
            }
            if let Some(resp) = approval_err((ctx.approve_trust)(&pubkey)) {
                return resp;
            }
            if ctx.trust.add(pubkey) != Ok(true) {
                return err_msg("bad_request", "trust list full");
            }
            if ctx.storage.save_trust(&ctx.trust.encode()).is_err() {
                ctx.trust.remove(&pubkey);
                return err("storage_full");
            }
            json!({"ok": true, "trusted": true, "changed": true})
        }

        // ---- LUD-25 seed-recoverable note secrets ----

        #[cfg(feature = "cash")]
        "provision_cash_node" => {
            let Some(host) = str_field(&cmd, "host") else {
                return err_msg("bad_request", "host is required");
            };
            let Some(node_hex) = str_field(&cmd, "node") else {
                return err_msg("bad_request", "node must be 64 bytes of hex");
            };
            let Ok(bytes) = crate::hex::hex_decode(node_hex) else {
                return err_msg("bad_request", "node must be 64 bytes of hex");
            };
            let Ok(node_bytes) = <[u8; 64]>::try_from(bytes.as_slice()) else {
                return err_msg("bad_request", "node must be 64 bytes of hex");
            };
            // The host is checked HERE, before the card, not left to
            // `provision` below. A card naming a host the registry would
            // refuse is a hold that could never have succeeded, and this
            // device has learned once already what that teaches an owner. It
            // also keeps a non-ASCII host away from the card, whose eliding
            // slices by byte.
            if !crate::cash_store::valid_host(host) {
                return err_msg("bad_request", "host must be a lowercase mint host");
            }
            // Approval AFTER the request is known to be well-formed and
            // BEFORE anything is written. A card for a request that could
            // never succeed teaches the owner to press without reading, and
            // this device already learned that lesson once.
            if let Some(resp) = approval_err((ctx.approve_cash)(host)) {
                return resp;
            }
            let node = crate::cash::cash_node_from_bytes(&node_bytes);
            // Reported back so a client can tell "set up" from "restarted the
            // ladder at zero", which are very different things to have just
            // done to a mint you already had notes at.
            let replaced = ctx.cash.get(host).is_some();
            match ctx.cash.provision(host, node) {
                Ok(()) => {}
                Err(crate::cash_store::CashError::Full) => return err("storage_full"),
                Err(_) => return err_msg("bad_request", "host must be a lowercase mint host"),
            }
            if ctx.storage.save_cash(&ctx.cash.encode()).is_err() {
                // Roll RAM back to match what survived: a registry that says
                // it can derive for a mint whose counter is not persisted
                // would re-issue secrets after a reboot.
                ctx.cash.forget(host);
                return err("storage_full");
            }
            json!({"ok": true, "host": host, "replaced": replaced, "next_index": 0})
        }

        #[cfg(feature = "cash")]
        "forget_cash_node" => {
            // No hold. Forgetting only ever removes an ability — the secrets
            // of notes already held are stored, never re-derived, so this
            // cannot lose money. Same reasoning as withdrawing trust.
            let Some(host) = str_field(&cmd, "host") else {
                return err_msg("bad_request", "host is required");
            };
            let changed = ctx.cash.forget(host);
            if changed && ctx.storage.save_cash(&ctx.cash.encode()).is_err() {
                return err("storage_full");
            }
            json!({"ok": true, "changed": changed})
        }

        #[cfg(feature = "cash")]
        "list_cash_mints" => {
            let mints: Vec<Value> = ctx
                .cash
                .hosts()
                .map(|(host, next_index)| json!({"host": host, "next_index": next_index}))
                .collect();
            // Never the node. It is bearer material for every note at that
            // mint, and nothing a client does needs it back.
            json!({"ok": true, "mints": mints})
        }

        #[cfg(feature = "cash")]
        "set_cash_index" => {
            // Raising only. A wallet that has minted further than this device
            // knows says so here, and the ladder skips to meet it. Lowering is
            // not offered at all: an index handed out twice is two notes
            // answering to one k1, and no client is well placed to ask for it.
            let Some(host) = str_field(&cmd, "host") else {
                return err_msg("bad_request", "host is required");
            };
            let Some(at_least) = u64_field(&cmd, "next_index") else {
                return err_msg("bad_request", "next_index is required");
            };
            if at_least > crate::cash::MAX_NOTE_INDEX as u64 {
                return err_msg("bad_request", "next_index must be below 2^31");
            }
            match ctx.cash.raise_index(host, at_least as u32) {
                Ok(next_index) => {
                    if ctx.storage.save_cash(&ctx.cash.encode()).is_err() {
                        return err("storage_full");
                    }
                    json!({"ok": true, "host": host, "next_index": next_index})
                }
                Err(_) => err_msg("bad_request", "no cash node is provisioned for that host"),
            }
        }

        // ---- LUD-25 Part 2: notes paid to this device's own keys ----

        #[cfg(feature = "cash")]
        "cash_address" => {
            // The watch-only branch a mint mints this identity's payments to.
            // No hold: it spends nothing. It does let whoever holds it link
            // every payment made to it, which is why it goes to a bound
            // client and, from there, to the one mint it is for.
            let Some(identity) = ctx.identity else {
                return err_msg("bad_request", "cash_address is not available on this surface");
            };
            let Some(host) = str_field(&cmd, "host") else {
                return err_msg("bad_request", "host is required");
            };
            if !crate::cash_store::valid_host(host) {
                return err_msg("bad_request", "host must be a lowercase mint host");
            }
            let cx1 = match crate::cash_key::address_node(identity, host)
                .and_then(|node| crate::cash_key::cx1_of(&node))
            {
                Ok(cx1) => cx1,
                Err(m) => return err_msg("bad_request", m),
            };
            let Ok(pubkey) = crate::derive::public_key_xonly(identity) else {
                return err("bad_request");
            };
            // The owner's key comes back with it, so a client can check the
            // branch belongs to the npub the lightning address does.
            json!({"ok": true, "host": host, "cx1": cx1, "pubkey": hex_encode(&pubkey)})
        }

        #[cfg(feature = "cash")]
        "claim_key_note" => {
            // A payment a wallet found by scanning the branch, whose wrap never
            // arrived: the device derives the key at `index` and keeps the note.
            // No hold, as import has none: it discloses nothing and the note
            // was already this device's.
            let Some(identity) = ctx.identity else {
                return err_msg("bad_request", "claim_key_note is not available on this surface");
            };
            let Some(host) = str_field(&cmd, "host") else { return err("bad_request") };
            let Some(amount) = u64_field(&cmd, "amount_msat") else {
                return err("bad_request");
            };
            let Some(index) = u64_field(&cmd, "index").and_then(|i| u32::try_from(i).ok()) else {
                return err_msg("bad_request", "index must be a uint32");
            };
            let sig = str_field(&cmd, "sig").unwrap_or("");
            let branch = crate::cash_key::branch_host(host);
            if !crate::cash_store::valid_host(branch) {
                return err_msg("bad_request", "host must be a lowercase mint host");
            }
            // The key the wallet expected, if it says: a claim for a key this
            // device would not derive is refused, not stored under another.
            let expected = match str_field(&cmd, "p") {
                None => None,
                Some(p) => match crate::encoding::decode_cp1(p) {
                    Some(pk) => Some(pk),
                    None => return err_msg("bad_request", "p is not a cp1"),
                },
            };
            let (secret, pubkey) =
                match crate::cash_key::claim_note_key(identity, branch, index, expected.as_ref()) {
                    Ok(found) => found,
                    Err(m) => return err_msg("bad_request", m),
                };
            let key = crate::note_store::KeyNote { index, pubkey };
            match ctx
                .store
                .import_key(ctx.storage, ctx.rng, &secret, key, host, amount, sig, ctx.now)
            {
                Ok((id, created)) => json!({
                    "ok": true,
                    "id": id,
                    "created": created,
                    "p": crate::encoding::encode_cp1(&pubkey),
                }),
                Err(e) => note_err(e),
            }
        }

        "list_notes" => {
            let offset = u64_field(&cmd, "offset").unwrap_or(0) as usize;
            let limit = u64_field(&cmd, "limit")
                .map(|l| l as usize)
                .unwrap_or(LIST_PAGE_MAX)
                .clamp(1, LIST_PAGE_MAX);
            let page = ctx.store.list(offset, limit);
            let mut obj = Map::new();
            obj.insert("ok".into(), Value::Bool(true));
            obj.insert("total".into(), json!(page.total));
            obj.insert("offset".into(), json!(page.offset));
            obj.insert(
                "notes".into(),
                Value::Array(page.notes.iter().map(meta_json).collect()),
            );
            if let Some(next) = page.next_offset {
                obj.insert("next_offset".into(), json!(next));
            }
            Value::Object(obj)
        }

        "new_secret" => {
            let parents = match parent_ids(&cmd) {
                Ok(p) => p,
                Err(e) => return e,
            };
            let label = str_field(&cmd, "label").unwrap_or("");
            #[cfg(feature = "cash")]
            let result = {
                let host = str_field(&cmd, "host");
                match cash_draw(ctx.cash, host) {
                    Err(resp) => return resp,
                    Ok(mut draw) => ctx.store.new_secret(
                        ctx.storage,
                        ctx.rng,
                        draw.as_mut(),
                        &parents,
                        label,
                        ctx.now,
                    ),
                }
            };
            #[cfg(not(feature = "cash"))]
            let result = ctx.store.new_secret(ctx.storage, ctx.rng, &parents, label, ctx.now);
            match result {
                Ok((id, h)) => json!({"ok": true, "id": id, "h": h}),
                Err(e) => note_err(e),
            }
        }

        "new_secret_pair" => {
            let parents = match parent_ids(&cmd) {
                Ok(p) => p,
                Err(e) => return e,
            };
            let label = str_field(&cmd, "label").unwrap_or("");
            #[cfg(feature = "cash")]
            let result = {
                let host = str_field(&cmd, "host");
                match cash_draw(ctx.cash, host) {
                    Err(resp) => return resp,
                    Ok(mut draw) => ctx.store.new_secret_pair(
                        ctx.storage,
                        ctx.rng,
                        draw.as_mut(),
                        &parents,
                        label,
                        ctx.now,
                    ),
                }
            };
            #[cfg(not(feature = "cash"))]
            let result = ctx.store.new_secret_pair(ctx.storage, ctx.rng, &parents, label, ctx.now);
            match result {
                Ok((id, h, id2, h2)) => json!({"ok": true, "id": id, "h": h, "id2": id2, "h2": h2}),
                Err(e) => note_err(e),
            }
        }

        "confirm" => {
            let Some(id) = str_field(&cmd, "id") else { return err("bad_request") };
            let Some(amount) = u64_field(&cmd, "amount_msat") else {
                return err("bad_request");
            };
            let Some(host) = str_field(&cmd, "host") else { return err("bad_request") };
            let sig = str_field(&cmd, "sig");
            match ctx.store.confirm(ctx.storage, id, amount, host, sig, ctx.now) {
                Ok(()) => ok(),
                Err(e) => note_err(e),
            }
        }

        "discard" => gated_by_id(ctx, &cmd, GatedCmd::Discard, |ctx, id| {
            ctx.store.discard(ctx.storage, id)
        }),

        "export_secret" => {
            let Some(id) = str_field(&cmd, "id") else { return err("bad_request") };
            let Some(meta) = ctx.store.get_meta(id) else { return err("not_found") };
            // State-check before the owner is asked: a prompt for a note that
            // could never export teaches the owner to press without reading.
            if let Err(e) = ctx.store.can_export(id) {
                return note_err(e);
            }
            if let Some(resp) = approval_err((ctx.approve)(GatedCmd::ExportSecret, &meta)) {
                return resp;
            }
            let exported = ctx.store.export_secret(id);
            match exported {
                Ok(k1) => {
                    // #129: the hold that just released this note also buys
                    // the right to write its record off. Recorded on success
                    // only: an export that failed released nothing, so
                    // there is nothing for a spend mark to follow.
                    ctx.grant.grant(id, ctx.client, ctx.now);
                    json!({"ok": true, "k1": k1})
                }
                Err(e) => note_err(e),
            }
        }

        "import_secret" => {
            let Some(k1) = str_field(&cmd, "k1") else { return err("bad_request") };
            let Some(host) = str_field(&cmd, "host") else { return err("bad_request") };
            let Some(amount) = u64_field(&cmd, "amount_msat") else {
                return err("bad_request");
            };
            let label = str_field(&cmd, "label").unwrap_or("");
            match ctx
                .store
                .import_secret(ctx.storage, ctx.rng, k1, host, amount, label, ctx.now)
            {
                Ok((id, _created)) => json!({"ok": true, "id": id}),
                Err(e) => note_err(e),
            }
        }

        "mark_spent" => gated_by_id(ctx, &cmd, GatedCmd::MarkSpent, |ctx, id| {
            let now = ctx.now;
            ctx.store.mark_spent(ctx.storage, id, now)
        }),

        "rename" => {
            let Some(label) = str_field(&cmd, "label") else { return err("bad_request") };
            if label.len() > crate::note_store::MAX_LABEL_LEN {
                // Checked here as well as in the store so the owner is never
                // prompted to approve a rename that cannot succeed.
                return err("bad_request");
            }
            let label = label.to_string();
            gated_by_id(ctx, &cmd, GatedCmd::Rename, move |ctx, id| {
                let now = ctx.now;
                ctx.store.rename(ctx.storage, id, &label, now)
            })
        }

        "delete" => gated_by_id(ctx, &cmd, GatedCmd::Delete, |ctx, id| {
            ctx.store.delete(ctx.storage, id)
        }),

        "send" => {
            let Some(id) = str_field(&cmd, "id") else { return err("bad_request") };
            let Some(to) = str_field(&cmd, "to").and_then(pubkey_field) else {
                return err("bad_request");
            };
            let Some(meta) = ctx.store.get_meta(id) else { return err("not_found") };
            if let Err(e) = ctx.store.can_send(id) {
                return note_err(e);
            }
            if ctx.wrap.is_none() {
                return err_msg("bad_request", "send is not available on this surface");
            }
            if let Some(resp) = approval_err((ctx.approve)(GatedCmd::Send, &meta)) {
                return resp;
            }
            let mut secret = match ctx.store.secret_for_send(id) {
                Ok(s) => s,
                Err(e) => return note_err(e),
            };
            let wrapped = (ctx.wrap.as_mut().expect("checked above"))(&secret, &meta, &to);
            secret.zeroize();
            let event = match wrapped {
                Ok(v) => v,
                Err(m) => return err_msg("bad_request", m),
            };
            // Persisted before the wrap leaves: a cut here strands an
            // unpublished wrap, never a note that can be sent twice.
            match ctx.store.mark_sent(ctx.storage, id, &to, ctx.now) {
                Ok(()) => json!({"ok": true, "event": event}),
                Err(e) => note_err(e),
            }
        }

        other => err_msg("bad_request", &format!("unknown cmd {other}")),
    }
}

/// The note state a gated command needs to be able to succeed, checked
/// BEFORE the owner is prompted: a card for a command that could never run
/// teaches the owner to press without reading (the recorded design rule).
/// `None` means any state is acceptable (rename).
fn required_state(kind: GatedCmd) -> Option<NoteState> {
    match kind {
        GatedCmd::ExportSecret | GatedCmd::MarkSpent | GatedCmd::Send => {
            Some(NoteState::Confirmed)
        }
        GatedCmd::Discard => Some(NoteState::Pending),
        GatedCmd::Delete => Some(NoteState::Spent),
        // Rename takes any state; trust is not about a note at all.
        GatedCmd::Rename | GatedCmd::Trust => None,
    }
}

/// The shared shape of every gated id-addressed command: resolve the note,
/// state-check, ask the owner with its metadata on screen, then run the
/// mutation. The mutation's own state check runs regardless — approval never
/// overrides the lifecycle rules.
fn gated_by_id(
    ctx: &mut NoteCmdContext<'_>,
    cmd: &Value,
    kind: GatedCmd,
    mutate: impl FnOnce(&mut NoteCmdContext<'_>, &str) -> Result<(), NoteError>,
) -> Value {
    let Some(id) = str_field(cmd, "id") else { return err("bad_request") };
    let Some(meta) = ctx.store.get_meta(id) else { return err("not_found") };
    if let Some(required) = required_state(kind) {
        if meta.state != required {
            return err("invalid_state");
        }
    }
    // #129: ONLY mark_spent may ride an export's hold, and only its own
    // note's, from its own client, inside the window. Everything else in
    // GatedCmd asks every time; a grant that widened to `discard`, `send`
    // or `delete` would be a hold answering a question nobody was shown.
    let granted = kind == GatedCmd::MarkSpent && ctx.grant.take(id, ctx.client, ctx.now);
    if !granted {
        if let Some(resp) = approval_err((ctx.approve)(kind, &meta)) {
            return resp;
        }
    }
    let id = id.to_string();
    match mutate(ctx, &id) {
        Ok(()) => ok(),
        Err(e) => note_err(e),
    }
}

// ---- relay-path mapping (heartwood_note_* NIP-46 extensions) ----

/// The note methods served over the relay path, in the order the
/// capabilities advert lists them. Rename/delete are deliberately absent:
/// housekeeping stays a USB-cable operation.
pub const NOTE_METHODS: [&str; 13] = [
    "heartwood_note_list",
    "heartwood_note_new",
    "heartwood_note_new_pair",
    "heartwood_note_confirm",
    "heartwood_note_discard",
    "heartwood_note_export",
    "heartwood_note_import",
    "heartwood_note_spent",
    "heartwood_note_send",
    "heartwood_note_trust",
    "heartwood_note_trusted",
    "heartwood_note_address",
    "heartwood_note_claim",
];

/// Map a `heartwood_note_*` NIP-46 request onto the wire command object the
/// dispatcher above already handles — `params[0]` is an optional object of
/// the command's own fields, exactly the USB JSON minus the `cmd` key. Pure
/// so the translation is host-tested; `Err` is the NIP-46 error string.
/// Unknown methods and non-object params are refused here, so the firmware
/// arm stays a straight pipe.
/// One note a relay card speaks for: what the locker knows about it.
pub struct BatchNote<'a> {
    pub amount_msat: u64,
    pub host: &'a str,
}

/// Header and title for a relay card that answers MORE THAN ONE gated note
/// command with a single hold.
///
/// The batch machinery (approval_queue) lets the same client's repeat asks
/// for the same method share a card, which is how a wallet collects three
/// notes with one hold instead of three. That is fine only if the card says
/// so: a card reading "RELEASE NOTE / 12 sats" whose hold releases three
/// notes worth 1,110 sats has told the owner a lie about their money. So a
/// batch card names the count, the total, and the mint (or how many mints)
/// — the same rule the signing card follows with its "x3".
///
/// `header` is the single-note header ("RELEASE NOTE"); `notes` is every
/// ask on the card, locker-known amounts only (a missing note contributes
/// nothing and the count still includes it, so the total can only ever be
/// an under-statement, never an over-statement that hides a note).
pub fn batch_card(header: &str, notes: &[BatchNote<'_>], recipient: Option<&str>) -> (String, String) {
    let action = header.strip_suffix(" NOTE").unwrap_or(header);
    let head = format!("{action} {} NOTES", notes.len());
    // Summed in msat and formatted ONCE. Truncating each note to sats first
    // and adding those loses up to a sat per note: three notes of 1 999 msat
    // are 5 997 msat, not the 3 sats a per-note division reports.
    let total = notes.iter().fold(0u64, |acc, n| acc.saturating_add(n.amount_msat));
    let amount = crate::note_fmt::format_amount(total);
    let mut hosts: Vec<&str> = notes.iter().map(|n| n.host).filter(|h| !h.is_empty()).collect();
    hosts.sort_unstable();
    hosts.dedup();
    let first = match hosts.as_slice() {
        [] => amount,
        [one] => format!("{amount} @ {}", crate::note_fmt::elide_host(one, crate::note_fmt::CARD_LINE_CHARS)),
        many => format!("{amount} @ {} mints", many.len()),
    };
    let title = match recipient {
        Some(to) if to.len() == 64 => format!("{first}\nto {}..{}", &to[..8], &to[56..]),
        Some(_) => format!("{first}\nto ?"),
        None => first,
    };
    (head, title)
}

pub fn note_cmd_for_method(method: &str, params: &[Value]) -> Result<Value, &'static str> {
    let cmd = match method {
        "heartwood_note_list" => "list_notes",
        "heartwood_note_new" => "new_secret",
        "heartwood_note_new_pair" => "new_secret_pair",
        "heartwood_note_confirm" => "confirm",
        "heartwood_note_discard" => "discard",
        "heartwood_note_export" => "export_secret",
        "heartwood_note_import" => "import_secret",
        "heartwood_note_spent" => "mark_spent",
        "heartwood_note_send" => "send",
        "heartwood_note_trust" => "trust",
        "heartwood_note_trusted" => "list_trusted",
        "heartwood_note_address" => "cash_address",
        "heartwood_note_claim" => "claim_key_note",
        _ => return Err("unknown note method"),
    };
    let mut fields = match params.first() {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(map)) => map.clone(),
        Some(_) => return Err("params[0] must be an object"),
    };
    // The wire command name is this layer's to set — a caller-supplied `cmd`
    // must not be able to redirect a gated method onto an ungated command.
    fields.insert("cmd".into(), Value::String(cmd.into()));
    Ok(Value::Object(fields))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::note_store::{NoteState, StorageError, MAX_NOTES};
    use std::collections::BTreeMap;
    use std::string::ToString;
    use std::vec;
    use std::vec::Vec;

    struct MemStorage {
        index: Option<Vec<String>>,
        notes: BTreeMap<String, Vec<u8>>,
        trust: Option<Vec<u8>>,
        cash: Option<Vec<u8>>,
        persist_ok: bool,
        /// Whether a note blob may be written. A record rewrite that fails is
        /// how a gated command gets to fail AFTER its approval was settled.
        note_write_ok: bool,
    }

    impl MemStorage {
        fn new() -> Self {
            MemStorage {
                index: None,
                notes: BTreeMap::new(),
                trust: None,
                cash: None,
                persist_ok: true,
                note_write_ok: true,
            }
        }
    }

    impl NoteStorage for MemStorage {
        fn load_index(&mut self) -> Result<Option<Vec<String>>, StorageError> {
            Ok(self.index.clone())
        }
        fn save_index(&mut self, ids: &[String]) -> Result<(), StorageError> {
            self.index = Some(ids.to_vec());
            Ok(())
        }
        fn load_note(&mut self, id: &str) -> Result<Option<Vec<u8>>, StorageError> {
            Ok(self.notes.get(id).cloned())
        }
        fn save_note(&mut self, id: &str, blob: &[u8]) -> Result<(), StorageError> {
            if !self.note_write_ok {
                return Err(StorageError);
            }
            self.notes.insert(id.to_string(), blob.to_vec());
            Ok(())
        }
        fn delete_note(&mut self, id: &str) -> Result<(), StorageError> {
            self.notes.remove(id);
            Ok(())
        }
        fn save_trust(&mut self, blob: &[u8]) -> Result<(), StorageError> {
            if !self.persist_ok {
                return Err(StorageError);
            }
            self.trust = Some(blob.to_vec());
            Ok(())
        }
        fn load_cash(&mut self) -> Result<Option<Vec<u8>>, StorageError> {
            Ok(self.cash.clone())
        }
        fn save_cash(&mut self, blob: &[u8]) -> Result<(), StorageError> {
            if !self.persist_ok {
                return Err(StorageError);
            }
            self.cash = Some(blob.to_vec());
            Ok(())
        }
    }

    struct Harness {
        store: NoteStore,
        storage: MemStorage,
        answer: Approval,
        asked: Vec<(GatedCmd, String)>,
        /// Secrets handed to the wrap hook, so a test can check the plaintext
        /// went where it should and nowhere else.
        wrapped: Vec<([u8; SECRET_LEN], [u8; 32])>,
        can_wrap: bool,
        trust: TrustList,
        trust_asked: Vec<[u8; 32]>,
        cash: crate::cash_store::CashRegistry,
        cash_asked: Vec<String>,
        persist_ok: bool,
        note_write_ok: bool,
        /// The identity the request is served as; `None` is direct USB.
        identity: Option<[u8; 32]>,
        /// Live spend grants (#129), and the two dials a test needs to move:
        /// which surface is asking, and what the boot clock says.
        grant: SpendGrant,
        client: GrantClient,
        now: u32,
    }

    impl Harness {
        fn new() -> Self {
            let mut storage = MemStorage::new();
            let store = NoteStore::load(&mut storage, MAX_NOTES).store;
            Harness {
                store,
                storage,
                answer: Approval::Approved,
                asked: Vec::new(),
                wrapped: Vec::new(),
                can_wrap: true,
                trust: TrustList::new(),
                trust_asked: Vec::new(),
                cash: crate::cash_store::CashRegistry::new(),
                cash_asked: Vec::new(),
                persist_ok: true,
                note_write_ok: true,
                identity: Some([7u8; 32]),
                grant: SpendGrant::new(),
                client: GrantClient::Relay([0xc1; 32]),
                now: 42,
            }
        }

        fn run(&mut self, msg: &str) -> Value {
            let mut counter: u64 = 0;
            let mut rng = move |buf: &mut [u8]| {
                for chunk in buf.chunks_mut(8) {
                    counter += 1;
                    let bytes = counter.to_be_bytes();
                    let n = chunk.len().min(8);
                    chunk[..n].copy_from_slice(&bytes[8 - n..]);
                }
            };
            let answer = self.answer;
            let asked = &mut self.asked;
            let mut approve = move |kind: GatedCmd, meta: &NoteMeta| {
                asked.push((kind, meta.id.clone()));
                answer
            };
            let wrapped = &mut self.wrapped;
            let mut wrap = move |secret: &[u8; SECRET_LEN], _meta: &NoteMeta, to: &[u8; 32]| {
                wrapped.push((*secret, *to));
                Ok(serde_json::json!({"kind": 1059, "content": "sealed"}))
            };
            let trust_asked = &mut self.trust_asked;
            let mut approve_trust = move |pk: &[u8; 32]| {
                trust_asked.push(*pk);
                answer
            };
            let cash_asked = &mut self.cash_asked;
            let mut approve_cash = move |host: &str| {
                cash_asked.push(host.to_string());
                answer
            };
            self.storage.persist_ok = self.persist_ok;
            self.storage.note_write_ok = self.note_write_ok;
            let mut ctx = NoteCmdContext {
                store: &mut self.store,
                storage: &mut self.storage,
                rng: &mut rng,
                approve: &mut approve,
                grant: &mut self.grant,
                client: self.client,
                wrap: if self.can_wrap { Some(&mut wrap) } else { None },
                trust: &mut self.trust,
                approve_trust: &mut approve_trust,
                cash: &mut self.cash,
                approve_cash: &mut approve_cash,
                now: self.now,
                fw_version: "0.0.0-test",
                board: "host",
                storage_state: "ok",
                identity: self.identity.as_ref(),
            };
            handle_note_cmd(&mut ctx, msg)
        }

        /// Drive a note to CONFIRMED and return its id.
        fn confirmed_note(&mut self) -> String {
            let res = self.run(r#"{"cmd":"new_secret","label":"float"}"#);
            assert_eq!(res["ok"], true, "{res}");
            let id = res["id"].as_str().unwrap().to_string();
            let res = self.run(&format!(
                r#"{{"cmd":"confirm","id":"{id}","amount_msat":21000,"host":"mint.example"}}"#
            ));
            assert_eq!(res["ok"], true, "{res}");
            id
        }

        /// Power-cycle the device. The store is NVS-backed and survives; the
        /// spend grants are RAM only and do not, and the boot clock the
        /// window is measured on restarts at zero.
        fn reboot(&mut self) {
            self.grant = SpendGrant::new();
            self.now = 0;
        }
    }

    // ---- LUD-25 seed-recoverable note secrets ----
    //
    // Without a host, new_secret draws at random exactly as it always has.
    // With one, the secret comes off that mint's ladder so a seed phrase can
    // find it again. The rules with teeth are all about the counter.

    #[cfg(feature = "cash")]
    mod cash_tests {
        use super::*;
        use crate::cash::{cash_secret_at, derive_cash_domain_node, derive_cash_root};
        use crate::cash_store::MAX_CASH_MINTS;

        const SEED_HEX: &str = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

        fn seed() -> [u8; 64] {
            let mut out = [0u8; 64];
            for (i, slot) in out.iter_mut().enumerate() {
                *slot = u8::from_str_radix(&SEED_HEX[i * 2..i * 2 + 2], 16).unwrap();
            }
            out
        }

        fn node_hex(host: &str) -> String {
            let node =
                derive_cash_domain_node(&derive_cash_root(&seed()).unwrap(), host).unwrap();
            crate::hex::hex_encode(crate::cash::cash_node_to_bytes(&node).as_ref())
        }

        /// What the wallet would derive at this index, to compare against.
        fn expected_h(host: &str, index: u32) -> String {
            let node =
                derive_cash_domain_node(&derive_cash_root(&seed()).unwrap(), host).unwrap();
            let secret = cash_secret_at(&node, index).unwrap();
            crate::note_store::secret_hash_hex(&secret)
        }

        fn provision(h: &mut Harness, host: &str) -> Value {
            h.run(&format!(
                r#"{{"cmd":"provision_cash_node","host":"{host}","node":"{}"}}"#,
                node_hex(host)
            ))
        }

        #[test]
        fn a_provisioned_mint_mints_the_secret_the_wallet_would_derive() {
            // The whole point: the device and the wallet, from one seed, have
            // to produce the same 32 bytes, or the money is findable from only
            // one of them.
            let mut h = Harness::new();
            assert_eq!(provision(&mut h, "mint.example")["ok"], true);

            let res = h.run(r#"{"cmd":"new_secret","host":"mint.example"}"#);
            assert_eq!(res["ok"], true, "{res}");
            assert_eq!(res["h"], expected_h("mint.example", 0));

            let res = h.run(r#"{"cmd":"new_secret","host":"mint.example"}"#);
            assert_eq!(res["h"], expected_h("mint.example", 1));
        }

        #[test]
        fn a_split_takes_two_indices_in_order() {
            let mut h = Harness::new();
            provision(&mut h, "mint.example");
            let res = h.run(r#"{"cmd":"new_secret_pair","host":"mint.example"}"#);
            assert_eq!(res["ok"], true, "{res}");
            assert_eq!(res["h"], expected_h("mint.example", 0));
            assert_eq!(res["h2"], expected_h("mint.example", 1));
            // and the next one carries on rather than repeating either
            let res = h.run(r#"{"cmd":"new_secret","host":"mint.example"}"#);
            assert_eq!(res["h"], expected_h("mint.example", 2));
        }

        #[test]
        fn no_host_still_draws_at_random() {
            // A client that never learned about mints keeps working, and its
            // notes are still perfectly good - just not findable from a seed.
            let mut h = Harness::new();
            provision(&mut h, "mint.example");
            let a = h.run(r#"{"cmd":"new_secret"}"#);
            assert_eq!(a["ok"], true);
            assert_ne!(a["h"], expected_h("mint.example", 0));
            // and it did not move the ladder
            let b = h.run(r#"{"cmd":"new_secret","host":"mint.example"}"#);
            assert_eq!(b["h"], expected_h("mint.example", 0));
        }

        #[test]
        fn an_unprovisioned_host_is_refused_rather_than_quietly_drawn() {
            // The caller asked for a note its seed could find. A random one
            // would satisfy the request and silently not be that, and nobody
            // would learn otherwise until a restore came up empty.
            let mut h = Harness::new();
            let res = h.run(r#"{"cmd":"new_secret","host":"mint.example"}"#);
            assert_eq!(res["ok"], false, "{res}");
            assert_eq!(res["error"], "bad_request");
            assert_eq!(h.run(r#"{"cmd":"get_info"}"#)["note_count"], 0);
        }

        #[test]
        fn the_counter_is_persisted_before_the_secret_exists() {
            // The ordering that matters. A counter written after the secret
            // was used would, on a cut in between, come back one index low,
            // and the next mint there would hand out a secret the SERVICE has
            // already issued a note against.
            let mut h = Harness::new();
            provision(&mut h, "mint.example");
            h.run(r#"{"cmd":"new_secret","host":"mint.example"}"#);

            // Reload the registry from what actually reached storage.
            let blob = h.storage.cash.clone().expect("a cash blob was written");
            let reloaded = crate::cash_store::CashRegistry::decode(&blob).expect("decodes");
            assert_eq!(reloaded.get("mint.example").unwrap().next_index, 1);
        }

        #[test]
        fn a_storage_that_cannot_keep_the_counter_mints_nothing() {
            // Deriving against a counter that will not survive a reboot is how
            // one k1 ends up behind two notes. Refusing is the only safe
            // answer, and it has to refuse BEFORE the note exists.
            let mut h = Harness::new();
            provision(&mut h, "mint.example");
            h.persist_ok = false;
            let res = h.run(r#"{"cmd":"new_secret","host":"mint.example"}"#);
            assert_eq!(res["ok"], false, "{res}");
            assert_eq!(res["error"], "storage_full");
            h.persist_ok = true;
            assert_eq!(h.run(r#"{"cmd":"get_info"}"#)["note_count"], 0);
        }

        #[test]
        fn provisioning_asks_the_owner_and_names_the_host() {
            // The card cannot show 64 bytes of hex to check, so it shows the
            // one thing the owner can check: which mint this is.
            let mut h = Harness::new();
            provision(&mut h, "mint.example");
            assert_eq!(h.cash_asked, alloc::vec!["mint.example".to_string()]);
        }

        #[test]
        fn a_declined_provision_stores_nothing() {
            let mut h = Harness::new();
            h.answer = Approval::Declined;
            let res = provision(&mut h, "mint.example");
            assert_eq!(res["ok"], false, "{res}");
            assert_eq!(res["error"], "user_declined");
            assert_eq!(h.run(r#"{"cmd":"list_cash_mints"}"#)["mints"].as_array().unwrap().len(), 0);
        }

        #[test]
        fn a_host_that_could_never_be_provisioned_never_reaches_a_card() {
            // Checked before the hold, not left to the registry underneath.
            // A card naming a host that would be refused anyway is a hold
            // that could never have succeeded, and the non-ASCII case would
            // also reach a card that elides by byte.
            let mut h = Harness::new();
            let node = node_hex("mint.example");
            for host in ["Mint.Example", "mint.example/w", "héllo.example", ""] {
                let res = h.run(&format!(
                    r#"{{"cmd":"provision_cash_node","host":"{host}","node":"{node}"}}"#
                ));
                assert_eq!(res["ok"], false, "{host} -> {res}");
                assert_eq!(res["error"], "bad_request", "{host} -> {res}");
            }
            assert!(h.cash_asked.is_empty(), "asked: {:?}", h.cash_asked);
        }

        #[test]
        fn a_malformed_node_never_reaches_a_card() {
            // A card for a request that could never succeed teaches the owner
            // to press without reading.
            let mut h = Harness::new();
            for msg in [
                r#"{"cmd":"provision_cash_node","host":"mint.example"}"#,
                r#"{"cmd":"provision_cash_node","host":"mint.example","node":"beef"}"#,
                r#"{"cmd":"provision_cash_node","host":"mint.example","node":"zz"}"#,
                r#"{"cmd":"provision_cash_node","node":"00"}"#,
            ] {
                let res = h.run(msg);
                assert_eq!(res["ok"], false, "{msg} -> {res}");
                assert_eq!(res["error"], "bad_request", "{msg} -> {res}");
            }
            assert!(h.cash_asked.is_empty(), "asked: {:?}", h.cash_asked);
        }

        #[test]
        fn replacing_a_node_says_so_and_restarts_the_ladder() {
            // Two very different things to have just done to a mint you
            // already hold notes at, so the answer distinguishes them.
            let mut h = Harness::new();
            assert_eq!(provision(&mut h, "mint.example")["replaced"], false);
            h.run(r#"{"cmd":"new_secret","host":"mint.example"}"#);
            let again = provision(&mut h, "mint.example");
            assert_eq!(again["replaced"], true);
            assert_eq!(again["next_index"], 0);
            let res = h.run(r#"{"cmd":"new_secret","host":"mint.example"}"#);
            assert_eq!(res["h"], expected_h("mint.example", 0));
        }

        #[test]
        fn the_index_can_be_raised_but_never_lowered() {
            // A wallet that has minted further than this device knows says so
            // here. Lowering is not offered: an index handed out twice is two
            // notes answering to one k1.
            let mut h = Harness::new();
            provision(&mut h, "mint.example");
            let res = h.run(r#"{"cmd":"set_cash_index","host":"mint.example","next_index":9}"#);
            assert_eq!(res["next_index"], 9, "{res}");
            let res = h.run(r#"{"cmd":"set_cash_index","host":"mint.example","next_index":3}"#);
            assert_eq!(res["next_index"], 9, "{res}");
            let res = h.run(r#"{"cmd":"new_secret","host":"mint.example"}"#);
            assert_eq!(res["h"], expected_h("mint.example", 9));
        }

        #[test]
        fn an_index_past_the_ladder_is_refused() {
            let mut h = Harness::new();
            provision(&mut h, "mint.example");
            let res =
                h.run(r#"{"cmd":"set_cash_index","host":"mint.example","next_index":2147483648}"#);
            assert_eq!(res["ok"], false, "{res}");
            assert_eq!(res["error"], "bad_request");
        }

        #[test]
        fn listing_mints_never_shows_the_node() {
            // It is bearer material for every note at that mint, and nothing
            // a client does needs it back.
            let mut h = Harness::new();
            provision(&mut h, "mint.example");
            h.run(r#"{"cmd":"new_secret","host":"mint.example"}"#);
            let res = h.run(r#"{"cmd":"list_cash_mints"}"#);
            let mints = res["mints"].as_array().unwrap();
            assert_eq!(mints.len(), 1);
            assert_eq!(mints[0]["host"], "mint.example");
            assert_eq!(mints[0]["next_index"], 1);
            assert!(!res.to_string().contains(&node_hex("mint.example")));
        }

        #[test]
        fn forgetting_a_mint_needs_no_hold_and_loses_no_note() {
            // It only ever removes an ability. Secrets already held are
            // stored, never re-derived.
            let mut h = Harness::new();
            provision(&mut h, "mint.example");
            let minted = h.run(r#"{"cmd":"new_secret","host":"mint.example"}"#);
            let id = minted["id"].as_str().unwrap().to_string();
            h.cash_asked.clear();

            let res = h.run(r#"{"cmd":"forget_cash_node","host":"mint.example"}"#);
            assert_eq!(res["changed"], true, "{res}");
            assert!(h.cash_asked.is_empty(), "forgetting asked for a hold");
            // the note is still there, and still spendable
            assert_eq!(h.run(r#"{"cmd":"get_info"}"#)["note_count"], 1);
            let res = h.run(&format!(r#"{{"cmd":"list_notes","id":"{id}"}}"#));
            assert_eq!(res["ok"], true, "{res}");
            // but no more can be minted there
            let res = h.run(r#"{"cmd":"new_secret","host":"mint.example"}"#);
            assert_eq!(res["error"], "bad_request");
            // and forgetting twice is not a change
            assert_eq!(
                h.run(r#"{"cmd":"forget_cash_node","host":"mint.example"}"#)["changed"],
                false
            );
        }

        #[test]
        fn two_mints_keep_separate_ladders() {
            // One counter shared across mints would skip indices at both and
            // leave a restore scanning gaps it should never have.
            let mut h = Harness::new();
            provision(&mut h, "mint.example");
            provision(&mut h, "127.0.0.1:8899");
            let a = h.run(r#"{"cmd":"new_secret","host":"mint.example"}"#);
            let b = h.run(r#"{"cmd":"new_secret","host":"127.0.0.1:8899"}"#);
            assert_eq!(a["h"], expected_h("mint.example", 0));
            assert_eq!(b["h"], expected_h("127.0.0.1:8899", 0));
            assert_ne!(a["h"], b["h"]);
        }

        #[test]
        fn the_registry_fills_up_and_says_storage_full() {
            let mut h = Harness::new();
            for i in 0..MAX_CASH_MINTS {
                let host = format!("mint{i}.example");
                assert_eq!(provision(&mut h, &host)["ok"], true);
            }
            let res = provision(&mut h, "one.too.many");
            assert_eq!(res["ok"], false, "{res}");
            assert_eq!(res["error"], "storage_full");
        }
    }

    // ---- the client's tag ----
    //
    // The wire has no request ids. Without a tag, a reply that is never
    // coming is indistinguishable from a slow one, and a late reply from the
    // reply to the next command, so this firmware had to poison a serial
    // session after a timeout (#102). With one, a client keeps the stream open
    // and retires the straggler when it turns up. Same field and same limit as
    // lnurl-vault, because one CLI drives both.

    #[test]
    fn a_tag_comes_back_on_a_success() {
        let mut h = Harness::new();
        let res = h.run(r#"{"cmd":"get_info","tag":"a1"}"#);
        assert_eq!(res["ok"], true);
        assert_eq!(res["tag"], "a1");
    }

    #[test]
    fn a_tag_comes_back_on_an_error_too() {
        // The refusals are what a client most needs matched: an untagged
        // error is a line it cannot attribute to any command it sent.
        let mut h = Harness::new();
        for msg in [
            r#"{"cmd":"nonsense","tag":"a2"}"#,
            r#"{"cmd":"confirm","tag":"a2"}"#,
            r#"{"cmd":"export_secret","id":"deadbeef","tag":"a2"}"#,
        ] {
            let res = h.run(msg);
            assert_eq!(res["ok"], false, "{res}");
            assert_eq!(res["tag"], "a2", "{res}");
        }
    }

    #[test]
    fn a_tag_comes_back_on_a_listing_page() {
        let mut h = Harness::new();
        for _ in 0..10 {
            h.run(r#"{"cmd":"new_secret"}"#);
        }
        let res = h.run(r#"{"cmd":"list_notes","tag":"a3"}"#);
        assert_eq!(res["tag"], "a3");
        assert_eq!(res["next_offset"], LIST_PAGE_MAX);
        let res = h.run(&format!(
            r#"{{"cmd":"list_notes","offset":{LIST_PAGE_MAX},"tag":"a3"}}"#
        ));
        assert_eq!(res["tag"], "a3");
    }

    #[test]
    fn a_tag_survives_the_round_trip_verbatim() {
        // Echoed as given, not re-encoded: a client matches the bytes it sent.
        let mut h = Harness::new();
        for tag in [r#"a " quote"#, "spaces and 🔑", "0", "-"] {
            let msg = serde_json::json!({"cmd": "get_info", "tag": tag}).to_string();
            assert_eq!(h.run(&msg)["tag"], tag);
        }
    }

    #[test]
    fn a_tag_that_cannot_be_echoed_as_given_is_refused() {
        // Truncating or coercing would echo something the client never sent,
        // which is worse than refusing: it would match the wrong reply.
        let mut h = Harness::new();
        let at_limit = "t".repeat(TAG_MAX_LEN);
        assert_eq!(h.run(&format!(r#"{{"cmd":"get_info","tag":"{at_limit}"}}"#))["tag"], at_limit);

        let too_long = "t".repeat(TAG_MAX_LEN + 1);
        for msg in [
            format!(r#"{{"cmd":"get_info","tag":"{too_long}"}}"#),
            r#"{"cmd":"get_info","tag":""}"#.to_string(),
            r#"{"cmd":"get_info","tag":7}"#.to_string(),
            r#"{"cmd":"get_info","tag":null}"#.to_string(),
            r#"{"cmd":"get_info","tag":["a"]}"#.to_string(),
        ] {
            let res = h.run(&msg);
            assert_eq!(res["ok"], false, "{msg} -> {res}");
            assert_eq!(res["error"], "bad_request", "{msg} -> {res}");
            // and the refusal carries no tag, for the same reason
            assert!(res.get("tag").is_none(), "{msg} -> {res}");
        }
    }

    #[test]
    fn a_bad_tag_never_runs_the_command() {
        // Read before anything can answer: a refused tag must not leave a
        // note behind, or a client retrying under a good tag would make two.
        let mut h = Harness::new();
        let too_long = "t".repeat(TAG_MAX_LEN + 1);
        let res = h.run(&format!(r#"{{"cmd":"new_secret","tag":"{too_long}"}}"#));
        assert_eq!(res["error"], "bad_request", "{res}");
        assert_eq!(h.run(r#"{"cmd":"get_info"}"#)["note_count"], 0);
    }

    #[test]
    fn a_tag_does_not_leak_into_the_next_command() {
        let mut h = Harness::new();
        assert_eq!(h.run(r#"{"cmd":"get_info","tag":"a4"}"#)["tag"], "a4");
        assert!(h.run(r#"{"cmd":"get_info"}"#).get("tag").is_none());
    }

    #[test]
    fn an_unparseable_line_is_answered_without_one() {
        // Nothing parsed, so there is no tag to echo - and a client treating
        // an untagged line as the answer to nothing it sent is exactly right.
        let mut h = Harness::new();
        let res = h.run(r#"{"cmd":"get_info","tag":"a5""#);
        assert_eq!(res["error"], "bad_request");
        assert!(res.get("tag").is_none(), "{res}");
    }

    #[test]
    fn a_client_that_sends_no_tags_sees_the_wire_as_before() {
        let mut h = Harness::new();
        let res = h.run(r#"{"cmd":"get_info"}"#);
        assert_eq!(res["ok"], true);
        assert!(res.get("tag").is_none(), "{res}");
    }

    #[test]
    fn get_info_reports_counts_and_storage() {
        let mut h = Harness::new();
        h.confirmed_note();
        h.run(r#"{"cmd":"new_secret"}"#);
        let res = h.run(r#"{"cmd":"get_info"}"#);
        assert_eq!(res["ok"], true);
        assert_eq!(res["note_count"], 2);
        assert_eq!(res["pending_count"], 1);
        assert_eq!(res["storage"], "ok");
        assert_eq!(res["board"], "host");
    }

    #[test]
    fn list_notes_pages_and_never_carries_secrets() {
        let mut h = Harness::new();
        for _ in 0..10 {
            h.run(r#"{"cmd":"new_secret"}"#);
        }
        let res = h.run(r#"{"cmd":"list_notes"}"#);
        assert_eq!(res["total"], 10);
        assert_eq!(res["notes"].as_array().unwrap().len(), LIST_PAGE_MAX);
        assert_eq!(res["next_offset"], LIST_PAGE_MAX);
        // No response field anywhere may carry a secret or hash.
        let text = res.to_string();
        assert!(!text.contains("secret"), "{text}");
        assert!(!text.contains("k1"), "{text}");

        let res = h.run(&format!(r#"{{"cmd":"list_notes","offset":{LIST_PAGE_MAX}}}"#));
        assert_eq!(res["notes"].as_array().unwrap().len(), 2);
        assert!(res.get("next_offset").is_none());
    }

    #[test]
    fn export_asks_with_the_notes_meta_and_returns_k1() {
        let mut h = Harness::new();
        let id = h.confirmed_note();
        let res = h.run(&format!(r#"{{"cmd":"export_secret","id":"{id}"}}"#));
        assert_eq!(res["ok"], true, "{res}");
        assert_eq!(res["k1"].as_str().unwrap().len(), 64);
        assert_eq!(h.asked, vec![(GatedCmd::ExportSecret, id)]);
    }

    #[test]
    fn export_maps_every_refusal_distinctly() {
        let mut h = Harness::new();
        let id = h.confirmed_note();
        for (answer, code) in [
            (Approval::Declined, "user_declined"),
            (Approval::TimedOut, "timeout"),
            (Approval::Unavailable, "display_unavailable"),
        ] {
            h.answer = answer;
            let res = h.run(&format!(r#"{{"cmd":"export_secret","id":"{id}"}}"#));
            assert_eq!(res["ok"], false);
            assert_eq!(res["error"], code);
        }
    }

    #[test]
    fn export_state_errors_never_reach_the_owner() {
        let mut h = Harness::new();
        // A PENDING note cannot export; the owner must not be prompted.
        let res = h.run(r#"{"cmd":"new_secret"}"#);
        let id = res["id"].as_str().unwrap().to_string();
        let res = h.run(&format!(r#"{{"cmd":"export_secret","id":"{id}"}}"#));
        assert_eq!(res["error"], "invalid_state");
        assert!(h.asked.is_empty());
        // Unknown id likewise.
        let res = h.run(r#"{"cmd":"export_secret","id":"00000000"}"#);
        assert_eq!(res["error"], "not_found");
        assert!(h.asked.is_empty());
    }

    #[test]
    fn destructive_commands_are_gated() {
        let mut h = Harness::new();
        let id = h.confirmed_note();
        h.answer = Approval::Declined;
        let res = h.run(&format!(r#"{{"cmd":"mark_spent","id":"{id}"}}"#));
        assert_eq!(res["error"], "user_declined");
        // The note is untouched.
        assert_eq!(h.store.get_meta(&id).unwrap().state, NoteState::Confirmed);

        h.answer = Approval::Approved;
        let res = h.run(&format!(r#"{{"cmd":"mark_spent","id":"{id}"}}"#));
        assert_eq!(res["ok"], true);
        let res = h.run(&format!(r#"{{"cmd":"delete","id":"{id}"}}"#));
        assert_eq!(res["ok"], true);
        assert!(h.store.get_meta(&id).is_none());
        assert_eq!(
            h.asked,
            vec![
                (GatedCmd::MarkSpent, id.clone()),
                (GatedCmd::MarkSpent, id.clone()),
                (GatedCmd::Delete, id)
            ]
        );
    }

    #[test]
    fn wrong_state_never_prompts_for_any_gated_command() {
        let mut h = Harness::new();
        let confirmed = h.confirmed_note();
        let res = h.run(r#"{"cmd":"new_secret"}"#);
        let pending = res["id"].as_str().unwrap().to_string();

        // Each of these could never succeed; the owner must not be asked.
        for msg in [
            format!(r#"{{"cmd":"delete","id":"{confirmed}"}}"#),   // needs SPENT
            format!(r#"{{"cmd":"discard","id":"{confirmed}"}}"#),  // needs PENDING
            format!(r#"{{"cmd":"mark_spent","id":"{pending}"}}"#), // needs CONFIRMED
            format!(r#"{{"cmd":"export_secret","id":"{pending}"}}"#),
        ] {
            let res = h.run(&msg);
            assert_eq!(res["error"], "invalid_state", "{msg}");
        }
        assert!(h.asked.is_empty(), "owner was prompted for a doomed command");
    }

    #[test]
    fn rename_is_gated_and_validates_before_prompting() {
        let mut h = Harness::new();
        let id = h.confirmed_note();
        // Over-long label: refused without a prompt.
        let long = "x".repeat(crate::note_store::MAX_LABEL_LEN + 1);
        let res = h.run(&format!(r#"{{"cmd":"rename","id":"{id}","label":"{long}"}}"#));
        assert_eq!(res["error"], "bad_request");
        assert!(h.asked.is_empty());
        // A declinable rename is declined; an approved one lands.
        h.answer = Approval::Declined;
        let res = h.run(&format!(r#"{{"cmd":"rename","id":"{id}","label":"a"}}"#));
        assert_eq!(res["error"], "user_declined");
        h.answer = Approval::Approved;
        let res = h.run(&format!(r#"{{"cmd":"rename","id":"{id}","label":"b"}}"#));
        assert_eq!(res["ok"], true);
        assert_eq!(h.store.get_meta(&id).unwrap().label, "b");
    }

    #[test]
    fn list_limit_is_clamped() {
        let mut h = Harness::new();
        for _ in 0..10 {
            h.run(r#"{"cmd":"new_secret"}"#);
        }
        // limit 0 clamps up to 1; an absurd limit clamps down to the page max.
        let res = h.run(r#"{"cmd":"list_notes","limit":0}"#);
        assert_eq!(res["notes"].as_array().unwrap().len(), 1);
        let res = h.run(r#"{"cmd":"list_notes","limit":10000}"#);
        assert_eq!(res["notes"].as_array().unwrap().len(), LIST_PAGE_MAX);
    }

    #[test]
    fn full_wallet_flow_over_the_wire() {
        let mut h = Harness::new();
        // Mint: browser pays, preimage imported, then rotated per LUD-25.
        let preimage = "5a".repeat(32);
        let res = h.run(&format!(
            r#"{{"cmd":"import_secret","k1":"{preimage}","host":"mint.example","amount_msat":10000,"label":"mint"}}"#
        ));
        let minted = res["id"].as_str().unwrap().to_string();
        // Import retry converges on the same id.
        let res = h.run(&format!(
            r#"{{"cmd":"import_secret","k1":"{preimage}","host":"evil.example","amount_msat":1,"label":"x"}}"#
        ));
        assert_eq!(res["id"].as_str().unwrap(), minted);

        let res = h.run(&format!(r#"{{"cmd":"new_secret","parent_ids":["{minted}"]}}"#));
        let (rot, h_hex) = (
            res["id"].as_str().unwrap().to_string(),
            res["h"].as_str().unwrap().to_string(),
        );
        assert_eq!(h_hex.len(), 64);
        h.run(&format!(
            r#"{{"cmd":"confirm","id":"{rot}","amount_msat":10000,"host":"mint.example"}}"#
        ));
        h.run(&format!(r#"{{"cmd":"mark_spent","id":"{minted}"}}"#));

        // Spend: split target + change, melt target.
        let res = h.run(&format!(r#"{{"cmd":"export_secret","id":"{rot}"}}"#));
        assert_eq!(res["k1"].as_str().unwrap().len(), 64);
        let res = h.run(&format!(r#"{{"cmd":"new_secret_pair","parent_ids":["{rot}"]}}"#));
        let (tgt, chg) = (
            res["id"].as_str().unwrap().to_string(),
            res["id2"].as_str().unwrap().to_string(),
        );
        assert_ne!(res["h"], res["h2"]);
        h.run(&format!(
            r#"{{"cmd":"confirm","id":"{tgt}","amount_msat":3000,"host":"mint.example"}}"#
        ));
        h.run(&format!(
            r#"{{"cmd":"confirm","id":"{chg}","amount_msat":7000,"host":"mint.example"}}"#
        ));
        h.run(&format!(r#"{{"cmd":"mark_spent","id":"{rot}"}}"#));
        h.run(&format!(r#"{{"cmd":"mark_spent","id":"{tgt}"}}"#));

        // What remains spendable is exactly the change note.
        let res = h.run(r#"{"cmd":"list_notes"}"#);
        let confirmed: Vec<&str> = res["notes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|n| n["state"] == "confirmed")
            .map(|n| n["id"].as_str().unwrap())
            .collect();
        assert_eq!(confirmed, vec![chg.as_str()]);
    }

    #[test]
    fn note_methods_map_onto_the_wire_commands() {
        let cmd = note_cmd_for_method(
            "heartwood_note_confirm",
            &[serde_json::json!({"id":"a1b2c3d4","amount_msat":21000,"host":"mint.example"})]
        )
        .unwrap();
        assert_eq!(cmd["cmd"], "confirm");
        assert_eq!(cmd["amount_msat"], 21000);
        // No params at all is a valid empty command (list with defaults).
        let cmd = note_cmd_for_method("heartwood_note_list", &[]).unwrap();
        assert_eq!(cmd["cmd"], "list_notes");
        // Every advertised method maps, and maps onto a command the
        // dispatcher knows (an unknown one would answer bad_request).
        for method in NOTE_METHODS {
            let cmd = note_cmd_for_method(method, &[]).unwrap();
            assert!(cmd["cmd"].is_string(), "{method}");
        }
    }

    #[test]
    fn note_method_mapping_refuses_cmd_smuggling() {
        // A caller must not redirect a gated method onto an ungated command.
        let cmd = note_cmd_for_method(
            "heartwood_note_export",
            &[serde_json::json!({"cmd":"list_notes","id":"a1b2c3d4"})]
        )
        .unwrap();
        assert_eq!(cmd["cmd"], "export_secret");
        assert_eq!(
            note_cmd_for_method("heartwood_note_frobnicate", &[]),
            Err("unknown note method")
        );
        assert_eq!(
            note_cmd_for_method("heartwood_note_list", &[serde_json::json!(7)]),
            Err("params[0] must be an object")
        );
    }

    #[test]
    fn gated_note_methods_are_pinned_always_button() {
        use crate::nip46::Nip46Method;
        for (method, gated) in [
            ("heartwood_note_export", true),
            ("heartwood_note_spent", true),
            ("heartwood_note_discard", true),
            ("heartwood_note_send", true),
            ("heartwood_note_list", false),
            ("heartwood_note_new", false),
            ("heartwood_note_new_pair", false),
            ("heartwood_note_confirm", false),
            ("heartwood_note_import", false),
        ] {
            assert_eq!(
                Nip46Method::from_str(method).always_requires_button(),
                gated,
                "{method}"
            );
        }
    }


    // ---- #129: a spend mark rides the export hold that just happened ----
    //
    // A collect is `export_secret` then `mark_spent`, and both were gated, so
    // the owner held the button twice for one note. The second hold bought
    // nothing: the mint had already burned the note by then, and the card
    // guards only against a paired client lying "that one is spent". These
    // tests pin what the grant may and may not do.

    #[test]
    fn a_spend_mark_rides_the_export_hold_that_just_happened() {
        let mut h = Harness::new();
        let id = h.confirmed_note();
        h.asked.clear();

        let res = h.run(&format!(r#"{{"cmd":"export_secret","id":"{id}"}}"#));
        assert_eq!(res["ok"], true, "{res}");
        assert!(res["k1"].is_string());
        assert_eq!(h.asked, vec![(GatedCmd::ExportSecret, id.clone())]);

        // The other half of the same collect: no second card.
        let res = h.run(&format!(r#"{{"cmd":"mark_spent","id":"{id}"}}"#));
        assert_eq!(res["ok"], true, "{res}");
        assert_eq!(
            h.asked,
            vec![(GatedCmd::ExportSecret, id.clone())],
            "the spend mark asked again"
        );
        assert!(h.grant.is_empty(), "the grant outlived its one use");
        let list = h.run(r#"{"cmd":"list_notes"}"#);
        assert_eq!(list["notes"][0]["state"], "spent");
    }

    #[test]
    fn a_spend_mark_with_no_grant_asks_exactly_as_before() {
        let mut h = Harness::new();
        let id = h.confirmed_note();
        h.asked.clear();
        let res = h.run(&format!(r#"{{"cmd":"mark_spent","id":"{id}"}}"#));
        assert_eq!(res["ok"], true, "{res}");
        assert_eq!(h.asked, vec![(GatedCmd::MarkSpent, id.clone())]);
    }

    #[test]
    fn the_grant_is_spent_by_the_attempt_not_by_its_success() {
        // Single use, and single use counts FAILURES. A grant left behind by
        // a spend mark that errored would let a client retry its way to a
        // free second write-off long after the owner stopped watching.
        let mut h = Harness::new();
        let id = h.confirmed_note();
        assert_eq!(h.run(&format!(r#"{{"cmd":"export_secret","id":"{id}"}}"#))["ok"], true);
        h.asked.clear();

        h.note_write_ok = false;
        let res = h.run(&format!(r#"{{"cmd":"mark_spent","id":"{id}"}}"#));
        assert_eq!(res["error"], "storage_full", "{res}");
        assert!(h.asked.is_empty(), "a granted spend mark must not ask");
        assert!(h.grant.is_empty(), "a failed attempt still spends the grant");

        h.note_write_ok = true;
        let res = h.run(&format!(r#"{{"cmd":"mark_spent","id":"{id}"}}"#));
        assert_eq!(res["ok"], true, "{res}");
        assert_eq!(h.asked, vec![(GatedCmd::MarkSpent, id.clone())]);
    }

    #[test]
    fn a_grant_never_covers_another_note() {
        let mut h = Harness::new();
        let a = h.confirmed_note();
        let b = h.confirmed_note();
        assert_eq!(h.run(&format!(r#"{{"cmd":"export_secret","id":"{a}"}}"#))["ok"], true);
        h.asked.clear();

        let res = h.run(&format!(r#"{{"cmd":"mark_spent","id":"{b}"}}"#));
        assert_eq!(res["ok"], true, "{res}");
        assert_eq!(h.asked, vec![(GatedCmd::MarkSpent, b.clone())]);
        // ...and b's card did not eat a's grant: that was not the attempt it
        // was minted for.
        let res = h.run(&format!(r#"{{"cmd":"mark_spent","id":"{a}"}}"#));
        assert_eq!(res["ok"], true, "{res}");
        assert_eq!(h.asked.len(), 1, "a's spend mark asked: {:?}", h.asked);
    }

    #[test]
    fn a_grant_never_crosses_to_another_client() {
        // The hold proves a human was present for THAT client's request. A
        // second client riding it would be a card answered on its behalf.
        for other in [GrantClient::Relay([0xc2; 32]), GrantClient::Cable] {
            let mut h = Harness::new();
            let id = h.confirmed_note();
            assert_eq!(h.run(&format!(r#"{{"cmd":"export_secret","id":"{id}"}}"#))["ok"], true);
            h.asked.clear();
            h.client = other;
            let res = h.run(&format!(r#"{{"cmd":"mark_spent","id":"{id}"}}"#));
            assert_eq!(res["ok"], true, "{res}");
            assert_eq!(h.asked, vec![(GatedCmd::MarkSpent, id.clone())], "{other:?}");
        }

        // And the other way round: a cable hold is not a relay client's.
        let mut h = Harness::new();
        h.client = GrantClient::Cable;
        let id = h.confirmed_note();
        assert_eq!(h.run(&format!(r#"{{"cmd":"export_secret","id":"{id}"}}"#))["ok"], true);
        h.asked.clear();
        h.client = GrantClient::Relay([0xc1; 32]);
        let res = h.run(&format!(r#"{{"cmd":"mark_spent","id":"{id}"}}"#));
        assert_eq!(res["ok"], true, "{res}");
        assert_eq!(h.asked, vec![(GatedCmd::MarkSpent, id.clone())]);
    }

    #[test]
    fn a_grant_expires_and_the_card_comes_back() {
        let mut h = Harness::new();
        let id = h.confirmed_note();
        let at = h.now;
        assert_eq!(h.run(&format!(r#"{{"cmd":"export_secret","id":"{id}"}}"#))["ok"], true);
        h.asked.clear();
        h.now = at + SPEND_GRANT_WINDOW_SECS + 1;
        let res = h.run(&format!(r#"{{"cmd":"mark_spent","id":"{id}"}}"#));
        assert_eq!(res["ok"], true, "{res}");
        assert_eq!(h.asked, vec![(GatedCmd::MarkSpent, id.clone())]);

        // The last second inside the window is still inside it.
        let mut h = Harness::new();
        let id = h.confirmed_note();
        let at = h.now;
        assert_eq!(h.run(&format!(r#"{{"cmd":"export_secret","id":"{id}"}}"#))["ok"], true);
        h.asked.clear();
        h.now = at + SPEND_GRANT_WINDOW_SECS;
        let res = h.run(&format!(r#"{{"cmd":"mark_spent","id":"{id}"}}"#));
        assert_eq!(res["ok"], true, "{res}");
        assert!(h.asked.is_empty(), "asked inside the window: {:?}", h.asked);
    }

    #[test]
    fn a_reboot_between_the_two_halves_brings_the_card_back() {
        // Grants are RAM only and never NVS. A board that came back up has
        // no memory of the hold, and must not behave as though it did.
        let mut h = Harness::new();
        let id = h.confirmed_note();
        assert_eq!(h.run(&format!(r#"{{"cmd":"export_secret","id":"{id}"}}"#))["ok"], true);
        h.reboot();
        h.asked.clear();
        let res = h.run(&format!(r#"{{"cmd":"mark_spent","id":"{id}"}}"#));
        assert_eq!(res["ok"], true, "{res}");
        assert_eq!(h.asked, vec![(GatedCmd::MarkSpent, id.clone())]);
    }

    #[test]
    fn an_export_that_was_not_approved_grants_nothing() {
        for answer in [Approval::Declined, Approval::TimedOut, Approval::Unavailable] {
            let mut h = Harness::new();
            let id = h.confirmed_note();
            h.answer = answer;
            let res = h.run(&format!(r#"{{"cmd":"export_secret","id":"{id}"}}"#));
            assert_eq!(res["ok"], false, "{res}");
            assert!(h.grant.is_empty(), "{answer:?} left a grant");

            h.answer = Approval::Approved;
            h.asked.clear();
            let res = h.run(&format!(r#"{{"cmd":"mark_spent","id":"{id}"}}"#));
            assert_eq!(res["ok"], true, "{res}");
            assert_eq!(h.asked, vec![(GatedCmd::MarkSpent, id.clone())], "{answer:?}");
        }
    }

    #[test]
    fn a_grant_covers_the_spend_mark_and_no_other_command() {
        // Forge a live grant against a note in each command's required state:
        // it must still raise that command's own card, and still be there
        // afterwards. A grant that widened to `discard`, `send` or `delete`
        // would answer a question the owner was never shown.
        let mut h = Harness::new();
        let pending = h.run(r#"{"cmd":"new_secret"}"#)["id"].as_str().unwrap().to_string();
        h.grant.grant(&pending, h.client, h.now);
        h.asked.clear();
        assert_eq!(h.run(&format!(r#"{{"cmd":"discard","id":"{pending}"}}"#))["ok"], true);
        assert_eq!(h.asked, vec![(GatedCmd::Discard, pending.clone())]);
        assert_eq!(h.grant.len(), 1, "discard spent the grant");

        let mut h = Harness::new();
        let id = h.confirmed_note();
        h.grant.grant(&id, h.client, h.now);
        h.asked.clear();
        let bob = "bb".repeat(32);
        let res = h.run(&format!(r#"{{"cmd":"send","id":"{id}","to":"{bob}"}}"#));
        assert_eq!(res["ok"], true, "{res}");
        assert_eq!(h.asked, vec![(GatedCmd::Send, id.clone())]);
        assert_eq!(h.grant.len(), 1, "send spent the grant");

        let mut h = Harness::new();
        let id = h.confirmed_note();
        h.grant.grant(&id, h.client, h.now);
        h.asked.clear();
        let res = h.run(&format!(r#"{{"cmd":"rename","id":"{id}","label":"x"}}"#));
        assert_eq!(res["ok"], true, "{res}");
        assert_eq!(h.asked, vec![(GatedCmd::Rename, id.clone())]);
        assert_eq!(h.grant.len(), 1, "rename spent the grant");

        let mut h = Harness::new();
        let id = h.confirmed_note();
        assert_eq!(h.run(&format!(r#"{{"cmd":"mark_spent","id":"{id}"}}"#))["ok"], true);
        h.grant.grant(&id, h.client, h.now);
        h.asked.clear();
        let res = h.run(&format!(r#"{{"cmd":"delete","id":"{id}"}}"#));
        assert_eq!(res["ok"], true, "{res}");
        assert_eq!(h.asked, vec![(GatedCmd::Delete, id.clone())]);
        assert_eq!(h.grant.len(), 1, "delete spent the grant");
    }

    #[test]
    fn every_note_in_a_batch_release_leaves_its_own_grant() {
        // A wallet collecting several notes fires the exports together, which
        // is what lets ONE card answer them all. Each leaves its own grant, so
        // the write-offs that follow cost no second hold.
        let mut h = Harness::new();
        let mut ids = Vec::new();
        for _ in 0..MAX_SPEND_GRANTS {
            ids.push(h.confirmed_note());
        }
        for id in &ids {
            assert_eq!(h.run(&format!(r#"{{"cmd":"export_secret","id":"{id}"}}"#))["ok"], true);
        }
        h.asked.clear();
        for id in &ids {
            let res = h.run(&format!(r#"{{"cmd":"mark_spent","id":"{id}"}}"#));
            assert_eq!(res["ok"], true, "{res}");
        }
        assert!(h.asked.is_empty(), "a batch collect asked again: {:?}", h.asked);
        assert!(h.grant.is_empty());
    }

    #[test]
    fn the_grant_table_is_bounded_and_a_re_export_replaces_rather_than_stacks() {
        let client = GrantClient::Cable;
        let mut g = SpendGrant::new();
        for i in 0..=MAX_SPEND_GRANTS {
            g.grant(&format!("note{i}"), client, 10);
        }
        assert_eq!(g.len(), MAX_SPEND_GRANTS);
        assert!(!g.take("note0", client, 10), "the oldest should have been evicted");
        assert!(g.take(&format!("note{MAX_SPEND_GRANTS}"), client, 10));

        let mut g = SpendGrant::new();
        g.grant("a1b2c3d4", client, 10);
        g.grant("a1b2c3d4", client, 20);
        assert_eq!(g.len(), 1, "one note behind two grants");
        assert!(g.take("a1b2c3d4", client, 20));
        assert!(!g.take("a1b2c3d4", client, 20));
    }

    #[test]
    fn send_seals_on_device_once_and_records_the_recipient() {
        let mut h = Harness::new();
        let id = h.confirmed_note();
        let bob = "bb".repeat(32);
        let res = h.run(&format!(r#"{{"cmd":"send","id":"{id}","to":"{bob}"}}"#));
        assert_eq!(res["ok"], true, "{res}");
        assert_eq!(res["event"]["kind"], 1059);
        // The secret went to the wrap hook and nowhere in the response.
        assert_eq!(h.wrapped.len(), 1);
        assert_eq!(h.wrapped[0].1, [0xbb; 32]);
        assert!(res.get("k1").is_none());
        assert_eq!(h.asked, vec![(GatedCmd::Send, id.clone())]);
        // Listed as sent, still confirmed on the wire.
        let list = h.run(r#"{"cmd":"list_notes"}"#);
        assert_eq!(list["notes"][0]["state"], "confirmed");
        assert_eq!(list["notes"][0]["sent_to"], bob);
        // A second send never reaches the owner.
        let res = h.run(&format!(r#"{{"cmd":"send","id":"{id}","to":"{bob}"}}"#));
        assert_eq!(res["error"], "invalid_state");
        assert_eq!(h.asked.len(), 1);
        assert_eq!(h.wrapped.len(), 1);
        // Unsend path: export still works (gated) so the owner's wallet can
        // rotate the note out from under an unclaimed wrap.
        let res = h.run(&format!(r#"{{"cmd":"export_secret","id":"{id}"}}"#));
        assert_eq!(res["ok"], true);
    }

    #[test]
    fn send_validates_before_prompting_and_needs_a_surface_that_can_seal() {
        let mut h = Harness::new();
        let id = h.confirmed_note();
        for bad in [
            format!(r#"{{"cmd":"send","id":"{id}"}}"#),
            format!(r#"{{"cmd":"send","id":"{id}","to":"abc"}}"#),
            format!(r#"{{"cmd":"send","id":"{id}","to":"{}"}}"#, "zz".repeat(32)),
        ] {
            assert_eq!(h.run(&bad)["error"], "bad_request", "{bad}");
        }
        let res = h.run(&format!(r#"{{"cmd":"send","id":"deadbeef","to":"{}"}}"#, "bb".repeat(32)));
        assert_eq!(res["error"], "not_found");
        // Pending note: state error, no prompt.
        let pending = h.run(r#"{"cmd":"new_secret"}"#)["id"].as_str().unwrap().to_string();
        let res = h.run(&format!(r#"{{"cmd":"send","id":"{pending}","to":"{}"}}"#, "bb".repeat(32)));
        assert_eq!(res["error"], "invalid_state");
        assert!(h.asked.is_empty());
        // Declined: nothing sealed, nothing marked.
        h.answer = Approval::Declined;
        let res = h.run(&format!(r#"{{"cmd":"send","id":"{id}","to":"{}"}}"#, "bb".repeat(32)));
        assert_eq!(res["error"], "user_declined");
        assert!(h.wrapped.is_empty());
        assert!(h.run(r#"{"cmd":"list_notes"}"#)["notes"][0].get("sent_to").is_none());
        // No wrap hook (direct USB): refused before the owner is asked.
        h.answer = Approval::Approved;
        h.can_wrap = false;
        let res = h.run(&format!(r#"{{"cmd":"send","id":"{id}","to":"{}"}}"#, "bb".repeat(32)));
        assert_eq!(res["error"], "bad_request");
        assert_eq!(h.asked.len(), 1);
    }

    #[test]
    fn received_notes_list_their_sender_and_count() {
        let mut h = Harness::new();
        let mut rng = |buf: &mut [u8]| buf.fill(9);
        h.store
            .receive(&mut h.storage, &mut rng, &[5u8; SECRET_LEN], None, "mint.example/w", 3_000, "", &[0xaa; 32], 1, false)
            .unwrap();
        let list = h.run(r#"{"cmd":"list_notes"}"#);
        assert_eq!(list["notes"][0]["state"], "confirmed");
        assert_eq!(list["notes"][0]["from"], "aa".repeat(32));
        assert!(list["notes"][0].get("sent_to").is_none());
        assert_eq!(h.run(r#"{"cmd":"get_info"}"#)["received_count"], 1);
        let id = list["notes"][0]["id"].as_str().unwrap().to_string();
        // Forwarding a received note is refused without a prompt.
        let res = h.run(&format!(r#"{{"cmd":"send","id":"{id}","to":"{}"}}"#, "bb".repeat(32)));
        assert_eq!(res["error"], "invalid_state");
        assert!(h.asked.is_empty());
    }

    #[test]
    fn malformed_input_is_answered_not_dropped() {
        let mut h = Harness::new();
        for msg in [
            "not json",
            "{}",
            r#"{"cmd":"frobnicate"}"#,
            r#"{"cmd":"confirm","id":"x"}"#,
            r#"{"cmd":"new_secret","parent_ids":[7]}"#,
        ] {
            let res = h.run(msg);
            assert_eq!(res["ok"], false, "{msg}");
            assert_eq!(res["error"], "bad_request", "{msg}");
        }
    }

    #[test]
    fn trusting_a_sender_is_gated_once_and_persisted() {
        let mut h = Harness::new();
        let mint = "ab".repeat(32);
        let res = h.run(&format!(r#"{{"cmd":"trust","pubkey":"{mint}"}}"#));
        assert_eq!(res["ok"], true, "{res}");
        assert_eq!(res["changed"], true);
        assert_eq!(h.trust_asked.len(), 1, "one hold to trust");
        assert!(h.trust.contains(&[0xab; 32]));
        assert_eq!(h.storage.trust.as_deref(), Some(h.trust.encode().as_slice()));

        // Again: already trusted, no second hold.
        let res = h.run(&format!(r#"{{"cmd":"trust","pubkey":"{mint}"}}"#));
        assert_eq!(res["changed"], false);
        assert_eq!(h.trust_asked.len(), 1);

        let res = h.run(r#"{"cmd":"list_trusted"}"#);
        assert_eq!(res["trusted"], serde_json::json!([mint]));
        let info = h.run(r#"{"cmd":"get_info"}"#);
        assert_eq!(info["trusted_count"], 1);

        // Withdrawing trust needs no hold.
        let res = h.run(&format!(r#"{{"cmd":"trust","pubkey":"{mint}","remove":true}}"#));
        assert_eq!(res["ok"], true);
        assert_eq!(res["changed"], true);
        assert!(h.trust.is_empty());
        assert_eq!(h.trust_asked.len(), 1);
    }

    #[test]
    fn trust_refuses_a_bad_key_a_declined_hold_and_a_full_list() {
        let mut h = Harness::new();
        assert_eq!(h.run(r#"{"cmd":"trust","pubkey":"abc"}"#)["error"], "bad_request");
        assert_eq!(h.run(r#"{"cmd":"trust"}"#)["error"], "bad_request");
        assert!(h.trust_asked.is_empty(), "nothing askable was asked");

        h.answer = Approval::Declined;
        let res = h.run(&format!(r#"{{"cmd":"trust","pubkey":"{}"}}"#, "cd".repeat(32)));
        assert_eq!(res["error"], "user_declined");
        assert!(h.trust.is_empty());
        assert!(h.storage.trust.is_none(), "a refusal writes nothing");

        h.answer = Approval::Approved;
        for n in 0..crate::trust::MAX_TRUSTED as u8 {
            let res = h.run(&format!(r#"{{"cmd":"trust","pubkey":"{}"}}"#, format!("{n:02x}").repeat(32)));
            assert_eq!(res["ok"], true, "{res}");
        }
        let res = h.run(&format!(r#"{{"cmd":"trust","pubkey":"{}"}}"#, "ff".repeat(32)));
        assert_eq!(res["error"], "bad_request");
        assert_eq!(res["message"], "trust list full");
        // The declined one above, plus the eight that filled it; not the ninth.
        assert_eq!(h.trust_asked.len(), 1 + crate::trust::MAX_TRUSTED, "a full list is refused before the hold");
    }

    #[test]
    fn a_trust_that_cannot_be_persisted_is_not_trusted() {
        let mut h = Harness::new();
        h.persist_ok = false;
        let res = h.run(&format!(r#"{{"cmd":"trust","pubkey":"{}"}}"#, "ee".repeat(32)));
        assert_eq!(res["error"], "storage_full");
        assert!(h.trust.is_empty(), "an unpersisted trust would vanish at reboot and mislead until then");
    }

    #[test]
    fn trust_methods_map_onto_the_wire_commands() {
        let cmd = note_cmd_for_method("heartwood_note_trust", &[serde_json::json!({"pubkey": "ab"})]).unwrap();
        assert_eq!(cmd["cmd"], "trust");
        assert_eq!(cmd["pubkey"], "ab");
        assert_eq!(note_cmd_for_method("heartwood_note_trusted", &[]).unwrap()["cmd"], "list_trusted");
        assert!(NOTE_METHODS.contains(&"heartwood_note_trust"));
        assert!(NOTE_METHODS.contains(&"heartwood_note_trusted"));
    }

    #[test]
    fn a_batch_card_names_the_count_total_and_mint() {
        let notes = [
            BatchNote { amount_msat: 12_000, host: "mint.forgesworn.dev" },
            BatchNote { amount_msat: 104_000, host: "mint.forgesworn.dev" },
            BatchNote { amount_msat: 994_000, host: "mint.forgesworn.dev" },
        ];
        let (head, title) = batch_card("RELEASE NOTE", &notes, None);
        assert_eq!(head, "RELEASE 3 NOTES");
        assert_eq!(title, "1 110 sats @ mint.forgesworn.dev");
        let (head, title) = batch_card("SPEND NOTE", &notes[..2], None);
        assert_eq!(head, "SPEND 2 NOTES");
        assert_eq!(title, "116 sats @ mint.forgesworn.dev");
    }

    #[test]
    fn a_batch_across_mints_says_how_many_mints() {
        let notes = [
            BatchNote { amount_msat: 50_000, host: "a.example" },
            BatchNote { amount_msat: 50_000, host: "b.example" },
            BatchNote { amount_msat: 1_000, host: "a.example" },
        ];
        let (_, title) = batch_card("RELEASE NOTE", &notes, None);
        assert_eq!(title, "101 sats @ 2 mints");
    }

    #[test]
    fn a_batch_send_names_the_recipient_once() {
        let to = "ab".repeat(32);
        let notes = [
            BatchNote { amount_msat: 5_000, host: "a.example" },
            BatchNote { amount_msat: 5_000, host: "a.example" },
        ];
        let (head, title) = batch_card("SEND NOTE", &notes, Some(&to));
        assert_eq!(head, "SEND 2 NOTES");
        assert_eq!(title, "10 sats @ a.example\nto abababab..abababab");
        let (_, title) = batch_card("SEND NOTE", &notes, Some("junk"));
        assert!(title.ends_with("\nto ?"));
    }

    #[test]
    fn a_batch_of_sub_sat_notes_is_not_rounded_to_nothing() {
        let notes = [
            BatchNote { amount_msat: 1_999, host: "a.example" },
            BatchNote { amount_msat: 1_999, host: "a.example" },
            BatchNote { amount_msat: 1_999, host: "a.example" },
        ];
        let (_, title) = batch_card("RELEASE NOTE", &notes, None);
        // Dividing each note by 1000 first and adding those would have said
        // "3 sats" for 5 997 msat, and "0 sats" for any note under one sat.
        assert_eq!(title, "5 997 msat @ a.example");
    }

    #[test]
    fn a_batch_with_an_unknown_note_still_counts_it() {
        // The total can under-state (an unknown amount adds nothing) but the
        // count never does: the owner is told how many holds this one is.
        let notes = [
            BatchNote { amount_msat: 7_000, host: "a.example" },
            BatchNote { amount_msat: 0, host: "" },
        ];
        let (head, title) = batch_card("DISCARD NOTE", &notes, None);
        assert_eq!(head, "DISCARD 2 NOTES");
        assert_eq!(title, "7 sats @ a.example");
    }

    // ---- LUD-25 Part 2 ----

    #[test]
    fn cash_address_hands_out_the_served_identitys_branch() {
        let mut h = Harness::new();
        let res = h.run(r#"{"cmd":"cash_address","host":"moneyer.dev"}"#);
        assert_eq!(res["ok"], true, "{res}");
        let node = crate::cash_key::address_node(&[7u8; 32], "moneyer.dev").unwrap();
        assert_eq!(res["cx1"], crate::cash_key::cx1_of(&node).unwrap());
        assert_eq!(res["pubkey"], hex_encode(&crate::derive::public_key_xonly(&[7u8; 32]).unwrap()));
        // it spends nothing, so nobody was asked
        assert!(h.asked.is_empty());

        for bad in ["", "Moneyer.dev", "moneyer.dev/w", "https://moneyer.dev"] {
            let res = h.run(&format!(r#"{{"cmd":"cash_address","host":"{bad}"}}"#));
            assert_eq!(res["error"], "bad_request", "{bad}");
        }
        h.identity = None;
        let res = h.run(r#"{"cmd":"cash_address","host":"moneyer.dev"}"#);
        assert_eq!(res["error"], "bad_request");
    }

    #[test]
    fn a_claimed_key_note_lists_its_key_and_exports_its_ck1() {
        let mut h = Harness::new();
        let (_, pubkey) = crate::cash_key::claim_note_key(&[7u8; 32], "moneyer.dev", 12, None).unwrap();
        let cp1 = crate::encoding::encode_cp1(&pubkey);
        let claim = format!(
            r#"{{"cmd":"claim_key_note","host":"moneyer.dev/w","index":12,"amount_msat":21000,"p":"{cp1}"}}"#
        );
        let res = h.run(&claim);
        assert_eq!(res["ok"], true, "{res}");
        assert_eq!((res["created"].clone(), res["p"].clone()), (json!(true), json!(cp1)));
        let id = res["id"].as_str().unwrap().to_string();
        // claimed again, it is the same note
        assert_eq!(h.run(&claim)["id"], id.as_str());

        let listed = h.run(r#"{"cmd":"list_notes"}"#);
        let note = &listed["notes"][0];
        assert_eq!((note["p"].clone(), note["index"].clone()), (json!(cp1), json!(12)));
        assert_eq!(note["state"], "confirmed");
        assert!(note.get("from").is_none());

        let res = h.run(&format!(r#"{{"cmd":"export_secret","id":"{id}"}}"#));
        let k1 = res["k1"].as_str().unwrap();
        assert!(k1.starts_with("ck1"), "{k1}");
        let (secret, _) = crate::cash_key::claim_note_key(&[7u8; 32], "moneyer.dev", 12, None).unwrap();
        assert_eq!(k1, crate::cash_key::ck1_of(&secret).unwrap());
        assert!(!k1.contains(&hex_encode(secret.as_ref())));
        assert_eq!(h.asked, vec![(GatedCmd::ExportSecret, id.clone())]);

        // and it is never sealed into a wrap as though its key were a k1
        let res = h.run(&format!(r#"{{"cmd":"send","id":"{id}","to":"{}"}}"#, "bb".repeat(32)));
        assert_eq!(res["error"], "invalid_state");
        assert!(h.wrapped.is_empty());
    }

    #[test]
    fn a_claim_for_a_key_this_device_would_not_derive_is_refused() {
        let mut h = Harness::new();
        let (_, pubkey) = crate::cash_key::claim_note_key(&[7u8; 32], "moneyer.dev", 12, None).unwrap();
        let cp1 = crate::encoding::encode_cp1(&pubkey);
        for (index, host) in [(13, "moneyer.dev/w"), (12, "mint.example/w")] {
            let res = h.run(&format!(
                r#"{{"cmd":"claim_key_note","host":"{host}","index":{index},"amount_msat":1000,"p":"{cp1}"}}"#
            ));
            assert_eq!(res["error"], "bad_request", "{host} {index}");
        }
        for bad in [
            r#"{"cmd":"claim_key_note","host":"moneyer.dev/w","index":4294967296,"amount_msat":1000}"#,
            r#"{"cmd":"claim_key_note","host":"moneyer.dev/w","index":1,"amount_msat":1000,"p":"cp1nope"}"#,
            r#"{"cmd":"claim_key_note","host":"moneyer.dev/w","index":1,"amount_msat":1000,"sig":"CS1"}"#,
            r#"{"cmd":"claim_key_note","host":"Moneyer.dev/w","index":1,"amount_msat":1000}"#,
            r#"{"cmd":"claim_key_note","host":"moneyer.dev/w","amount_msat":1000}"#,
        ] {
            assert_eq!(h.run(bad)["error"], "bad_request", "{bad}");
        }
        assert_eq!(h.store.counts().0, 0);
        h.identity = None;
        let res = h.run(r#"{"cmd":"claim_key_note","host":"moneyer.dev/w","index":1,"amount_msat":1000}"#);
        assert_eq!(res["error"], "bad_request");
    }

    #[test]
    fn the_key_note_methods_map_and_are_not_gated() {
        use crate::nip46::Nip46Method;
        assert_eq!(note_cmd_for_method("heartwood_note_address", &[]).unwrap()["cmd"], "cash_address");
        assert_eq!(note_cmd_for_method("heartwood_note_claim", &[]).unwrap()["cmd"], "claim_key_note");
        for method in ["heartwood_note_address", "heartwood_note_claim"] {
            assert!(NOTE_METHODS.contains(&method));
            let parsed = Nip46Method::from_str(method);
            assert_eq!(parsed.as_str(), method);
            assert!(!parsed.always_requires_button(), "{method}");
        }
    }
}
