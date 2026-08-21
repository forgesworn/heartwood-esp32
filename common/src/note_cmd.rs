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
    pub wrap: Option<WrapFn<'a>>,
    /// Senders whose wraps are stored without a hold. Persisted through
    /// `storage.save_trust`; a refusal there is `storage_full`.
    pub trust: &'a mut TrustList,
    /// Asked before a sender is trusted: the card names the key, not a note.
    pub approve_trust: &'a mut dyn FnMut(&[u8; 32]) -> Approval,
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

/// Dispatch one command message (already parsed from its transport frame).
/// Always returns a response object — an unparseable or unknown command is a
/// `bad_request` response, never silence, because the client's only timeout
/// is the long physical-confirm one.
pub fn handle_note_cmd(ctx: &mut NoteCmdContext<'_>, msg: &str) -> Value {
    let cmd: Value = match serde_json::from_str(msg) {
        Ok(v) => v,
        Err(_) => return err_msg("bad_request", "not a JSON object"),
    };
    let Some(name) = str_field(&cmd, "cmd") else {
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
            match ctx.store.new_secret(ctx.storage, ctx.rng, &parents, label, ctx.now) {
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
            match ctx.store.new_secret_pair(ctx.storage, ctx.rng, &parents, label, ctx.now) {
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
            match ctx.store.export_secret(id) {
                Ok(k1) => json!({"ok": true, "k1": k1}),
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
    if let Some(resp) = approval_err((ctx.approve)(kind, &meta)) {
        return resp;
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
pub const NOTE_METHODS: [&str; 11] = [
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
    let total: u64 = notes.iter().map(|n| n.amount_msat / 1000).sum();
    let mut hosts: Vec<&str> = notes.iter().map(|n| n.host).filter(|h| !h.is_empty()).collect();
    hosts.sort_unstable();
    hosts.dedup();
    let first = match hosts.as_slice() {
        [] => format!("{total} sats"),
        [one] => format!("{total} sats @ {one}"),
        many => format!("{total} sats @ {} mints", many.len()),
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
        persist_ok: bool,
    }

    impl MemStorage {
        fn new() -> Self {
            MemStorage { index: None, notes: BTreeMap::new(), trust: None, persist_ok: true }
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
        persist_ok: bool,
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
                persist_ok: true,
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
            self.storage.persist_ok = self.persist_ok;
            let mut ctx = NoteCmdContext {
                store: &mut self.store,
                storage: &mut self.storage,
                rng: &mut rng,
                approve: &mut approve,
                wrap: if self.can_wrap { Some(&mut wrap) } else { None },
                trust: &mut self.trust,
                approve_trust: &mut approve_trust,
                now: 42,
                fw_version: "0.0.0-test",
                board: "host",
                storage_state: "ok",
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
            .receive(&mut h.storage, &mut rng, &[5u8; SECRET_LEN], "mint.example/w", 3_000, &[0xaa; 32], 1, false)
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
        assert_eq!(title, "1110 sats @ mint.forgesworn.dev");
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
}
