// common/src/phone_unlock.rs
//
// The wire half of phone unlock (docs/specs/2026-09-24-phone-unlock-design.md
// sections 2 and 6): what a locked board publishes for each enrolled phone,
// what a phone sends back, and how a phone decides whether to prompt.
//
// The rule behind every choice here: nothing stable about a phone appears on
// the wire. So a lock announcement (kind 24135) carries no `p` tag, only
//
//   ["h", hex(HMAC-SHA256(K, "hint" || author))[..16]]
//
// where `author` is the board's per-boot one-time pubkey, and K is the phone
// key from `data_key::phone_key`. It changes every boot and only a holder of
// K can recognise it. The content is sealed to the same K and author:
//
//   okm      = HKDF-SHA256(salt "heartwood-phone-unlock-v1", ikm K,
//                          info "announce" || author)        -> 64 bytes
//   enc_key  = okm[0..32]      mac_key = okm[32..64]
//   ct       = ChaCha20(enc_key, nonce) XOR json              (IETF, counter 0)
//   tag      = HMAC-SHA256(mac_key, 0x01 || nonce || ct)
//   content  = base64(0x01 || nonce(12) || ct || tag(32))
//
// The JSON is a [`LockContext`]. A phone answers with a kind-24136 event from
// a fresh throwaway key, p-tagged to `author`, whose content is
// NIP-44(throwaway -> author) of a [`Delivery`] `{v, id, s}`. Holding S is the
// proof; the board does not care who authored the delivery.
//
// The same construction carries a relay update when the board's relay list
// changes: `t` is `"relays"` instead of `"locked"`, the author is a fresh
// one-time key per round, and it is posted on the relays the phones were last
// told about. A phone never prompts for it and follows its `relays`. When and
// where it goes: `phone_relays`.
//
// Test vectors: tests/fixtures/phone-unlock-v1.json and
// phone-unlock-v1-relays.json (checked by the tests below and by
// scripts/lib/phone-unlock.test.mjs, an independent implementation in Node's
// own crypto).

use alloc::string::String;
use alloc::vec::Vec;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// Kind of the lock announcement, board -> phone (and board -> operator).
pub const ANNOUNCE_KIND: u64 = 24135;
/// Kind of the unlock delivery, phone -> board (and operator -> board).
pub const DELIVERY_KIND: u64 = 24136;
/// The tag that carries the per-boot hint.
pub const HINT_TAG: &str = "h";
/// Hex characters of the hint: 64 bits, which keeps collisions between
/// unrelated boards negligible for a phone that reads every announcement.
pub const HINT_HEX_LEN: usize = 16;

const HKDF_SALT: &[u8] = b"heartwood-phone-unlock-v1";
const SEALED_VERSION: u8 = 1;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 32;
/// Refuse to open anything larger. A context with eight relays at 64 bytes
/// each and every other field full is well under 1 KiB.
pub const MAX_CONTENT_LEN: usize = 2048;

/// The oldest announcement a phone prompts for. Two announce periods: a phone
/// that was asleep for one still catches the next.
pub const MAX_ANNOUNCE_AGE_SECS: u64 = 120;
/// Tolerance for a board or relay clock that runs ahead of the phone's.
pub const MAX_FUTURE_SKEW_SECS: u64 = 60;

/// What a lock announcement says. Everything here is labelling, not proof: a
/// thief holding the board's flash can write any of it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockContext {
    pub v: u8,
    /// `"locked"`: the board is waiting for an unlock. `"relays"`: the board
    /// is unlocked and telling the phone its relay list changed.
    pub t: String,
    /// The phone record this message is for.
    pub id: u32,
    /// Locked restarts so far on this board. See [`judge`].
    pub boot: u32,
    /// Why the chip restarted, as the board's diagnostics name it
    /// (`power-on`, `brownout`, `task-watchdog`, ...).
    pub reset: String,
    pub ssid: String,
    /// `aa:bb:cc:dd:ee:ff`, or empty if unknown.
    pub bssid: String,
    pub fw: String,
    /// The board's configured relays, so a phone follows relay changes.
    pub relays: Vec<String>,
}

pub const TYPE_LOCKED: &str = "locked";
pub const TYPE_RELAYS: &str = "relays";

#[derive(Debug, PartialEq, Eq)]
pub enum PhoneUnlockError {
    BadEncoding,
    /// Wrong key, wrong author, or tampered.
    NotForUs,
    BadJson,
}

fn content_keys(phone_key: &[u8; 32], author: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(HKDF_SALT), phone_key);
    let mut info = [0u8; 8 + 32];
    info[..8].copy_from_slice(b"announce");
    info[8..].copy_from_slice(author);
    let mut okm = [0u8; 64];
    hk.expand(&info, &mut okm).expect("64 bytes is a valid HKDF-SHA256 length");
    let mut enc = [0u8; 32];
    let mut mac = [0u8; 32];
    enc.copy_from_slice(&okm[..32]);
    mac.copy_from_slice(&okm[32..]);
    okm.zeroize();
    (enc, mac)
}

/// The `h` tag value for `author` under this phone key.
pub fn hint(phone_key: &[u8; 32], author: &[u8; 32]) -> String {
    let mut mac = HmacSha256::new_from_slice(phone_key).expect("HMAC accepts any key length");
    mac.update(b"hint");
    mac.update(author);
    let full = mac.finalize().into_bytes();
    let mut out = String::with_capacity(HINT_HEX_LEN);
    for b in &full[..HINT_HEX_LEN / 2] {
        out.push_str(&alloc::format!("{b:02x}"));
    }
    out
}

/// Constant-time comparison of a received hint with ours.
pub fn hint_matches(phone_key: &[u8; 32], author: &[u8; 32], received: &str) -> bool {
    let ours = hint(phone_key, author);
    if received.len() != ours.len() {
        return false;
    }
    received
        .bytes()
        .zip(ours.bytes())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// Seal a context for one phone. `nonce` must be random and fresh.
pub fn seal_context(
    phone_key: &[u8; 32],
    author: &[u8; 32],
    ctx: &LockContext,
    nonce: &[u8; NONCE_LEN],
) -> String {
    let json = serde_json::to_vec(ctx).expect("a LockContext always serialises");
    seal_bytes(phone_key, author, &json, nonce)
}

fn seal_bytes(phone_key: &[u8; 32], author: &[u8; 32], plain: &[u8], nonce: &[u8; NONCE_LEN]) -> String {
    let (mut enc, mut mk) = content_keys(phone_key, author);
    let mut blob = Vec::with_capacity(1 + NONCE_LEN + plain.len() + TAG_LEN);
    blob.push(SEALED_VERSION);
    blob.extend_from_slice(nonce);
    let ct_at = blob.len();
    blob.extend_from_slice(plain);
    ChaCha20::new((&enc).into(), nonce.into()).apply_keystream(&mut blob[ct_at..]);
    let mut mac = HmacSha256::new_from_slice(&mk).expect("HMAC accepts any key length");
    mac.update(&blob);
    let tag = mac.finalize().into_bytes();
    blob.extend_from_slice(&tag);
    enc.zeroize();
    mk.zeroize();
    B64.encode(blob)
}

/// Open a sealed context. Fails unless it was sealed to this phone key AND
/// this author, so a message cannot be re-posted under another key.
pub fn open_context(
    phone_key: &[u8; 32],
    author: &[u8; 32],
    content: &str,
) -> Result<LockContext, PhoneUnlockError> {
    if content.len() > MAX_CONTENT_LEN {
        return Err(PhoneUnlockError::BadEncoding);
    }
    let blob = B64.decode(content).map_err(|_| PhoneUnlockError::BadEncoding)?;
    if blob.len() < 1 + NONCE_LEN + TAG_LEN || blob[0] != SEALED_VERSION {
        return Err(PhoneUnlockError::BadEncoding);
    }
    let (body, tag) = blob.split_at(blob.len() - TAG_LEN);
    let (mut enc, mut mk) = content_keys(phone_key, author);
    let mut mac = HmacSha256::new_from_slice(&mk).expect("HMAC accepts any key length");
    mac.update(body);
    let ok = mac.verify_slice(tag).is_ok();
    mk.zeroize();
    if !ok {
        enc.zeroize();
        return Err(PhoneUnlockError::NotForUs);
    }
    let nonce: &[u8; NONCE_LEN] = body[1..1 + NONCE_LEN].try_into().expect("length checked");
    let mut plain = body[1 + NONCE_LEN..].to_vec();
    ChaCha20::new((&enc).into(), nonce.into()).apply_keystream(&mut plain);
    enc.zeroize();
    let ctx: LockContext = serde_json::from_slice(&plain).map_err(|_| PhoneUnlockError::BadJson)?;
    if ctx.v != 1 {
        return Err(PhoneUnlockError::BadJson);
    }
    Ok(ctx)
}

/// What a phone sends inside its NIP-44 delivery.
#[derive(Clone, PartialEq, Eq)]
pub struct Delivery {
    pub id: u32,
    pub slot_secret: [u8; 32],
}

impl Drop for Delivery {
    fn drop(&mut self) {
        self.slot_secret.zeroize();
    }
}

impl core::fmt::Debug for Delivery {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Delivery").field("id", &self.id).finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryWire {
    v: u8,
    id: u32,
    s: String,
}

impl Delivery {
    /// `{"v":1,"id":<id>,"s":"<64 hex>"}`.
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in &self.slot_secret {
            s.push_str(&alloc::format!("{b:02x}"));
        }
        let out = alloc::format!("{{\"v\":1,\"id\":{},\"s\":\"{}\"}}", self.id, s);
        s.zeroize();
        out
    }

    /// Strict parse. Anything else is not a phone delivery.
    pub fn parse(json: &str) -> Result<Self, PhoneUnlockError> {
        let mut wire: DeliveryWire = serde_json::from_str(json).map_err(|_| PhoneUnlockError::BadJson)?;
        let out = (|| {
            if wire.v != 1 || wire.s.len() != 64 {
                return None;
            }
            let mut slot_secret = [0u8; 32];
            for (i, chunk) in wire.s.as_bytes().chunks(2).enumerate() {
                let hex = core::str::from_utf8(chunk).ok()?;
                if !hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
                    return None;
                }
                slot_secret[i] = u8::from_str_radix(hex, 16).ok()?;
            }
            Some(Delivery { id: wire.id, slot_secret })
        })();
        wire.s.zeroize();
        out.ok_or(PhoneUnlockError::BadJson)
    }
}

/// Whether a phone should prompt for an announcement it has opened.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Prompt,
    /// The same locked restart it already prompted for (the board repeats
    /// its announcement every 60 s under the same one-time author).
    Duplicate,
    /// Older than [`MAX_ANNOUNCE_AGE_SECS`], or too far in the future.
    Stale,
    /// A lower restart count than one already seen: a replay.
    Replay,
    /// Not a lock announcement (for example a relay-list update).
    NotLocked,
}

/// The phone's prompt rule. `last` is the restart count and one-time author
/// of the newest announcement this phone has already prompted for on this
/// board.
///
/// A repeat is recognised by count AND author: the board repeats its
/// announcement all boot under one author, and every boot has a new one. So
/// a board whose count failed to persist (same count, new author) still gets
/// its prompt, and a lower count is a replay whoever wrote it.
pub fn judge(
    ctx: &LockContext,
    author: &[u8; 32],
    created_at: u64,
    now: u64,
    last: Option<(u32, [u8; 32])>,
) -> Verdict {
    if ctx.t != TYPE_LOCKED {
        return Verdict::NotLocked;
    }
    if created_at.saturating_add(MAX_ANNOUNCE_AGE_SECS) < now
        || created_at > now.saturating_add(MAX_FUTURE_SKEW_SECS)
    {
        return Verdict::Stale;
    }
    match last {
        Some((boot, _)) if ctx.boot < boot => Verdict::Replay,
        Some((boot, seen)) if ctx.boot == boot && seen == *author => Verdict::Duplicate,
        _ => Verdict::Prompt,
    }
}

// ---------------------------------------------------------------------------
// Enrolment
// ---------------------------------------------------------------------------

/// What the board returns for an enrolment: the record id and the hand-off
/// sealed to the phone's one-off enrolment key P. Sapwood relays `sealed`
/// and `ephemeral_pubkey` to the phone without being able to read them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enrolment {
    pub id: u32,
    pub ephemeral_pubkey: [u8; 32],
    pub sealed: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum EnrolError {
    Phone(crate::data_key::PhoneError),
    BadEnrolmentKey,
    NoRelays,
    Crypto(&'static str),
}

/// The plaintext of an enrolment hand-off, as the phone reads it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandOff {
    pub v: u8,
    pub id: u32,
    pub s: String,
    pub relays: Vec<String>,
}

impl Drop for HandOff {
    fn drop(&mut self) {
        self.s.zeroize();
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&alloc::format!("{b:02x}"));
    }
    out
}

/// Enrol a phone: draw its slot secret S and a fresh record id, add the
/// record (K and DK wrapped under S) to `phones`, and seal `{v, id, s, relays}`
/// to the phone's enrolment key P with NIP-44 from a one-off key. P is used
/// for this hand-off only and is not stored. The caller persists `phones`
/// and returns the [`Enrolment`] only once that write has succeeded, so a
/// phone is never handed a secret the board did not keep.
pub fn enrol(
    phones: &mut crate::data_key::PhoneSet,
    dk: &[u8; 32],
    enrol_pubkey: &[u8; 32],
    label: &str,
    relays: &[String],
    rng: &mut dyn FnMut(&mut [u8]),
) -> Result<Enrolment, EnrolError> {
    if relays.is_empty() {
        return Err(EnrolError::NoRelays);
    }
    // The enrolment key must be a real curve point, or the phone could never
    // open the hand-off.
    let mut probe = [0u8; 32];
    rng(&mut probe);
    probe[0] |= 1;
    let probe_ok = crate::nip44::get_conversation_key(&probe, enrol_pubkey).is_ok();
    probe.zeroize();
    if !probe_ok {
        return Err(EnrolError::BadEnrolmentKey);
    }

    let id = loop {
        let mut b = [0u8; 4];
        rng(&mut b);
        let id = u32::from_be_bytes(b);
        if !phones.records().iter().any(|r| r.id == id) {
            break id;
        }
    };
    let mut slot_secret = [0u8; 32];
    rng(&mut slot_secret);
    let mut nonce = [0u8; 12];
    rng(&mut nonce);
    let added = phones.enrol(id, label, &slot_secret, dk, &nonce);
    if let Err(e) = added {
        slot_secret.zeroize();
        return Err(EnrolError::Phone(e));
    }

    let mut ephemeral_sk = [0u8; 32];
    let ephemeral_pubkey = loop {
        rng(&mut ephemeral_sk);
        if let Ok(pk) = crate::derive::public_key_xonly(&ephemeral_sk) {
            break pk;
        }
    };
    let ck = crate::nip44::get_conversation_key(&ephemeral_sk, enrol_pubkey);
    ephemeral_sk.zeroize();
    let mut ck = match ck {
        Ok(ck) => ck,
        Err(e) => {
            slot_secret.zeroize();
            let _ = phones.revoke(id);
            return Err(EnrolError::Crypto(e));
        }
    };
    let relays_json = serde_json::to_string(relays).expect("strings always serialise");
    let mut s_hex = hex_lower(&slot_secret);
    slot_secret.zeroize();
    let plaintext = alloc::format!("{{\"v\":1,\"id\":{id},\"s\":\"{s_hex}\",\"relays\":{relays_json}}}");
    s_hex.zeroize();
    let mut n44 = [0u8; 32];
    rng(&mut n44);
    let sealed = crate::nip44::encrypt_owned(&ck, plaintext, &n44);
    ck.zeroize();
    match sealed {
        Ok(sealed) => Ok(Enrolment { id, ephemeral_pubkey, sealed }),
        Err(e) => {
            let _ = phones.revoke(id);
            Err(EnrolError::Crypto(e))
        }
    }
}

/// The phone's side: open a hand-off with its enrolment secret key.
pub fn open_enrolment(
    enrol_sk: &[u8; 32],
    ephemeral_pubkey: &[u8; 32],
    sealed: &str,
) -> Result<HandOff, PhoneUnlockError> {
    let mut ck = crate::nip44::get_conversation_key(enrol_sk, ephemeral_pubkey)
        .map_err(|_| PhoneUnlockError::NotForUs)?;
    let plain = crate::nip44::decrypt(&ck, sealed);
    ck.zeroize();
    let mut plain = plain.map_err(|_| PhoneUnlockError::NotForUs)?;
    let parsed: Result<HandOff, _> = serde_json::from_str(&plain);
    plain.zeroize();
    let handoff = parsed.map_err(|_| PhoneUnlockError::BadJson)?;
    if handoff.v != 1 || handoff.s.len() != 64 {
        return Err(PhoneUnlockError::BadJson);
    }
    Ok(handoff)
}

// ---------------------------------------------------------------------------
// Management commands (USB frame 0x64, relay management methods)
// ---------------------------------------------------------------------------

/// One phone-unlock management command.
#[derive(Debug, PartialEq, Eq)]
pub enum PhoneCmd {
    /// Needs a press: it adds authority to unlock.
    Enrol { enrol_pubkey: [u8; 32], label: String },
    List,
    /// No press: removing authority is always allowed.
    Revoke { id: u32 },
    SetAnnounceOperator { on: bool },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CmdWire {
    op: String,
    #[serde(default)]
    enrol_pubkey: Option<String>,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    id: Option<u32>,
    #[serde(default)]
    on: Option<bool>,
}

impl PhoneCmd {
    /// `{"op":"enrol","enrol_pubkey":"<64 hex>","label":"Pixel 8"}`,
    /// `{"op":"list"}`, `{"op":"revoke","id":N}`,
    /// `{"op":"set_announce_operator","on":false}`.
    pub fn parse(json: &[u8]) -> Result<Self, &'static str> {
        let w: CmdWire = serde_json::from_slice(json).map_err(|_| "malformed phone-unlock command")?;
        match w.op.as_str() {
            "enrol" => {
                let hex = w.enrol_pubkey.ok_or("enrol needs enrol_pubkey")?;
                let bytes = crate::hex::hex_decode(&hex).map_err(|_| "enrol_pubkey is not hex")?;
                let enrol_pubkey: [u8; 32] =
                    bytes.try_into().map_err(|_| "enrol_pubkey must be 32 bytes")?;
                let label = w.label.unwrap_or_default().trim().into();
                Ok(PhoneCmd::Enrol { enrol_pubkey, label })
            }
            "list" => Ok(PhoneCmd::List),
            "revoke" => Ok(PhoneCmd::Revoke { id: w.id.ok_or("revoke needs id")? }),
            "set_announce_operator" => Ok(PhoneCmd::SetAnnounceOperator {
                on: w.on.ok_or("set_announce_operator needs on")?,
            }),
            _ => Err("unknown phone-unlock op"),
        }
    }
}

/// The `list` answer. Ids and labels only; nothing that unlocks.
pub fn list_json(phones: &crate::data_key::PhoneSet, announce_operator: bool) -> serde_json::Value {
    serde_json::json!({
        "phones": phones
            .records()
            .iter()
            .map(|r| serde_json::json!({ "id": r.id, "label": r.label }))
            .collect::<Vec<_>>(),
        "max": crate::data_key::MAX_PHONES,
        "announce_operator": announce_operator,
    })
}

/// The `revoke` answer: the id, and what the NVS scrub that followed the
/// revocation did (`zeroed`, `pages_skipped`, `complete`). `complete` is what
/// says the revoked record's old bytes are gone from the board's NVS
/// (`crate::nvs_scrub`).
pub fn revoke_json(id: u32, scrub: &crate::nvs_scrub::ScrubReport) -> serde_json::Value {
    serde_json::json!({ "revoked": id, "scrub": scrub.to_json() })
}

/// The `enrol` answer.
pub fn enrolment_json(e: &Enrolment) -> serde_json::Value {
    serde_json::json!({
        "id": e.id,
        "ephemeral_pubkey": hex_lower(&e.ephemeral_pubkey),
        "sealed": e.sealed,
    })
}

// ---------------------------------------------------------------------------
// Relay updates (when and where they go: crate::phone_relays)
// ---------------------------------------------------------------------------
//
// A relay update is a lock announcement in every wire respect: kind 24135, a
// one-time author (fresh per round), one `h` tag, content sealed as above. Only the sealed `t`
// says `"relays"`, which the prompt rule answers with [`Verdict::NotLocked`],
// and which is as long as `"locked"`, so an update is the same size as that
// boot's lock announcements. A phone follows `relays` from any message it
// opens, whatever the verdict.

impl LockContext {
    /// This context as a relay update: every field as it is (so the sealed
    /// size matches this boot's lock announcements), `t` = `"relays"`.
    pub fn as_relay_update(&self) -> LockContext {
        LockContext { t: TYPE_RELAYS.into(), ..self.clone() }
    }
}

/// One phone's message under `author`: the `h` tag value and the sealed
/// content of `shared` with that phone's id. Lock announcements and relay
/// updates both go through here, one phone at a time, so a board never
/// holds every phone's event at once. `nonce` must be random and fresh.
pub fn phone_message(
    rec: &crate::data_key::PhoneRecord,
    shared: &LockContext,
    author: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
) -> (String, String) {
    let ctx = LockContext { id: rec.id, ..shared.clone() };
    (hint(&rec.phone_key, author), seal_context(&rec.phone_key, author, &ctx, nonce))
}

/// [`phone_message`] for every enrolled phone. A board with no phones gets
/// nothing, and a revoked phone has no record, so nothing here is for it.
pub fn per_phone_messages(
    phones: &crate::data_key::PhoneSet,
    shared: &LockContext,
    author: &[u8; 32],
    rng: &mut dyn FnMut(&mut [u8]),
) -> Vec<(String, String)> {
    phones
        .records()
        .iter()
        .map(|rec| {
            let mut nonce = [0u8; NONCE_LEN];
            rng(&mut nonce);
            phone_message(rec, shared, author, &nonce)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_key::phone_key;

    fn ctx() -> LockContext {
        LockContext {
            v: 1,
            t: TYPE_LOCKED.into(),
            id: 7,
            boot: 212,
            reset: "poweron".into(),
            ssid: "devolo-753".into(),
            bssid: "aa:bb:cc:dd:ee:ff".into(),
            fw: "0.18.0-beta.17".into(),
            relays: alloc::vec!["wss://relay.example".into(), "wss://two.example".into()],
        }
    }

    #[test]
    fn a_phone_recognises_and_opens_its_own_announcement_only() {
        let k = phone_key(&[1u8; 32]);
        let other = phone_key(&[2u8; 32]);
        let author = [9u8; 32];
        let h = hint(&k, &author);
        assert_eq!(h.len(), HINT_HEX_LEN);
        assert!(hint_matches(&k, &author, &h));
        assert!(!hint_matches(&other, &author, &h));
        assert!(!hint_matches(&k, &[8u8; 32], &h), "the hint changes with the one-time key");
        assert!(!hint_matches(&k, &author, &h[..15]));

        let content = seal_context(&k, &author, &ctx(), &[3u8; 12]);
        assert_eq!(open_context(&k, &author, &content), Ok(ctx()));
        assert_eq!(open_context(&other, &author, &content), Err(PhoneUnlockError::NotForUs));
        assert_eq!(
            open_context(&k, &[8u8; 32], &content),
            Err(PhoneUnlockError::NotForUs),
            "content is bound to its author"
        );
        assert!(!content.contains("devolo"));
    }

    #[test]
    fn tampered_or_malformed_content_is_refused() {
        let k = phone_key(&[1u8; 32]);
        let author = [9u8; 32];
        let content = seal_context(&k, &author, &ctx(), &[3u8; 12]);
        let mut raw = B64.decode(&content).unwrap();
        for i in 0..raw.len() {
            raw[i] ^= 1;
            assert!(open_context(&k, &author, &B64.encode(&raw)).is_err(), "flip at {i}");
            raw[i] ^= 1;
        }
        assert_eq!(open_context(&k, &author, "not base64!"), Err(PhoneUnlockError::BadEncoding));
        assert_eq!(open_context(&k, &author, ""), Err(PhoneUnlockError::BadEncoding));
        let big = "A".repeat(MAX_CONTENT_LEN + 4);
        assert_eq!(open_context(&k, &author, &big), Err(PhoneUnlockError::BadEncoding));
        // Valid seal, but not a context.
        let junk = seal_bytes(&k, &author, b"{\"v\":1}", &[3u8; 12]);
        assert_eq!(open_context(&k, &author, &junk), Err(PhoneUnlockError::BadJson));
    }

    #[test]
    fn deliveries_round_trip_and_parse_strictly() {
        let d = Delivery { id: 7, slot_secret: [0xAB; 32] };
        let json = d.to_json();
        assert_eq!(Delivery::parse(&json).unwrap(), d);
        assert!(!alloc::format!("{d:?}").contains("ab"), "Debug hides S");
        // Built, not written out: a 64-hex literal reads as a secret to the
        // repository's scanner.
        let s = "ab".repeat(32);
        let upper = s.to_uppercase();
        let not_hex = alloc::format!("z{}", &s[1..]);
        let zeros = "0".repeat(64);
        let cases = [
            alloc::format!(r#"{{"v":2,"id":7,"s":"{s}"}}"#),
            String::from(r#"{"v":1,"id":7,"s":"abab"}"#),
            alloc::format!(r#"{{"v":1,"id":7,"s":"{upper}"}}"#),
            alloc::format!(r#"{{"v":1,"id":7,"s":"{not_hex}"}}"#),
            alloc::format!(r#"{{"v":1,"id":-1,"s":"{s}"}}"#),
            alloc::format!(r#"{{"v":1,"id":7,"s":"{s}","x":1}}"#),
            zeros,
        ];
        for bad in &cases {
            assert!(Delivery::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_prompt_rule() {
        let c = ctx();
        let a = [9u8; 32];
        let b = [8u8; 32];
        let now = 1_800_000_000;
        assert_eq!(judge(&c, &a, now, now, None), Verdict::Prompt);
        assert_eq!(judge(&c, &a, now - 120, now, Some((211, b))), Verdict::Prompt);
        assert_eq!(judge(&c, &a, now - 121, now, None), Verdict::Stale);
        assert_eq!(judge(&c, &a, now + 60, now, None), Verdict::Prompt);
        assert_eq!(judge(&c, &a, now + 61, now, None), Verdict::Stale);
        assert_eq!(judge(&c, &a, now, now, Some((212, a))), Verdict::Duplicate);
        assert_eq!(
            judge(&c, &a, now, now, Some((212, b))),
            Verdict::Prompt,
            "same count, new boot: the count failed to persist"
        );
        assert_eq!(judge(&c, &a, now, now, Some((213, a))), Verdict::Replay);
        let mut r = ctx();
        r.t = TYPE_RELAYS.into();
        assert_eq!(judge(&r, &a, now, now, None), Verdict::NotLocked);
    }

    /// The published vectors. Regenerate only with a deliberate format bump.
    #[test]
    fn fixture_vectors_hold() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/phone-unlock-v1.json"
        ))
        .unwrap();
        let hex32 = |v: &serde_json::Value| -> [u8; 32] {
            let s = v.as_str().unwrap();
            let mut out = [0u8; 32];
            for i in 0..32 {
                out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
            }
            out
        };
        let s = hex32(&fixture["slot_secret"]);
        let k = phone_key(&s);
        assert_eq!(hex32(&fixture["phone_key"]), k);
        let author = hex32(&fixture["author"]);
        assert_eq!(fixture["hint"].as_str().unwrap(), hint(&k, &author));
        let mut nonce = [0u8; 12];
        let n = fixture["nonce"].as_str().unwrap();
        for i in 0..12 {
            nonce[i] = u8::from_str_radix(&n[2 * i..2 * i + 2], 16).unwrap();
        }
        let context: LockContext = serde_json::from_value(fixture["context"].clone()).unwrap();
        assert_eq!(context, ctx());
        let sealed = seal_context(&k, &author, &context, &nonce);
        assert_eq!(fixture["content"].as_str().unwrap(), sealed);
        assert_eq!(open_context(&k, &author, &sealed).unwrap(), context);
        let d = Delivery { id: context.id, slot_secret: s };
        assert_eq!(fixture["delivery"].as_str().unwrap(), d.to_json());
    }

    fn rng_from(seed: u8) -> impl FnMut(&mut [u8]) {
        let mut n = seed;
        move |buf: &mut [u8]| {
            for b in buf.iter_mut() {
                n = n.wrapping_mul(31).wrapping_add(7);
                *b = n;
            }
        }
    }

    #[test]
    fn enrolment_hands_the_phone_a_secret_that_unlocks_and_nothing_else() {
        use crate::data_key::{PhoneSet, PhoneError};
        let dk = [0xD0u8; 32];
        let enrol_sk = [0x42u8; 32];
        let enrol_pk = crate::derive::public_key_xonly(&enrol_sk).unwrap();
        let relays = alloc::vec![String::from("wss://relay.example")];
        let mut phones = PhoneSet::default();
        let e = enrol(&mut phones, &dk, &enrol_pk, "Pixel 8", &relays, &mut rng_from(1)).unwrap();
        assert_eq!(phones.records().len(), 1);
        assert_eq!(phones.records()[0].id, e.id);

        let handoff = open_enrolment(&enrol_sk, &e.ephemeral_pubkey, &e.sealed).unwrap();
        assert_eq!(handoff.id, e.id);
        assert_eq!(handoff.relays, relays);
        let mut s = [0u8; 32];
        for i in 0..32 {
            s[i] = u8::from_str_radix(&handoff.s[2 * i..2 * i + 2], 16).unwrap();
        }
        assert_eq!(phones.unwrap(e.id, &s), Ok(dk));
        assert_eq!(phones.records()[0].phone_key, crate::data_key::phone_key(&s));

        // Nobody else opens the hand-off.
        assert!(open_enrolment(&[0x43u8; 32], &e.ephemeral_pubkey, &e.sealed).is_err());

        // A second enrolment gets a different secret and id.
        let e2 = enrol(&mut phones, &dk, &enrol_pk, "spare", &relays, &mut rng_from(2)).unwrap();
        assert_ne!(e2.id, e.id);
        assert_eq!(phones.unwrap(e2.id, &s), Err(PhoneError::WrongSecret));
    }

    #[test]
    fn enrolment_refuses_cleanly() {
        use crate::data_key::{PhoneError, PhoneSet, MAX_PHONES};
        let dk = [0xD0u8; 32];
        let enrol_pk = crate::derive::public_key_xonly(&[0x42u8; 32]).unwrap();
        let relays = alloc::vec![String::from("wss://relay.example")];
        let mut phones = PhoneSet::default();
        assert_eq!(
            enrol(&mut phones, &dk, &enrol_pk, "x", &[], &mut rng_from(1)),
            Err(EnrolError::NoRelays)
        );
        // x = 0 is not on the curve.
        assert_eq!(
            enrol(&mut phones, &dk, &[0u8; 32], "x", &relays, &mut rng_from(1)),
            Err(EnrolError::BadEnrolmentKey)
        );
        assert_eq!(
            enrol(&mut phones, &dk, &enrol_pk, "seventeen chars!!", &relays, &mut rng_from(1)),
            Err(EnrolError::Phone(PhoneError::LabelTooLong))
        );
        assert!(phones.is_empty(), "a refusal leaves no record");
        for i in 0..MAX_PHONES {
            enrol(&mut phones, &dk, &enrol_pk, "p", &relays, &mut rng_from(i as u8 + 10)).unwrap();
        }
        assert_eq!(
            enrol(&mut phones, &dk, &enrol_pk, "p", &relays, &mut rng_from(99)),
            Err(EnrolError::Phone(PhoneError::Full))
        );
    }

    #[test]
    fn commands_parse_strictly() {
        let pk = "ab".repeat(32);
        assert_eq!(
            PhoneCmd::parse(alloc::format!(r#"{{"op":"enrol","enrol_pubkey":"{pk}","label":" Pixel "}}"#).as_bytes()),
            Ok(PhoneCmd::Enrol { enrol_pubkey: [0xAB; 32], label: "Pixel".into() })
        );
        assert_eq!(PhoneCmd::parse(br#"{"op":"list"}"#), Ok(PhoneCmd::List));
        assert_eq!(PhoneCmd::parse(br#"{"op":"revoke","id":7}"#), Ok(PhoneCmd::Revoke { id: 7 }));
        assert_eq!(
            PhoneCmd::parse(br#"{"op":"set_announce_operator","on":false}"#),
            Ok(PhoneCmd::SetAnnounceOperator { on: false })
        );
        for bad in [
            &br#"{"op":"enrol"}"#[..],
            br#"{"op":"enrol","enrol_pubkey":"abcd"}"#,
            br#"{"op":"revoke"}"#,
            br#"{"op":"revoke","id":-1}"#,
            br#"{"op":"list","extra":1}"#,
            br#"{"op":"reset"}"#,
            b"not json",
        ] {
            assert!(PhoneCmd::parse(bad).is_err(), "{}", core::str::from_utf8(bad).unwrap());
        }
    }

    #[test]
    fn the_list_answer_carries_no_secret() {
        let mut phones = crate::data_key::PhoneSet::default();
        phones.enrol(3, "Pixel", &[1u8; 32], &[2u8; 32], &[0u8; 12]).unwrap();
        let v = list_json(&phones, false);
        assert_eq!(v, serde_json::json!({"phones":[{"id":3,"label":"Pixel"}],"max":16,"announce_operator":false}));
    }

    #[test]
    fn the_revoke_answer_adds_the_scrub_result() {
        let done = crate::nvs_scrub::ScrubReport { zeroed: 9, already_clean: 2, ..Default::default() };
        assert_eq!(
            revoke_json(3, &done),
            serde_json::json!({"revoked":3,"scrub":{"zeroed":9,"pages_skipped":0,"complete":true}})
        );
        let partial = crate::nvs_scrub::ScrubReport { pages_skipped: 1, ..done };
        assert_eq!(revoke_json(3, &partial)["scrub"]["complete"], false);
        // Earlier readers only looked for `revoked`; it is unchanged.
        assert_eq!(revoke_json(3, &partial)["revoked"], 3);
    }

    // --- Relay changes ------------------------------------------------------

    #[test]
    fn a_relay_update_is_never_a_prompt_and_looks_like_a_lock_announcement() {
        assert_eq!(TYPE_RELAYS.len(), TYPE_LOCKED.len(), "the type must not change the size");
        let lock = ctx();
        let update = lock.as_relay_update();
        assert_eq!(update.t, TYPE_RELAYS);
        assert_eq!(LockContext { t: TYPE_LOCKED.into(), ..update.clone() }, lock, "only t differs");

        let k = phone_key(&[1u8; 32]);
        let author = [9u8; 32];
        let sealed_lock = seal_context(&k, &author, &lock, &[3u8; 12]);
        let sealed_update = seal_context(&k, &author, &update, &[3u8; 12]);
        assert_eq!(sealed_lock.len(), sealed_update.len(), "same size on the wire");
        assert_ne!(sealed_lock, sealed_update);
        assert_eq!(open_context(&k, &author, &sealed_update), Ok(update.clone()));

        // Whatever the timing and history, an update never prompts.
        let now = 1_800_000_000;
        for last in [None, Some((0, author)), Some((212, author)), Some((9_999, [1u8; 32]))] {
            for created in [now, now - 500, now + 500] {
                assert_eq!(judge(&update, &author, created, now, last), Verdict::NotLocked);
            }
        }
        // Anything but exactly "locked" is not a lock announcement.
        for t in ["", "Locked", "locked ", "relay", "unlock"] {
            let odd = LockContext { t: t.into(), ..lock.clone() };
            assert_eq!(judge(&odd, &author, now, now, None), Verdict::NotLocked, "{t:?}");
        }
    }

    #[test]
    fn per_phone_messages_use_the_lock_scheme_and_skip_revoked_phones() {
        use crate::data_key::PhoneSet;
        let dk = [0xD0u8; 32];
        let (s1, s2) = ([1u8; 32], [2u8; 32]);
        let mut phones = PhoneSet::default();
        let author = [9u8; 32];
        let shared = ctx().as_relay_update();

        assert!(per_phone_messages(&phones, &shared, &author, &mut rng_from(1)).is_empty(), "no phones, nothing");

        phones.enrol(11, "a", &s1, &dk, &[0u8; 12]).unwrap();
        phones.enrol(22, "b", &s2, &dk, &[1u8; 12]).unwrap();
        let out = per_phone_messages(&phones, &shared, &author, &mut rng_from(1));
        assert_eq!(out.len(), 2);
        for (s, id) in [(s1, 11u32), (s2, 22u32)] {
            let k = phone_key(&s);
            let mine: Vec<_> = out.iter().filter(|(h, _)| hint_matches(&k, &author, h)).collect();
            assert_eq!(mine.len(), 1, "exactly one message is recognisably this phone's");
            let (h, content) = mine[0];
            assert_eq!(h, &hint(&k, &author), "the lock announcements' hint");
            let opened = open_context(&k, &author, content).unwrap();
            assert_eq!(opened, LockContext { id, ..shared.clone() });
        }
        assert!(out.iter().all(|(_, c)| !c.contains("relay.example")));

        // A later round, under a new one-time author, shares no tag with this one.
        let next = per_phone_messages(&phones, &shared, &[8u8; 32], &mut rng_from(2));
        assert!(next.iter().all(|(h, _)| out.iter().all(|(o, _)| o != h)));

        // Revoked: the phone that still holds its secret finds nothing.
        phones.revoke(22).unwrap();
        let out = per_phone_messages(&phones, &shared, &author, &mut rng_from(3));
        assert_eq!(out.len(), 1);
        let k2 = phone_key(&s2);
        assert!(out.iter().all(|(h, c)| !hint_matches(&k2, &author, h) && open_context(&k2, &author, c).is_err()));
    }

    /// The published relay-update vector (tests/fixtures/phone-unlock-v1-relays.json):
    /// the v1 fixture's keys and context with `t` = "relays".
    #[test]
    fn relay_update_vector_holds() {
        let v1: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/phone-unlock-v1.json")).unwrap();
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/phone-unlock-v1-relays.json")).unwrap();
        for key in ["slot_secret", "phone_key", "author", "hint", "nonce"] {
            assert_eq!(fixture[key], v1[key], "{key}");
        }
        let hex = |s: &str| -> Vec<u8> {
            (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
        };
        let k: [u8; 32] = hex(fixture["phone_key"].as_str().unwrap()).try_into().unwrap();
        let author: [u8; 32] = hex(fixture["author"].as_str().unwrap()).try_into().unwrap();
        let nonce: [u8; 12] = hex(fixture["nonce"].as_str().unwrap()).try_into().unwrap();
        let context: LockContext = serde_json::from_value(fixture["context"].clone()).unwrap();
        assert_eq!(context, ctx().as_relay_update());
        let sealed = seal_context(&k, &author, &context, &nonce);
        assert_eq!(fixture["content"].as_str().unwrap(), sealed);
        assert_eq!(sealed.len(), v1["content"].as_str().unwrap().len());
        assert_eq!(judge(&context, &author, 0, 0, None), Verdict::NotLocked);
    }

}
