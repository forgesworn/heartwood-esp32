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
                let enrol_pubkey = enrol_pubkey_from_hex(&hex)?;
                let label = enrol_label(w.label.as_deref().unwrap_or_default())?;
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

/// A label as the board keeps and shows it: trimmed, and printable ASCII.
/// It is the requester's text, and the enrol card draws it under the request
/// code, so a label that could break a line could draw a code of its own
/// where the owner looks for the real one, and a glyph the fonts cannot draw
/// could hide what it says.
fn enrol_label(raw: &str) -> Result<String, &'static str> {
    // Checked before trimming: `trim` would quietly drop Unicode spaces.
    if !raw.bytes().all(|b| (0x20..=0x7E).contains(&b)) {
        return Err(LABEL_ASCII_ERROR);
    }
    Ok(raw.trim().into())
}

/// Labels are printable ASCII: one line, and nothing the board's fonts
/// would draw as something else.
pub const LABEL_ASCII_ERROR: &str = "label must be printable ASCII (letters, digits, spaces, punctuation)";

fn enrol_pubkey_from_hex(hex: &str) -> Result<[u8; 32], &'static str> {
    let bytes = crate::hex::hex_decode(hex).map_err(|_| "enrol_pubkey is not hex")?;
    bytes.try_into().map_err(|_| "enrol_pubkey must be 32 bytes")
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

/// The `enrol` answer.
pub fn enrolment_json(e: &Enrolment) -> serde_json::Value {
    serde_json::json!({
        "id": e.id,
        "ephemeral_pubkey": hex_lower(&e.ephemeral_pubkey),
        "sealed": e.sealed,
    })
}

// ---------------------------------------------------------------------------
// Enrolment over the relay (kind-24134 management, deferred approval)
// ---------------------------------------------------------------------------
//
// The cable enrols with frame 0x64 {"op":"enrol"}. Over the relay the same
// enrolment is the management method `enrol_unlock_phone`: from the device
// operator only (never a per-identity delegate; a NIP-46 client has no route
// to management at all), behind the one-time mutation challenge like every
// other change, and held on the board's button as a card (#64) rather than
// blocking the relay loop. What comes back is the cable's answer unchanged,
// so the manager (Sapwood, once it supports this) hands it to the phone
// exactly as after a cable enrolment, and the phone cannot tell which way it
// came.
//
// Two codes, both spoken-token tokens of
// HMAC-SHA256(key, utf8(context) || counter_be32), counter 0.
//
//   request code  key = the phone's enrolment key P, FIVE words of the
//                 2048-word list (spoken_words: word i is
//                 uint16_be(digest[2i..2i+2]) % 2048, i in 0..5, from digest
//                 bytes 0..10, so 55 bits). On the board's card BEFORE the
//                 press, and on the phone, which made P: the owner holds only
//                 if the two match. The browser that relayed the request may
//                 show them too, as a convenience, but that proves nothing:
//                 whoever relays the request can swap in a key of their own.
//                 The bound: a compromised browser holds P from the moment the
//                 owner pastes the phone's code, before it sends anything, so
//                 it can grind a key of its own whose words match for as long
//                 as the owner waits for a card. Each try is a key generation
//                 and an HMAC; 55 bits is about 3.6e16 tries, weeks on one GPU
//                 and hours even on a large rented rack, against an owner who
//                 waits minutes. 44 bits was about half an hour on one GPU. A
//                 table built beforehand does not help: P is fresh each time.
//   check code    key = the board's one-off hand-off key, 3 bytes of hex,
//                 shown "ABC 123". On the board after the press, in Sapwood
//                 and on the phone. It confirms delivery and catches mix-ups
//                 (a stale or crossed hand-off); it does NOT prove the board
//                 sent the hand-off the phone holds. The hand-off comes from an
//                 unauthenticated one-off key, so whoever has already swapped
//                 P can grind 24 bits for a hand-off key whose code matches.
//                 The five words are the only defence against a swap. An
//                 authenticated hand-off (the board signing (E, P) with its
//                 paired identity) is a parked follow-up.

/// The management method that adds a phone over the relay.
pub const ENROL_METHOD: &str = "enrol_unlock_phone";
/// Advertised in `get_status.capabilities` by firmware that serves it.
pub const RELAY_ENROL_CAPABILITY: &str = "phone_enrol_relay_v1";
/// spoken-token context of the request code (key: the enrolment key P).
pub const REQUEST_CODE_CONTEXT: &str = "heartwood-unlock:enrol-request";
/// spoken-token context of the check code (key: the hand-off key).
pub const CHECK_CODE_CONTEXT: &str = "heartwood-unlock:enrol-check";
/// How many enrolment keys a board remembers as used this boot.
pub const USED_ENROL_KEYS_MAX: usize = 16;

fn spoken_digest(key: &[u8; 32], context: &str) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(context.as_bytes());
    mac.update(&0u32.to_be_bytes());
    mac.finalize().into_bytes().into()
}

/// How many words the request code has.
pub const REQUEST_CODE_WORDS: usize = 5;

/// The request code's words: spoken-token's
/// `deriveToken(P, 'heartwood-unlock:enrol-request', 0, { format: 'words', count: 5 })`,
/// word i from digest bytes 2i and 2i + 1.
pub fn request_words(enrol_pubkey: &[u8; 32]) -> [&'static str; REQUEST_CODE_WORDS] {
    let digest = spoken_digest(enrol_pubkey, REQUEST_CODE_CONTEXT);
    core::array::from_fn(|i| crate::spoken_words::word_for(&digest[2 * i..2 * i + 2]))
}

/// The code the enrol card shows before the press, from the phone's
/// enrolment key P: five words, space-joined, as spoken-token returns them.
/// The phone that made P shows the same; the owner holds only if they match.
pub fn request_code(enrol_pubkey: &[u8; 32]) -> String {
    request_words(enrol_pubkey).join(" ")
}

/// The code the board, Sapwood and the phone show after the press, from the
/// board's one-off hand-off key: spoken-token hex, 6 characters, "ABC 123".
/// It confirms delivery and catches mix-ups; it cannot prove the board made
/// the hand-off (see the module notes above).
pub fn check_code(ephemeral_pubkey: &[u8; 32]) -> String {
    let d = spoken_digest(ephemeral_pubkey, CHECK_CODE_CONTEXT);
    let hex = alloc::format!("{:02X}{:02X}{:02X}", d[0], d[1], d[2]);
    alloc::format!("{} {}", &hex[..3], &hex[3..])
}

/// How long the enrol card stays up, on the cable and over the relay: half
/// as long again as the 30 s every other card has. The five words are the
/// only defence against a swapped enrolment key, and on the Heltec's 128x64
/// OLED the owner reads them a page at a time and compares each with the
/// phone (bench, 2026-09-25: at 30 s the card went before they had been
/// read; 60 s was then judged too long).
pub const ENROL_CARD_SECS: u32 = 45;

/// How many pages the enrol card steps through: two words a page, so 1 and 2,
/// then 3 and 4, then 5.
pub const ENROL_PAGES: usize = REQUEST_CODE_WORDS.div_ceil(2);

/// How long each page of the enrol card stays up before the next, with no
/// press (a press answers the card).
pub const ENROL_PAGE_SECS: u32 = 4;

/// The least time the enrol card refuses a hold: one full cycle of its pages
/// (12 s). [`EnrolGate`] also waits for every page to have had its full
/// dwell on screen, which a stalled loop can make later still.
pub const ENROL_GATE_MS: u64 = ENROL_PAGES as u64 * ENROL_PAGE_SECS as u64 * 1000;

/// The page an undisturbed enrol card shows `elapsed_secs` whole seconds
/// after it opened (previews and docs). The loops themselves turn pages with
/// [`EnrolGate`], which only moves on from a page that has been on screen for
/// its full dwell.
pub fn enrol_page(elapsed_secs: u32) -> usize {
    (elapsed_secs / ENROL_PAGE_SECS) as usize % ENROL_PAGES
}

/// The longest page marker, in characters.
pub const ENROL_MARKER_MAX_CHARS: usize = 8;

/// Where page `page` sits in the code, drawn beside the countdown: "1-2 of
/// 5", "3-4 of 5", "5 of 5".
pub fn enrol_page_marker(page: usize) -> &'static str {
    match page % ENROL_PAGES {
        0 => "1-2 of 5",
        1 => "3-4 of 5",
        _ => "5 of 5",
    }
}

/// The enrol card's pages and press gate, stepped by both loops (relay.rs
/// `tick_button_card`, `approval::run_enrol_approval_loop` on the cable) every
/// time they look at the card, with the milliseconds since it opened and
/// whether the A button is down. The caller draws the page `step` returns
/// whenever it changes, so the page this holds is the page on screen.
///
/// A page gives way to the next only once it has been on screen for its full
/// `ENROL_PAGE_SECS`, however long the loop took to look again, so a loop
/// that stalls (a relay redial, a WiFi rejoin) cannot skip a page. The card
/// arms, and a hold starts to count, only once every page has had its full
/// dwell, [`ENROL_GATE_MS`] has passed and the button has been seen up since:
/// a hold, or a tap, that began before that never approves or declines
/// anything, and a hold on page 1 alone would rest on two words, 22 bits,
/// which a compromised browser grinds in moments. Armed stays armed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EnrolGate {
    page: usize,
    /// When the page on screen was first drawn; `None` before the first look.
    page_since_ms: Option<u64>,
    /// Pages that have completed a full dwell (at most `ENROL_PAGES`).
    dwelt: usize,
    armed: bool,
}

impl EnrolGate {
    /// One look at the card; returns the page to have on screen.
    pub fn step(&mut self, elapsed_ms: u64, button_down: bool) -> usize {
        let dwell = u64::from(ENROL_PAGE_SECS) * 1000;
        match self.page_since_ms {
            None => self.page_since_ms = Some(elapsed_ms),
            Some(since) if elapsed_ms.saturating_sub(since) >= dwell => {
                self.dwelt = (self.dwelt + 1).min(ENROL_PAGES);
                self.page = (self.page + 1) % ENROL_PAGES;
                self.page_since_ms = Some(elapsed_ms);
            }
            Some(_) => {}
        }
        if self.dwelt >= ENROL_PAGES && elapsed_ms >= ENROL_GATE_MS && !button_down {
            self.armed = true;
        }
        self.page
    }

    /// Something else was drawn over the card and it has just been drawn
    /// again (`elapsed_ms` since it opened): the page on screen starts its
    /// dwell afresh, so time the words were hidden never counts towards the
    /// gate. A card drawn over again and again only expires.
    pub fn restart_page(&mut self, elapsed_ms: u64) {
        if self.page_since_ms.is_some() {
            self.page_since_ms = Some(elapsed_ms);
        }
    }

    /// The page on screen.
    pub fn page(&self) -> usize {
        self.page
    }

    /// Whether a hold now counts.
    pub fn armed(&self) -> bool {
        self.armed
    }
}

/// What one page of the enrol card draws: a top line naming what is asked,
/// with the requester's label in quotes, and below it this page's words, one
/// a line, each with its place in the code (1 to 5). The label never shares a
/// line with a word, and its quotes keep it from reading as words even when
/// it is spelt like them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrolCard {
    pub top: String,
    /// `(place, word)`, place counted from 1, at most two a page.
    pub lines: Vec<(usize, String)>,
}

/// Page `page` of the enrol card for these words and label (a page past the
/// last wraps round). `top_max_chars` is how many small-font characters the
/// top line holds on this panel, clear of the button tags
/// (`Layout::span_chars`: 20 on the Heltec); a label that would overflow it
/// is shortened inside its quotes with "..", since it is only a description
/// (the words are the check). Labels are printable ASCII, so a character is a
/// byte.
pub fn enrol_card(words: &[&str; REQUEST_CODE_WORDS], label: &str, top_max_chars: usize, page: usize) -> EnrolCard {
    // `ADD "` + label + `"?`
    const FRAME: usize = 7;
    let room = top_max_chars.saturating_sub(FRAME);
    let label = if label.len() <= room {
        String::from(label)
    } else {
        alloc::format!("{}..", &label[..room.saturating_sub(2).min(label.len())])
    };
    let first = (page % ENROL_PAGES) * 2;
    EnrolCard {
        top: alloc::format!("ADD \"{label}\"?"),
        lines: (first..(first + 2).min(REQUEST_CODE_WORDS))
            .map(|i| (i + 1, String::from(words[i])))
            .collect(),
    }
}

/// The enrol card's hint line. Before the gate ([`EnrolGate`]) it asks for
/// the comparison and offers no hold: "compare all 5 words". After it, the
/// question that matters, whether the phone shows the same words, ahead of
/// the shortest form of the board's button hint. At most 20 characters, so
/// it fits the Heltec's span clear of its tag. `tags` is `Some(cancel)`
/// where the board labels its buttons on the screen edge (with "NO" when
/// there is a cancel button), `None` where it does not; `button_b` whether a
/// second button cancels; `armed` whether a hold now counts.
pub fn enrol_hint(tags: Option<bool>, button_b: bool, armed: bool) -> &'static str {
    if !armed {
        return "compare all 5 words";
    }
    match (tags, button_b) {
        (Some(true), _) => "on phone? hold YES",
        (Some(false), _) => "on phone? hold PRG",
        (None, true) => "on phone? A=yes B=no",
        (None, false) => "on phone? hold 2s",
    }
}

/// How an enrol card ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CardOutcome {
    Approved,
    Denied,
    Expired,
}

/// What the board shows once an enrol card resolves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnrolResult {
    /// Added, and the answer reached a live relay: the check code, and the
    /// id to revoke if the phone never shows that code.
    Done { id: u32 },
    /// Added, but no live relay took the answer: its secret left nowhere.
    NotSent { id: u32 },
    /// Pressed, but refused at the press: nothing was written.
    NotAdded,
    Declined,
    Expired,
}

impl EnrolResult {
    /// Whether this screen holds the display ([`ResultHold`]): every pressed
    /// outcome does, since each carries something to read or act on.
    pub fn holds(self) -> bool {
        matches!(self, EnrolResult::Done { .. } | EnrolResult::NotSent { .. } | EnrolResult::NotAdded)
    }
}

/// The result screen for a card's outcome: `added` is the id of a record
/// written at the press, `delivered` whether a relay that counted as live at
/// the press took the answer.
pub fn enrol_result(outcome: CardOutcome, added: Option<u32>, delivered: bool) -> EnrolResult {
    match (outcome, added) {
        (CardOutcome::Approved, Some(id)) if delivered => EnrolResult::Done { id },
        (CardOutcome::Approved, Some(id)) => EnrolResult::NotSent { id },
        (CardOutcome::Approved, None) => EnrolResult::NotAdded,
        // A record is only ever written after a press.
        (CardOutcome::Denied, _) => EnrolResult::Declined,
        (CardOutcome::Expired, _) => EnrolResult::Expired,
    }
}

/// How long a result screen keeps the display against anything waiting for
/// it (a relay card queued behind, a cable command that draws its own card):
/// what every result held before it stayed up until a press. Nothing waits
/// longer for the screen than it did then.
pub const RESULT_HOLD_MS: u64 = 20_000;

/// The most a result screen stays up with nothing waiting and no press: long
/// enough to walk to the phone and compare the check code (bench, 2026-09-25:
/// at 20 s the owner had to photograph it), short enough that a board left
/// alone returns to its idle screen.
pub const RESULT_HOLD_MAX_MS: u64 = 300_000;

/// A result screen holding the display: until a fresh press, until something
/// waiting for the screen has let it stand [`RESULT_HOLD_MS`], or at most
/// [`RESULT_HOLD_MAX_MS`]. It arms only once the button has been seen up, so
/// the release of the hold that approved the card cannot dismiss its own
/// result.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResultHold {
    armed: bool,
}

/// What a result hold does on one pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HoldStep {
    Hold,
    Release,
}

impl ResultHold {
    /// Whether a hold that began `elapsed_ms` ago has run its longest. Needs
    /// no button state, so anything that asks whether the screen is taken can
    /// ask it on any pass, whatever the network is doing.
    pub fn expired(elapsed_ms: u64) -> bool {
        elapsed_ms >= RESULT_HOLD_MAX_MS
    }

    /// Whether a hold that began `elapsed_ms` ago gives way to something
    /// waiting for the screen.
    pub fn yields(elapsed_ms: u64) -> bool {
        elapsed_ms >= RESULT_HOLD_MS
    }

    /// Something else took the button over the top of the result (a cable
    /// card, answered by a hold): ignore presses again until the button has
    /// been seen up, so that card's release does not dismiss the result.
    pub fn await_release(&mut self) {
        self.armed = false;
    }

    /// One pass: `button_down` is whether A is held now, `pressed` whether a
    /// press finished since the last pass (A released, or B), `waiting`
    /// whether a card is queued for the screen. Presses seen before the hold
    /// arms are the approving hold's own, and are ignored.
    pub fn step(&mut self, elapsed_ms: u64, button_down: bool, pressed: bool, waiting: bool) -> HoldStep {
        if Self::expired(elapsed_ms) || (waiting && Self::yields(elapsed_ms)) {
            return HoldStep::Release;
        }
        if !self.armed {
            if !button_down {
                self.armed = true;
            }
            return HoldStep::Hold;
        }
        if pressed {
            HoldStep::Release
        } else {
            HoldStep::Hold
        }
    }
}

/// How long after a relay was last heard from it still counts as able to
/// carry an answer: one ping interval plus a grace for the pong's jitter and
/// round trip, so a quiet healthy relay is not taken for a dead one.
pub const ANSWER_LIVE_GRACE_MS: u64 = 10_000;

/// Whether a relay last heard from `since_rx_ms` ago counts as live, for a
/// board that pings every `ping_interval_ms`.
pub fn heard_recently(since_rx_ms: u64, ping_interval_ms: u64) -> bool {
    since_rx_ms < ping_interval_ms.saturating_add(ANSWER_LIVE_GRACE_MS)
}

impl PhoneCmd {
    /// A relay management request as a phone command, or `None` when the
    /// method is not one. `list_unlock_phones`, `revoke_unlock_phone {id}`,
    /// `set_announce_operator {on}` and `enrol_unlock_phone {enrol_pubkey,
    /// label?}`. Enrolment takes no other field: one this firmware does not
    /// understand may be one that matters.
    pub fn from_mgmt(method: &str, params: Option<&serde_json::Value>) -> Option<Result<Self, &'static str>> {
        let field = |name: &str| params.and_then(|p| p.get(name));
        Some(match method {
            "list_unlock_phones" => Ok(PhoneCmd::List),
            "revoke_unlock_phone" => field("id")
                .and_then(|v| v.as_u64())
                .and_then(|v| u32::try_from(v).ok())
                .map(|id| PhoneCmd::Revoke { id })
                .ok_or("revoke_unlock_phone requires params.id"),
            "set_announce_operator" => field("on")
                .and_then(|v| v.as_bool())
                .map(|on| PhoneCmd::SetAnnounceOperator { on })
                .ok_or("set_announce_operator requires params.on"),
            ENROL_METHOD => (|| {
                let hex = field("enrol_pubkey")
                    .and_then(|v| v.as_str())
                    .ok_or("enrol_unlock_phone requires params.enrol_pubkey")?;
                if params
                    .and_then(|p| p.as_object())
                    .is_some_and(|o| o.keys().any(|k| k != "enrol_pubkey" && k != "label"))
                {
                    return Err("enrol_unlock_phone takes only enrol_pubkey and label");
                }
                let enrol_pubkey = enrol_pubkey_from_hex(hex)?;
                let label = match field("label") {
                    None => String::new(),
                    Some(v) => enrol_label(v.as_str().ok_or("label must be a string")?)?,
                };
                Ok(PhoneCmd::Enrol { enrol_pubkey, label })
            })(),
            _ => return None,
        })
    }
}

/// Enrolment keys already answered this boot. A phone makes a fresh one-off
/// key per enrolment, so the same key again is a host resending a command it
/// has already sent (a retrying request helper queued three extra enrols
/// behind one press on 2026-09-24, and the secrets of the records they made
/// were never read). RAM only: after a restart a key that never completed
/// may be tried again, which is harmless, since it completed nothing.
#[derive(Default)]
pub struct UsedEnrolKeys {
    keys: Vec<[u8; 32]>,
}

impl UsedEnrolKeys {
    /// Mark `key` used. False if it already was.
    pub fn claim(&mut self, key: &[u8; 32]) -> bool {
        if self.keys.contains(key) {
            return false;
        }
        if self.keys.len() >= USED_ENROL_KEYS_MAX {
            self.keys.remove(0);
        }
        self.keys.push(*key);
        true
    }
}

/// Why an enrolment was refused. Every refusal adds nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnrolRefusal {
    /// A per-identity delegate asked over the relay.
    NotDeviceOperator,
    /// An enrolment is already waiting on the board's button.
    AnotherPending,
    /// This enrolment key was already used this boot.
    KeyUsed,
    LabelTooLong,
    Locked,
    /// At-rest encryption is off, so there is no data key to wrap.
    NoDataKey,
    NoRelays,
    /// Sixteen phones already.
    Full,
    /// The device operator changed while the card was up.
    OperatorChanged,
    /// The press came with no relay live to carry the answer.
    NoRelaySession,
    /// The answer would not fit the free heap: refused before the record is
    /// written, so nothing is kept that could not be handed over.
    LowMemory,
}

impl EnrolRefusal {
    pub fn message(self) -> String {
        use crate::data_key::{LABEL_MAX, MAX_PHONES};
        match self {
            EnrolRefusal::NotDeviceOperator => {
                alloc::format!("{ENROL_METHOD} is a device-level operation and requires the device operator")
            }
            EnrolRefusal::AnotherPending => "another phone is already waiting for a press on the board".into(),
            EnrolRefusal::KeyUsed => "this enrolment key was already used: start again on the phone".into(),
            EnrolRefusal::LabelTooLong => alloc::format!("label longer than {LABEL_MAX} bytes"),
            EnrolRefusal::Locked => "unlock the board first".into(),
            EnrolRefusal::NoDataKey => "phone unlock opens encrypted storage: set a PIN or vault key first".into(),
            EnrolRefusal::NoRelays => "phone unlock needs WiFi relays configured".into(),
            EnrolRefusal::Full => alloc::format!("{MAX_PHONES} phones already enrolled; revoke one first"),
            EnrolRefusal::OperatorChanged => {
                "the device operator changed while the card was up: nothing was added".into()
            }
            EnrolRefusal::NoRelaySession => "no relay was live to carry the answer: nothing was added".into(),
            EnrolRefusal::LowMemory => "device low on memory: nothing was added, retry shortly".into(),
        }
    }
}

/// What the board knows when it decides whether an enrolment can go ahead.
#[derive(Clone, Copy, Debug)]
pub struct EnrolFacts {
    pub label_len: usize,
    /// Identities present and none still sealed.
    pub unlocked: bool,
    /// This boot holds the data key the phone's record will wrap.
    pub data_key: bool,
    pub relays: bool,
    pub phones: usize,
}

/// The board-state refusals, in the order the cable has always checked them.
/// Asked before any card, and again when the card is pressed.
pub fn enrol_refusal(f: &EnrolFacts) -> Option<EnrolRefusal> {
    if f.label_len > crate::data_key::LABEL_MAX {
        Some(EnrolRefusal::LabelTooLong)
    } else if !f.unlocked {
        Some(EnrolRefusal::Locked)
    } else if !f.data_key {
        Some(EnrolRefusal::NoDataKey)
    } else if !f.relays {
        Some(EnrolRefusal::NoRelays)
    } else if f.phones >= crate::data_key::MAX_PHONES {
        Some(EnrolRefusal::Full)
    } else {
        None
    }
}

/// Who may ask over the relay, before anything else is looked at: the device
/// operator, with no other enrolment waiting on the button. A delegate is
/// refused first, so it learns nothing about the board.
pub fn relay_enrol_gate(device_operator: bool, enrolment_pending: bool) -> Option<EnrolRefusal> {
    if !device_operator {
        Some(EnrolRefusal::NotDeviceOperator)
    } else if enrolment_pending {
        Some(EnrolRefusal::AnotherPending)
    } else {
        None
    }
}

/// What the relay answers when the card queue has no room.
pub const BUSY_ERROR: &str = "signer is busy with another approval; retry shortly";

/// The relay's admission of an `enrol_unlock_phone`, in its fixed order (the
/// one-time mutation challenge is already spent by then, like every
/// mutation's): who is asking, whether another enrolment waits, the request
/// itself, the board, room in the card queue, and last the enrolment key's
/// claim, so no refusal before it burns the phone's code. Each stage runs
/// only if every stage before it passed. The firmware passes its own
/// closures; the host tests pass recording ones.
pub fn admit_relay_enrol<P>(
    device_operator: bool,
    enrolment_pending: bool,
    parse: impl FnOnce() -> Result<P, String>,
    board: impl FnOnce(&P) -> Result<(), String>,
    room: impl FnOnce(&P) -> bool,
    claim: impl FnOnce(&P) -> bool,
) -> Result<P, String> {
    if let Some(refusal) = relay_enrol_gate(device_operator, enrolment_pending) {
        return Err(refusal.message());
    }
    let request = parse()?;
    board(&request)?;
    if !room(&request) {
        return Err(BUSY_ERROR.into());
    }
    if !claim(&request) {
        return Err(EnrolRefusal::KeyUsed.message());
    }
    Ok(request)
}

/// At the press: the operator that asked must still be the device operator,
/// a relay must be live to carry the answer (a record whose hand-off cannot
/// leave would be an orphan), and the board must still be able to enrol.
pub fn relay_enrol_completion(
    operator_current: bool,
    relay_live: bool,
    facts: &EnrolFacts,
) -> Option<EnrolRefusal> {
    if !operator_current {
        Some(EnrolRefusal::OperatorChanged)
    } else if !relay_live {
        Some(EnrolRefusal::NoRelaySession)
    } else {
        enrol_refusal(facts)
    }
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

    // --- Enrolment over the relay -------------------------------------------

    fn good_facts() -> EnrolFacts {
        EnrolFacts { label_len: 7, unlocked: true, data_key: true, relays: true, phones: 0 }
    }

    /// Vectors from spoken-token itself; the check-code pair (2.0.4, hex) is
    /// the one Cambium's EnrolmentTest and scripts/lib/phone-unlock.test.mjs
    /// already pin.
    #[test]
    fn codes_are_spoken_token_hex_tokens() {
        assert_eq!(check_code(&[0xAB; 32]), "9B6 164");
        assert_eq!(check_code(&[0x00; 32]), "EF1 645");
        // Five words, 55 bits, from spoken-token 2.1.0's
        // deriveToken(P, 'heartwood-unlock:enrol-request', 0, { format: 'words', count: 5 }).
        assert_eq!(request_code(&[0xAB; 32]), "swim behind stand bugle female");
        assert_eq!(request_code(&[0x00; 32]), "talent humble reform admit narrow");
        assert_eq!(request_code(&[0x42; 32]), "profit buddy moment aim kitten");
        assert_eq!(request_code(&[0xFF; 32]), "what attitude price easy large");
        assert_eq!(request_words(&[0xAB; 32]), ["swim", "behind", "stand", "bugle", "female"]);
    }

    #[test]
    fn the_enrol_card_keeps_the_words_to_their_own_lines() {
        let words = request_words(&[0xAB; 32]);
        // The Heltec's top line, clear of its "<PRG" tag: 20 small-font
        // characters (firmware/src/layout.rs, `span_chars`, pinned by
        // `text_keeps_clear_of_the_button_tags` in the ui-preview tests).
        const HELTEC_TOP: usize = 20;
        // One word a line, numbered with its place in the code, two lines a
        // page: 1 and 2, then 3 and 4, then 5.
        let line = |n: usize, w: &str| (n, String::from(w));
        assert_eq!(
            enrol_card(&words, "Pixel 8", HELTEC_TOP, 0),
            EnrolCard { top: "ADD \"Pixel 8\"?".into(), lines: vec![line(1, "swim"), line(2, "behind")] }
        );
        assert_eq!(enrol_card(&words, "Pixel 8", HELTEC_TOP, 1).lines, vec![line(3, "stand"), line(4, "bugle")]);
        assert_eq!(enrol_card(&words, "Pixel 8", HELTEC_TOP, 2).lines, vec![line(5, "female")]);
        // A page past the last wraps round rather than drawing nothing.
        assert_eq!(enrol_card(&words, "Pixel 8", HELTEC_TOP, ENROL_PAGES).lines, vec![line(1, "swim"), line(2, "behind")]);
        // Every word appears once across the pages, in order.
        let all: Vec<(usize, String)> =
            (0..ENROL_PAGES).flat_map(|p| enrol_card(&words, "", HELTEC_TOP, p).lines).collect();
        assert_eq!(all, (1..=REQUEST_CODE_WORDS).map(|n| line(n, words[n - 1])).collect::<Vec<_>>());
        assert_eq!(enrol_card(&words, "phone", HELTEC_TOP, 0).top, "ADD \"phone\"?");
        // A long label is shortened inside its quotes on the top line, never
        // wrapped onto a word line; a wide panel shows it whole.
        let long = "Sixteen chars 16";
        assert_eq!(enrol_card(&words, long, HELTEC_TOP, 0).top, "ADD \"Sixteen cha..\"?");
        assert_eq!(enrol_card(&words, long, HELTEC_TOP, 0).top.len(), HELTEC_TOP);
        assert_eq!(enrol_card(&words, long, 29, 0).top, "ADD \"Sixteen chars 16\"?");
        assert_eq!(enrol_card(&words, long, 3, 0).top, "ADD \"..\"?");
        for max in 0..30 {
            let top = enrol_card(&words, long, max, 0).top;
            assert!(top.len() <= max.max(9), "{max}: {top}");
        }
        // Even a label spelt as words is quoted on the top line, so it reads
        // as a name and never as a row of words.
        let card = enrol_card(&words, "stand bugle", HELTEC_TOP, 1);
        assert_eq!(card.lines[0].1, "stand");
        assert_eq!(card.top, "ADD \"stand bugle\"?");
        for (_, word) in &card.lines {
            assert!(!word.contains('"'));
        }

        // A label is the requester's text. One that could break a line could
        // draw words of its own where the owner looks for the real ones, and
        // a glyph the ASCII fonts cannot draw could hide what it says. So:
        // printable ASCII, one line, and always drawn after "for ".
        let pk = "ab".repeat(32);
        for label in [
            "x\nswim behind", "x\rswim", "tab\there", "nul\u{0}", "del\u{7f}", "nel\u{85}x", "Zoë's phone",
            "\u{2028}x", "\u{200b}swim", "ｓｗｉｍ",
        ] {
            let json = serde_json::json!({ "op": "enrol", "enrol_pubkey": pk, "label": label }).to_string();
            assert_eq!(PhoneCmd::parse(json.as_bytes()), Err(LABEL_ASCII_ERROR), "{label:?}");
            let params = serde_json::json!({ "enrol_pubkey": pk, "label": label });
            assert_eq!(PhoneCmd::from_mgmt(ENROL_METHOD, Some(&params)), Some(Err(LABEL_ASCII_ERROR)), "{label:?}");
        }
        for label in ["Pixel 8 Pro", "Zoe's phone", "a-b_c.d/e (1)!", "~"] {
            let params = serde_json::json!({ "enrol_pubkey": pk, "label": label });
            assert!(matches!(PhoneCmd::from_mgmt(ENROL_METHOD, Some(&params)), Some(Ok(_))), "{label:?}");
        }
    }

    #[test]
    fn management_methods_map_onto_the_cable_commands() {
        let pk = "ab".repeat(32);
        let enrol = serde_json::json!({ "enrol_pubkey": pk, "label": " Pixel 8 " });
        assert_eq!(
            PhoneCmd::from_mgmt(ENROL_METHOD, Some(&enrol)),
            Some(Ok(PhoneCmd::Enrol { enrol_pubkey: [0xAB; 32], label: "Pixel 8".into() }))
        );
        let no_label = serde_json::json!({ "enrol_pubkey": pk });
        assert_eq!(
            PhoneCmd::from_mgmt(ENROL_METHOD, Some(&no_label)),
            Some(Ok(PhoneCmd::Enrol { enrol_pubkey: [0xAB; 32], label: String::new() }))
        );
        assert_eq!(PhoneCmd::from_mgmt("list_unlock_phones", None), Some(Ok(PhoneCmd::List)));
        assert_eq!(
            PhoneCmd::from_mgmt("revoke_unlock_phone", Some(&serde_json::json!({ "id": 7 }))),
            Some(Ok(PhoneCmd::Revoke { id: 7 }))
        );
        assert_eq!(
            PhoneCmd::from_mgmt("set_announce_operator", Some(&serde_json::json!({ "on": false }))),
            Some(Ok(PhoneCmd::SetAnnounceOperator { on: false }))
        );
        // The messages the relay has always answered with.
        assert_eq!(
            PhoneCmd::from_mgmt("revoke_unlock_phone", Some(&serde_json::json!({ "id": -1 }))),
            Some(Err("revoke_unlock_phone requires params.id"))
        );
        assert_eq!(
            PhoneCmd::from_mgmt("revoke_unlock_phone", Some(&serde_json::json!({ "id": 4_294_967_296u64 }))),
            Some(Err("revoke_unlock_phone requires params.id"))
        );
        assert_eq!(PhoneCmd::from_mgmt("set_announce_operator", None), Some(Err("set_announce_operator requires params.on")));
        // Enrolment is strict: a field this firmware does not understand may
        // be one that matters, so it is refused rather than ignored.
        for (params, why) in [
            (None, "enrol_unlock_phone requires params.enrol_pubkey"),
            (Some(serde_json::json!({})), "enrol_unlock_phone requires params.enrol_pubkey"),
            (Some(serde_json::json!({ "enrol_pubkey": "abcd" })), "enrol_pubkey must be 32 bytes"),
            (Some(serde_json::json!({ "enrol_pubkey": "zz".repeat(32) })), "enrol_pubkey is not hex"),
            (Some(serde_json::json!({ "enrol_pubkey": 7 })), "enrol_unlock_phone requires params.enrol_pubkey"),
            (Some(serde_json::json!({ "enrol_pubkey": pk, "label": 7 })), "label must be a string"),
            (Some(serde_json::json!({ "enrol_pubkey": pk, "relays": [] })), "enrol_unlock_phone takes only enrol_pubkey and label"),
            (Some(serde_json::json!([pk])), "enrol_unlock_phone requires params.enrol_pubkey"),
        ] {
            assert_eq!(PhoneCmd::from_mgmt(ENROL_METHOD, params.as_ref()), Some(Err(why)), "{params:?}");
        }
        // Anything else is not a phone command at all.
        for method in ["enrol", "unlock_phone_enrol", "get_status", "create_client", ""] {
            assert_eq!(PhoneCmd::from_mgmt(method, None), None, "{method}");
        }
    }

    #[test]
    fn an_enrolment_key_is_used_once_and_the_memory_is_bounded() {
        let mut used = UsedEnrolKeys::default();
        assert!(used.claim(&[1u8; 32]));
        assert!(!used.claim(&[1u8; 32]), "the same key again is a resend");
        for i in 2..=(USED_ENROL_KEYS_MAX as u8) {
            assert!(used.claim(&[i; 32]));
        }
        assert!(!used.claim(&[1u8; 32]), "still remembered at the cap");
        assert!(used.claim(&[0xEE; 32]));
        assert!(used.claim(&[1u8; 32]), "the oldest makes room once the cap is passed");
        assert!(!used.claim(&[0xEE; 32]));
    }

    #[test]
    fn enrolment_is_refused_in_a_fixed_order_and_only_when_it_must_be() {
        assert_eq!(enrol_refusal(&good_facts()), None);
        assert_eq!(
            enrol_refusal(&EnrolFacts { phones: crate::data_key::MAX_PHONES - 1, ..good_facts() }),
            None,
            "the sixteenth phone fits"
        );
        assert_eq!(
            enrol_refusal(&EnrolFacts { phones: crate::data_key::MAX_PHONES, ..good_facts() }),
            Some(EnrolRefusal::Full)
        );
        assert_eq!(
            enrol_refusal(&EnrolFacts { label_len: crate::data_key::LABEL_MAX + 1, ..good_facts() }),
            Some(EnrolRefusal::LabelTooLong)
        );
        assert_eq!(enrol_refusal(&EnrolFacts { unlocked: false, ..good_facts() }), Some(EnrolRefusal::Locked));
        assert_eq!(enrol_refusal(&EnrolFacts { data_key: false, ..good_facts() }), Some(EnrolRefusal::NoDataKey));
        assert_eq!(enrol_refusal(&EnrolFacts { relays: false, ..good_facts() }), Some(EnrolRefusal::NoRelays));
        // A locked board says only that it is locked, whatever else is true.
        let worst = EnrolFacts { label_len: 3, unlocked: false, data_key: false, relays: false, phones: 99 };
        assert_eq!(enrol_refusal(&worst), Some(EnrolRefusal::Locked));
        assert_eq!(
            enrol_refusal(&EnrolFacts { data_key: false, relays: false, phones: 99, ..good_facts() }),
            Some(EnrolRefusal::NoDataKey)
        );
        assert_eq!(enrol_refusal(&EnrolFacts { relays: false, phones: 99, ..good_facts() }), Some(EnrolRefusal::NoRelays));
    }

    #[test]
    fn over_the_relay_only_the_device_operator_asks_and_only_one_waits() {
        assert_eq!(relay_enrol_gate(true, false), None);
        assert_eq!(relay_enrol_gate(true, true), Some(EnrolRefusal::AnotherPending));
        // A delegate learns nothing, not even that a card is up.
        assert_eq!(relay_enrol_gate(false, false), Some(EnrolRefusal::NotDeviceOperator));
        assert_eq!(relay_enrol_gate(false, true), Some(EnrolRefusal::NotDeviceOperator));
    }

    #[test]
    fn a_pressed_card_rechecks_authority_a_relay_and_the_board() {
        assert_eq!(relay_enrol_completion(true, true, &good_facts()), None);
        assert_eq!(relay_enrol_completion(false, true, &good_facts()), Some(EnrolRefusal::OperatorChanged));
        assert_eq!(relay_enrol_completion(false, false, &good_facts()), Some(EnrolRefusal::OperatorChanged));
        assert_eq!(
            relay_enrol_completion(true, false, &good_facts()),
            Some(EnrolRefusal::NoRelaySession),
            "no answer could reach the phone: add nothing rather than an orphan"
        );
        // Whatever changed while the card was up is caught at the press.
        assert_eq!(
            relay_enrol_completion(true, true, &EnrolFacts { data_key: false, ..good_facts() }),
            Some(EnrolRefusal::NoDataKey)
        );
        assert_eq!(
            relay_enrol_completion(true, true, &EnrolFacts { phones: crate::data_key::MAX_PHONES, ..good_facts() }),
            Some(EnrolRefusal::Full)
        );
    }

    #[test]
    fn the_enrol_hint_fits_the_narrowest_span() {
        for tags in [Some(true), Some(false), None] {
            for b in [true, false] {
                for armed in [true, false] {
                    let hint = enrol_hint(tags, b, armed);
                    assert!(hint.len() <= 20, "{hint}");
                }
                assert!(enrol_hint(tags, b, true).starts_with("on phone? "));
            }
        }
    }

    #[test]
    fn the_result_screen_says_done_only_for_an_answer_that_left() {
        use CardOutcome::*;
        assert_eq!(enrol_result(Approved, Some(9), true), EnrolResult::Done { id: 9 });
        assert_eq!(enrol_result(Approved, Some(9), false), EnrolResult::NotSent { id: 9 });
        assert_eq!(enrol_result(Approved, None, true), EnrolResult::NotAdded);
        assert_eq!(enrol_result(Approved, None, false), EnrolResult::NotAdded);
        assert_eq!(enrol_result(Denied, None, false), EnrolResult::Declined);
        assert_eq!(enrol_result(Expired, None, true), EnrolResult::Expired);
        // Every pressed outcome holds the screen; a decline or expiry does not.
        assert!(EnrolResult::Done { id: 1 }.holds());
        assert!(EnrolResult::NotSent { id: 1 }.holds());
        assert!(EnrolResult::NotAdded.holds());
        assert!(!EnrolResult::Declined.holds());
        assert!(!EnrolResult::Expired.holds());
    }

    #[test]
    fn a_result_hold_outlasts_the_approving_press_and_ends_on_a_new_one() {
        // The approving hold is still down when the result appears; its
        // release must not dismiss the screen.
        let mut hold = ResultHold::default();
        assert_eq!(hold.step(0, true, false, false), HoldStep::Hold);
        assert_eq!(hold.step(300, false, true, false), HoldStep::Hold, "the approving hold's own release");
        assert_eq!(hold.step(600, false, false, false), HoldStep::Hold);
        assert_eq!(hold.step(900, true, false, false), HoldStep::Hold, "a new press, still down");
        assert_eq!(hold.step(1_200, false, true, false), HoldStep::Release, "a new press, released");

        // Left alone with nothing waiting, it stays up long past the old
        // 20 s, and ends only at its upper bound, armed or not.
        let mut idle = ResultHold::default();
        assert_eq!(idle.step(0, false, false, false), HoldStep::Hold);
        assert_eq!(idle.step(RESULT_HOLD_MS, false, false, false), HoldStep::Hold);
        assert_eq!(idle.step(120_000, false, false, false), HoldStep::Hold, "two minutes to compare");
        assert_eq!(idle.step(RESULT_HOLD_MAX_MS - 1, false, false, false), HoldStep::Hold);
        assert_eq!(idle.step(RESULT_HOLD_MAX_MS, false, false, false), HoldStep::Release);
        let mut stuck = ResultHold::default();
        assert_eq!(
            stuck.step(RESULT_HOLD_MAX_MS, true, true, false),
            HoldStep::Release,
            "a button held down forever"
        );

        // Another card's approving hold, over the top of a held result, is
        // not a press on the result: after await_release its release is
        // ignored until the button has been seen up.
        let mut interrupted = ResultHold::default();
        assert_eq!(interrupted.step(0, false, false, false), HoldStep::Hold);
        interrupted.await_release();
        assert_eq!(interrupted.step(30_000, true, false, false), HoldStep::Hold);
        assert_eq!(interrupted.step(31_000, false, true, false), HoldStep::Hold, "the other card's release");
        assert_eq!(interrupted.step(32_000, false, true, false), HoldStep::Release, "a fresh press");

        // Expiry needs no button state, so the loop can ask it on any pass.
        assert!(!ResultHold::expired(RESULT_HOLD_MAX_MS - 1));
        assert!(ResultHold::expired(RESULT_HOLD_MAX_MS));
        // A few minutes, not seconds, and never forever.
        const { assert!(RESULT_HOLD_MAX_MS >= 120_000 && RESULT_HOLD_MAX_MS <= 600_000) };
    }

    #[test]
    fn a_waiting_card_takes_over_a_result_after_the_old_hold() {
        // Nothing that waits for the screen waits longer than it did when
        // every result ended at RESULT_HOLD_MS.
        let mut hold = ResultHold::default();
        assert_eq!(hold.step(0, false, false, true), HoldStep::Hold);
        assert_eq!(hold.step(RESULT_HOLD_MS - 1, false, false, true), HoldStep::Hold);
        assert_eq!(hold.step(RESULT_HOLD_MS, false, false, true), HoldStep::Release);
        // Unarmed (the approving hold never let go) still gives way.
        let mut pinned = ResultHold::default();
        assert_eq!(pinned.step(RESULT_HOLD_MS, true, false, true), HoldStep::Release);
        // Something that turns up later takes over at once.
        let mut late = ResultHold::default();
        assert_eq!(late.step(0, false, false, false), HoldStep::Hold);
        assert_eq!(late.step(90_000, false, false, false), HoldStep::Hold);
        assert_eq!(late.step(91_000, false, false, true), HoldStep::Release);
        assert!(!ResultHold::yields(RESULT_HOLD_MS - 1));
        assert!(ResultHold::yields(RESULT_HOLD_MS));
    }

    #[test]
    fn the_enrol_card_shows_every_word_before_it_can_be_approved() {
        // Half as long again as the shared 30 s: long enough to read five
        // words a page at a time and compare them with the phone.
        assert_eq!(ENROL_CARD_SECS, 45);
        assert_eq!(ENROL_PAGES, REQUEST_CODE_WORDS.div_ceil(2));
        // Pages turn on EnrolGate, which both loops step: looked at once a
        // second, page 1 for 0-3 s, page 2 for 4-7, page 3 for 8-11, then
        // round.
        let mut gate = EnrolGate::default();
        let pages: Vec<usize> = (0..ENROL_CARD_SECS).map(|s| gate.step(u64::from(s) * 1000, false)).collect();
        for (second, page) in pages.iter().enumerate() {
            assert_eq!(*page, (second / ENROL_PAGE_SECS as usize) % ENROL_PAGES, "second {second}");
        }
        // Every run lasts the full dwell, bar the last, which the expiry cuts.
        let runs: Vec<&[usize]> = pages.chunk_by(|a, b| a == b).collect();
        assert!(runs[..runs.len() - 1].iter().all(|run| run.len() == ENROL_PAGE_SECS as usize));
        // The gate is exactly one full cycle: all five words have been on
        // screen before a hold can count, and the window leaves more than
        // 30 s to hold after it, while every page comes round twice more.
        assert_eq!(ENROL_GATE_MS, u64::from(ENROL_PAGE_SECS) * ENROL_PAGES as u64 * 1000);
        let gate_secs = (ENROL_GATE_MS / 1000) as usize;
        let before: Vec<usize> = pages[..gate_secs].to_vec();
        for page in 0..ENROL_PAGES {
            assert!(before.contains(&page), "page {page} before the gate");
            let after = pages[gate_secs..]
                .chunk_by(|a, b| a == b)
                .filter(|run| run[0] == page && run.len() == ENROL_PAGE_SECS as usize)
                .count();
            assert!(after >= 2, "page {page} shown {after} full times after the gate");
        }
        assert!(ENROL_CARD_SECS as usize - gate_secs > 30);
        // Never a page out of range, however long.
        let mut long = EnrolGate::default();
        for ms in [0, 1, 11_000, 12_000, 44_000, 45_000, 1_000_000, u64::MAX] {
            assert!(long.step(ms, false) < ENROL_PAGES);
        }
    }

    #[test]
    fn no_hold_that_starts_before_the_gate_approves_the_enrol_card() {
        let dwell = u64::from(ENROL_PAGE_SECS) * 1000;
        // A loop that looks every second: pages turn after their full dwell
        // and the card arms as the third page's dwell completes, at 12 s.
        let mut g = EnrolGate::default();
        let mut pages = Vec::new();
        for second in 0..=12u64 {
            pages.push(g.step(second * 1000, false));
            assert_eq!(g.armed(), second >= 12, "second {second}");
        }
        assert_eq!(pages, [0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 0]);
        assert!(g.step(20_000, true) == g.page() && g.armed(), "armed stays armed: a hold from here counts");

        // A short press during the gate is harmless: ignored, not a decline,
        // and the card still arms once the button is up after the gate.
        let mut tap = EnrolGate::default();
        for ms in (0..=12_000).step_by(500) {
            tap.step(ms, (3_000..3_400).contains(&ms));
        }
        assert!(tap.armed());

        // A hold that starts before the gate never counts, however long it
        // runs past it; only a fresh press after it can.
        let mut early = EnrolGate::default();
        for ms in (0..=15_000).step_by(1_000) {
            early.step(ms, ms >= 10_000);
            assert!(!early.armed(), "{ms}: still the hold that began at 10 s");
        }
        early.step(15_100, false);
        assert!(early.armed());

        // The loop stalls (a redial, a WiFi rejoin) with page 1 on screen:
        // page 1 has had its dwell, but pages 2 and 3 were never drawn, so
        // the gate stays shut however much time has passed, and each page
        // still gets its full dwell once the loop is back.
        let mut stalled = EnrolGate::default();
        assert_eq!(stalled.step(0, false), 0);
        assert_eq!(stalled.step(20_000, false), 1, "page 1 was on screen throughout");
        assert!(!stalled.armed(), "20 s gone, but pages 2 and 3 never shown");
        assert_eq!(stalled.step(20_000 + dwell - 1, false), 1);
        assert_eq!(stalled.step(20_000 + dwell, false), 2);
        assert!(!stalled.armed());
        assert_eq!(stalled.step(40_000, false), 0);
        assert!(stalled.armed(), "every page has now had its full dwell");

        // Something else drew over the card (a confirmation, a status):
        // the page on screen starts its dwell again once the card is back,
        // so time spent hidden never counts as time read.
        let mut hidden = EnrolGate::default();
        hidden.step(0, false);
        hidden.step(3_000, false);
        hidden.restart_page(3_500);
        assert_eq!(hidden.step(4_000, false), 0, "page 1 was hidden from 3 s");
        assert_eq!(hidden.step(7_499, false), 0);
        assert_eq!(hidden.step(7_500, false), 1, "a full dwell after it came back");
        // Drawn over every second, the card never arms: it only expires.
        let mut flooded = EnrolGate::default();
        for ms in (0..=45_000).step_by(1_000) {
            flooded.step(ms, false);
            flooded.restart_page(ms);
        }
        assert!(!flooded.armed());
        assert_eq!(flooded.page(), 0);

        // A page is never skipped, whatever the gap between looks.
        let mut jumpy = EnrolGate::default();
        let seen: Vec<usize> = [0, 9_000, 9_100, 30_000, 30_100, 45_000].iter().map(|ms| jumpy.step(*ms, false)).collect();
        assert_eq!(seen, [0, 1, 1, 2, 2, 0]);
    }

    #[test]
    fn the_enrol_card_says_where_it_is_and_when_it_can_be_held() {
        assert_eq!(enrol_page_marker(0), "1-2 of 5");
        assert_eq!(enrol_page_marker(1), "3-4 of 5");
        assert_eq!(enrol_page_marker(2), "5 of 5");
        assert_eq!(enrol_page_marker(ENROL_PAGES), "1-2 of 5");
        for page in 0..ENROL_PAGES {
            assert!(enrol_page_marker(page).len() <= ENROL_MARKER_MAX_CHARS);
        }
        // Before the gate the hint asks for the comparison and offers no hold.
        for tags in [Some(true), Some(false), None] {
            for b in [true, false] {
                let waiting = enrol_hint(tags, b, false);
                assert_eq!(waiting, "compare all 5 words");
                assert!(!waiting.contains("hold") && !waiting.contains("yes"));
                assert!(enrol_hint(tags, b, true).starts_with("on phone? "));
            }
        }
    }

    #[test]
    fn a_quiet_healthy_relay_still_counts_as_live() {
        let ping = 20_000;
        // A pong lands a little after each ping interval.
        assert!(heard_recently(0, ping));
        assert!(heard_recently(ping + 3_000, ping), "pong after jitter and a round trip");
        assert!(heard_recently(ping + ANSWER_LIVE_GRACE_MS - 1, ping));
        assert!(!heard_recently(ping + ANSWER_LIVE_GRACE_MS, ping));
        assert!(!heard_recently(u64::MAX, ping));
    }

    /// The relay's order: the challenge is spent before this runs (every
    /// mutation's, handle_mgmt_event in relay.rs, pinned by the mgmt test that
    /// enrol_unlock_phone requires one); then who is asking, then the request,
    /// then the board, then room in the queue, and only then is the key
    /// claimed, so no refusal burns the phone's code.
    #[test]
    fn a_relay_enrolment_claims_its_key_last() {
        use core::cell::RefCell;
        let trace = RefCell::new(Vec::<&str>::new());
        let run = |operator: bool, pending: bool, parses: bool, board: bool, room: bool, fresh: bool| {
            trace.borrow_mut().clear();
            let out = admit_relay_enrol(
                operator,
                pending,
                || {
                    trace.borrow_mut().push("parse");
                    if parses { Ok(7u8) } else { Err("bad".to_string()) }
                },
                |p: &u8| {
                    assert_eq!(*p, 7);
                    trace.borrow_mut().push("board");
                    if board { Ok(()) } else { Err("locked".to_string()) }
                },
                |_: &u8| {
                    trace.borrow_mut().push("room");
                    room
                },
                |_: &u8| {
                    trace.borrow_mut().push("claim");
                    fresh
                },
            );
            (out, trace.borrow().clone())
        };
        assert_eq!(run(true, false, true, true, true, true), (Ok(7), vec!["parse", "board", "room", "claim"]));
        // A delegate: nothing else is even looked at.
        let (out, steps) = run(false, true, true, true, true, true);
        assert_eq!(out, Err(EnrolRefusal::NotDeviceOperator.message()));
        assert!(steps.is_empty());
        let (out, steps) = run(true, true, true, true, true, true);
        assert_eq!(out, Err(EnrolRefusal::AnotherPending.message()));
        assert!(steps.is_empty());
        // Every refusal before the claim leaves the key unclaimed.
        assert_eq!(run(true, false, false, true, true, true), (Err("bad".into()), vec!["parse"]));
        assert_eq!(run(true, false, true, false, true, true), (Err("locked".into()), vec!["parse", "board"]));
        assert_eq!(
            run(true, false, true, true, false, true),
            (Err(BUSY_ERROR.into()), vec!["parse", "board", "room"])
        );
        assert_eq!(
            run(true, false, true, true, true, false),
            (Err(EnrolRefusal::KeyUsed.message()), vec!["parse", "board", "room", "claim"])
        );
    }

    #[test]
    fn refusal_messages_are_distinct_and_keep_the_cable_wording() {
        use EnrolRefusal::*;
        let all = [
            NotDeviceOperator, AnotherPending, KeyUsed, LabelTooLong, Locked, NoDataKey, NoRelays, Full,
            OperatorChanged, NoRelaySession, LowMemory,
        ];
        let messages: Vec<String> = all.iter().map(|r| r.message()).collect();
        for (i, m) in messages.iter().enumerate() {
            assert!(!m.is_empty());
            assert!(messages.iter().skip(i + 1).all(|n| n != m), "{m}");
        }
        // What the cable path has always said, which Sapwood shows as is.
        assert_eq!(KeyUsed.message(), "this enrolment key was already used: start again on the phone");
        assert_eq!(LabelTooLong.message(), "label longer than 16 bytes");
        assert_eq!(Locked.message(), "unlock the board first");
        assert_eq!(NoDataKey.message(), "phone unlock opens encrypted storage: set a PIN or vault key first");
        assert_eq!(NoRelays.message(), "phone unlock needs WiFi relays configured");
        assert_eq!(Full.message(), "16 phones already enrolled; revoke one first");
        assert_eq!(
            NotDeviceOperator.message(),
            "enrol_unlock_phone is a device-level operation and requires the device operator"
        );
    }

    /// The enrol answer is what crosses the relay (inside the operator's NIP-44)
    /// and what Sapwood republishes to the phone: nothing in it names the
    /// phone, its label or its enrolment key.
    #[test]
    fn the_enrol_answer_names_neither_the_phone_nor_its_enrolment_key() {
        use crate::data_key::PhoneSet;
        let enrol_sk = [0x42u8; 32];
        let enrol_pk = crate::derive::public_key_xonly(&enrol_sk).unwrap();
        let relays = alloc::vec![String::from("wss://relay.example")];
        let mut phones = PhoneSet::default();
        let e = enrol(&mut phones, &[0xD0; 32], &enrol_pk, "Pixel 8", &relays, &mut rng_from(5)).unwrap();
        let answer = enrolment_json(&e).to_string();
        assert!(!answer.contains("Pixel"));
        assert!(!answer.contains(&hex_lower(&enrol_pk)));
        let json = enrolment_json(&e);
        let keys: Vec<&String> = json.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["ephemeral_pubkey", "id", "sealed"]);
        // The code the board shows after the press is the phone's and Sapwood's.
        assert_eq!(check_code(&e.ephemeral_pubkey).len(), 7);
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
