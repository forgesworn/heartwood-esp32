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
// Test vectors: tests/fixtures/phone-unlock-v1.json (checked by the tests
// below and by scripts/lib/phone-unlock.test.mjs, an independent
// implementation in Node's own crypto).

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
    /// Locked restarts so far on this board. A phone never prompts twice for
    /// the same count, and drops a lower one as a replay.
    pub boot: u32,
    /// Why the chip restarted, as ESP-IDF names it (`poweron`, `brownout`,
    /// `task_wdt`, ...).
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
    /// its announcement every 60 s).
    Duplicate,
    /// Older than [`MAX_ANNOUNCE_AGE_SECS`], or too far in the future.
    Stale,
    /// A lower restart count than one already seen: a replay.
    Replay,
    /// Not a lock announcement (for example a relay-list update).
    NotLocked,
}

/// The phone's prompt rule. `last_boot` is the highest restart count this
/// phone has already prompted for on this board.
pub fn judge(ctx: &LockContext, created_at: u64, now: u64, last_boot: Option<u32>) -> Verdict {
    if ctx.t != TYPE_LOCKED {
        return Verdict::NotLocked;
    }
    if created_at.saturating_add(MAX_ANNOUNCE_AGE_SECS) < now
        || created_at > now.saturating_add(MAX_FUTURE_SKEW_SECS)
    {
        return Verdict::Stale;
    }
    match last_boot {
        Some(b) if ctx.boot < b => Verdict::Replay,
        Some(b) if ctx.boot == b => Verdict::Duplicate,
        _ => Verdict::Prompt,
    }
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
        for bad in [
            r#"{"v":2,"id":7,"s":"abababababababababababababababababababababababababababababababab"}"#,
            r#"{"v":1,"id":7,"s":"abab"}"#,
            r#"{"v":1,"id":7,"s":"ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB"}"#,
            r#"{"v":1,"id":7,"s":"zbababababababababababababababababababababababababababababababab"}"#,
            r#"{"v":1,"id":-1,"s":"abababababababababababababababababababababababababababababababab"}"#,
            r#"{"v":1,"id":7,"s":"abababababababababababababababababababababababababababababababab","x":1}"#,
            "0000000000000000000000000000000000000000000000000000000000000000",
        ] {
            assert!(Delivery::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_prompt_rule() {
        let c = ctx();
        let now = 1_800_000_000;
        assert_eq!(judge(&c, now, now, None), Verdict::Prompt);
        assert_eq!(judge(&c, now - 120, now, Some(211)), Verdict::Prompt);
        assert_eq!(judge(&c, now - 121, now, None), Verdict::Stale);
        assert_eq!(judge(&c, now + 60, now, None), Verdict::Prompt);
        assert_eq!(judge(&c, now + 61, now, None), Verdict::Stale);
        assert_eq!(judge(&c, now, now, Some(212)), Verdict::Duplicate);
        assert_eq!(judge(&c, now, now, Some(213)), Verdict::Replay);
        let mut r = ctx();
        r.t = TYPE_RELAYS.into();
        assert_eq!(judge(&r, now, now, None), Verdict::NotLocked);
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
}
