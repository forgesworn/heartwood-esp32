// common/src/nip59.rs
//
// Family-bunker C4/C5 event shapes and the NIP-59 gift wrap
// (2026-08-14-c4-c5-escalation-audit-schemas.md, ratified).
//
// Pure and host-testable: the two rumor template builders freeze the exact
// tag shapes the `signet-app` consumer already reads (C5 kind-31000 audit,
// byte-compatible with `audit.ts`'s `buildAuditEventTemplate`; C4 kind-31001
// notices), and `gift_wrap` assembles rumor → seal → wrap with signing
// injected as a callback so the firmware passes libsecp256k1 and the host
// tests pass k256. Nothing here touches a clock or an RNG — timestamps and
// nonces are caller-supplied, per the schema doc's request-derived timestamp
// rule (§0.1).

#[allow(unused_imports)]
use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use serde::Serialize;
use zeroize::Zeroize;

use crate::hex::hex_encode;
use crate::nip44;
use crate::nip46::{self, SignedEvent, UnsignedEvent};

/// NIP-59 seal.
pub const SEAL_KIND: u64 = 13;
/// NIP-59 gift wrap.
pub const GIFT_WRAP_KIND: u64 = 1059;
/// C5 audit rumor kind (matches `signet-app`'s `AUDIT_EVENT_KIND`).
pub const AUDIT_KIND: u64 = 31000;
/// C4 escalation notice rumor kind.
pub const NOTICE_KIND: u64 = 31001;
/// NIP-59 canonical backwards jitter ceiling for seal/wrap timestamps.
pub const TWO_DAYS_SECS: u64 = 172_800;
/// NIP-40 expiration horizon for approval-notice wraps (schema §1.3).
pub const APPROVAL_EXPIRY_SECS: u64 = 86_400;
/// NIP-40 expiration horizon for petition-notice wraps (schema §1.3).
pub const PETITION_EXPIRY_SECS: u64 = 604_800;

/// Schema §0.1: device-authored rumors stamp
/// `created_at = max(trigger.created_at, last_stamped + 1)` so emitted events
/// never go backwards within a boot. `last_stamped` is the session-monotonic
/// floor the caller keeps.
pub fn stamp_monotonic(trigger_created_at: u64, last_stamped: &mut u64) -> u64 {
    let stamped = trigger_created_at.max(last_stamped.saturating_add(1));
    *last_stamped = stamped;
    stamped
}

/// Jitter a seal/wrap timestamp up to two days into the past from `base`,
/// never into the future. `rand` is caller-supplied randomness (hardware RNG
/// on the device, anything in tests).
pub fn jitter_past(base: u64, rand: u64) -> u64 {
    base.saturating_sub(rand % (TWO_DAYS_SECS + 1))
}

/// The method-or-kind coalescing key (schema §1.1 `d` tag): the event kind
/// for `sign_event`/`sign_event_compact`, else the method name.
pub fn method_or_kind_key(method: &str, event_kind: Option<u64>) -> String {
    match (method, event_kind) {
        ("sign_event" | "sign_event_compact", Some(kind)) => format!("{kind}"),
        _ => method.to_string(),
    }
}

/// C5 audit rumor parameters. Tag order and content mirror the app's
/// `buildAuditEventTemplate` exactly: `t`, `d`, `k`?, `method`?, `outcome`,
/// `p`?; content always empty (the privacy contract).
pub struct AuditRumor<'a> {
    /// Guardian NP pubkey hex — the rumor author (schema §0.2).
    pub guardian_np_hex: &'a str,
    /// The dependant identity whose activity is audited (the served
    /// identity's pubkey hex).
    pub dependant_hex: &'a str,
    /// Per §0.1, already stamped monotonic from the trigger request.
    pub created_at: u64,
    /// Uniqueness counter within a second: `d` carries
    /// `created_at * 1000 + emit_counter` in place of wall-clock ms.
    pub emit_counter: u64,
    /// Event kind for sign_event outcomes; `None` for transport methods.
    pub event_kind: Option<u64>,
    /// NIP-46 method for transport outcomes (nip04/nip44 encrypt/decrypt).
    pub method: Option<&'a str>,
    /// `auto-approved` | `auto-denied` | `approved` | `denied`.
    pub outcome: &'a str,
    /// Counterparty pubkey hex when derivable from the template.
    pub counterparty_hex: Option<&'a str>,
}

/// Build the C5 kind-31000 audit rumor (unsigned; `gift_wrap` computes the id).
pub fn build_audit_rumor(p: &AuditRumor<'_>) -> UnsignedEvent {
    let ms = p.created_at.saturating_mul(1000).saturating_add(p.emit_counter % 1000);
    let mut tags: Vec<Vec<String>> = vec![
        vec!["t".to_string(), "audit".to_string()],
        vec!["d".to_string(), format!("{}:{ms}", p.dependant_hex)],
    ];
    if let Some(kind) = p.event_kind {
        tags.push(vec!["k".to_string(), format!("{kind}")]);
    }
    if let Some(method) = p.method {
        tags.push(vec!["method".to_string(), method.to_string()]);
    }
    tags.push(vec!["outcome".to_string(), p.outcome.to_string()]);
    if let Some(counterparty) = p.counterparty_hex {
        tags.push(vec!["p".to_string(), counterparty.to_string()]);
    }
    UnsignedEvent {
        pubkey: p.guardian_np_hex.to_string(),
        created_at: p.created_at,
        kind: AUDIT_KIND,
        tags,
        content: String::new(),
    }
}

/// C4 approval-needed notice parameters (schema §1.1).
pub struct ApprovalNotice<'a> {
    pub guardian_np_hex: &'a str,
    /// The requesting app's NIP-46 client pubkey hex.
    pub client_hex: &'a str,
    /// The triggering NIP-46 request event id hex — the park handle.
    pub park_id_hex: &'a str,
    /// The served identity's pubkey hex.
    pub identity_hex: &'a str,
    /// NIP-46 method name.
    pub method: &'a str,
    /// Event kind — sign_event only.
    pub event_kind: Option<u64>,
    /// Seconds the device will hold the parked request.
    pub park_ttl_secs: u64,
    /// Per §0.1, already stamped monotonic.
    pub created_at: u64,
}

/// Build the C4 kind-31001 approval-needed rumor.
pub fn build_approval_notice(p: &ApprovalNotice<'_>) -> UnsignedEvent {
    let key = method_or_kind_key(p.method, p.event_kind);
    let mut tags: Vec<Vec<String>> = vec![
        vec!["t".to_string(), "approval".to_string()],
        vec!["d".to_string(), format!("{}:{key}", p.client_hex)],
        vec!["park".to_string(), p.park_id_hex.to_string()],
        vec!["client".to_string(), p.client_hex.to_string()],
        vec!["identity".to_string(), p.identity_hex.to_string()],
        vec!["method".to_string(), p.method.to_string()],
    ];
    if let Some(kind) = p.event_kind {
        tags.push(vec!["k".to_string(), format!("{kind}")]);
    }
    tags.push(vec!["park-ttl".to_string(), format!("{}", p.park_ttl_secs)]);
    UnsignedEvent {
        pubkey: p.guardian_np_hex.to_string(),
        created_at: p.created_at,
        kind: NOTICE_KIND,
        tags,
        content: String::new(),
    }
}

/// Build the C4 kind-31001 petition rumor (schema §1.2): same shape as the
/// approval notice, `t:petition`, no `park` tag (nothing is held), plus a
/// `count` of asks since the last verdict so nagging coalesces.
pub fn build_petition_notice(
    guardian_np_hex: &str,
    client_hex: &str,
    identity_hex: &str,
    method: &str,
    event_kind: Option<u64>,
    count: u64,
    created_at: u64,
) -> UnsignedEvent {
    let key = method_or_kind_key(method, event_kind);
    let mut tags: Vec<Vec<String>> = vec![
        vec!["t".to_string(), "petition".to_string()],
        vec!["d".to_string(), format!("{client_hex}:{key}")],
        vec!["client".to_string(), client_hex.to_string()],
        vec!["identity".to_string(), identity_hex.to_string()],
        vec!["method".to_string(), method.to_string()],
    ];
    if let Some(kind) = event_kind {
        tags.push(vec!["k".to_string(), format!("{kind}")]);
    }
    tags.push(vec!["count".to_string(), format!("{count}")]);
    UnsignedEvent {
        pubkey: guardian_np_hex.to_string(),
        created_at,
        kind: NOTICE_KIND,
        tags,
        content: String::new(),
    }
}

/// A rumor as it travels inside the seal: the unsigned event plus its
/// computed id, no signature — the same shape `signet-app`'s `giftWrap`
/// produces (`{...innerEvent, id}`).
#[derive(Serialize)]
struct RumorEvent<'a> {
    id: &'a str,
    pubkey: &'a str,
    created_at: u64,
    kind: u64,
    tags: &'a [Vec<String>],
    content: &'a str,
}

/// Serialise a rumor (unsigned event + computed id) to the JSON that gets
/// NIP-44-encrypted into the seal.
pub fn rumor_json(event: &UnsignedEvent) -> Result<String, &'static str> {
    let id = hex_encode(&nip46::compute_event_id(event));
    serde_json::to_string(&RumorEvent {
        id: &id,
        pubkey: &event.pubkey,
        created_at: event.created_at,
        kind: event.kind,
        tags: &event.tags,
        content: &event.content,
    })
    .map_err(|_| "rumor serialisation failed")
}

/// Signature callback: `(secret, hash) -> 64-byte BIP-340 Schnorr sig`.
/// Firmware passes a closure over `sign::sign_hash`; host tests pass k256.
pub type SignFn<'a> = &'a dyn Fn(&[u8; 32], &[u8; 32]) -> Result<[u8; 64], &'static str>;

/// Seal and wrap timestamps, pre-jittered by the caller (`jitter_past`).
pub struct WrapTimes {
    pub seal_created_at: u64,
    pub wrap_created_at: u64,
}

/// Assemble the full NIP-59 gift wrap for a rumor:
///
/// - seal: kind 13, signed by the author (the guardian NP — the consumer's
///   `expectedSignerPubkey` gate demands the real key, schema §0.2), content
///   = NIP-44(author⇄recipient, rumor JSON), no tags;
/// - wrap: kind 1059, signed by a caller-generated ephemeral key, content =
///   NIP-44(ephemeral⇄recipient, seal JSON), tags `["p", recipient]` plus an
///   optional NIP-40 `["expiration", …]` — the expiration goes on the wrap
///   only, never the rumor (schema §1.3).
///
/// Nonces and both keypairs come from the caller; conversation keys are
/// zeroised before return.
#[allow(clippy::too_many_arguments)]
pub fn gift_wrap(
    rumor: &UnsignedEvent,
    author_secret: &[u8; 32],
    recipient_pubkey: &[u8; 32],
    eph_secret: &[u8; 32],
    eph_pubkey: &[u8; 32],
    times: WrapTimes,
    expiration: Option<u64>,
    seal_nonce: &[u8; 32],
    wrap_nonce: &[u8; 32],
    sign: SignFn<'_>,
) -> Result<SignedEvent, &'static str> {
    let recipient_hex = hex_encode(recipient_pubkey);

    // Seal: encrypt the rumor to the recipient under the author's key.
    let mut seal_conv = nip44::get_conversation_key(author_secret, recipient_pubkey)?;
    let seal_content = nip44::encrypt_owned(&seal_conv, rumor_json(rumor)?, seal_nonce);
    seal_conv.zeroize();
    let seal_unsigned = UnsignedEvent {
        pubkey: rumor.pubkey.clone(),
        created_at: times.seal_created_at,
        kind: SEAL_KIND,
        tags: vec![],
        content: seal_content?,
    };
    let seal_id = nip46::compute_event_id(&seal_unsigned);
    let seal_sig = sign(author_secret, &seal_id)?;
    let seal = SignedEvent {
        id: hex_encode(&seal_id),
        pubkey: seal_unsigned.pubkey,
        created_at: seal_unsigned.created_at,
        kind: seal_unsigned.kind,
        tags: seal_unsigned.tags,
        content: seal_unsigned.content,
        sig: hex_encode(&seal_sig),
    };
    let seal_json = serde_json::to_string(&seal).map_err(|_| "seal serialisation failed")?;

    // Wrap: encrypt the seal to the recipient under the ephemeral key.
    let mut wrap_conv = nip44::get_conversation_key(eph_secret, recipient_pubkey)?;
    let wrap_content = nip44::encrypt_owned(&wrap_conv, seal_json, wrap_nonce);
    wrap_conv.zeroize();
    let mut tags = vec![vec!["p".to_string(), recipient_hex]];
    if let Some(expires_at) = expiration {
        tags.push(vec!["expiration".to_string(), format!("{expires_at}")]);
    }
    let wrap_unsigned = UnsignedEvent {
        pubkey: hex_encode(eph_pubkey),
        created_at: times.wrap_created_at,
        kind: GIFT_WRAP_KIND,
        tags,
        content: wrap_content?,
    };
    let wrap_id = nip46::compute_event_id(&wrap_unsigned);
    let wrap_sig = sign(eph_secret, &wrap_id)?;
    Ok(SignedEvent {
        id: hex_encode(&wrap_id),
        pubkey: wrap_unsigned.pubkey,
        created_at: wrap_unsigned.created_at,
        kind: wrap_unsigned.kind,
        tags: wrap_unsigned.tags,
        content: wrap_unsigned.content,
        sig: hex_encode(&wrap_sig),
    })
}

#[cfg(all(test, feature = "k256-backend"))]
mod tests {
    use super::*;

    const GUARDIAN_NP: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DEP: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const CLIENT: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const PARK: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    fn k256_sign(secret: &[u8; 32], hash: &[u8; 32]) -> Result<[u8; 64], &'static str> {
        let sk = k256::schnorr::SigningKey::from_bytes(secret).map_err(|_| "bad key")?;
        let sig = sk.sign_raw(hash, &[0u8; 32]).map_err(|_| "sign failed")?;
        Ok(sig.to_bytes())
    }

    fn keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
        let secret = [seed; 32];
        let sk = k256::schnorr::SigningKey::from_bytes(&secret).unwrap();
        let pk: [u8; 32] = sk.verifying_key().to_bytes().into();
        (secret, pk)
    }

    // --- §0.1 timestamps ---

    #[test]
    fn stamp_is_monotonic_within_a_boot() {
        let mut last = 0u64;
        assert_eq!(stamp_monotonic(1_700_000_000, &mut last), 1_700_000_000);
        // An older trigger still moves forward.
        assert_eq!(stamp_monotonic(1_600_000_000, &mut last), 1_700_000_001);
        assert_eq!(stamp_monotonic(1_700_000_005, &mut last), 1_700_000_005);
        assert_eq!(last, 1_700_000_005);
    }

    #[test]
    fn jitter_only_goes_backwards_and_at_most_two_days() {
        let base = 1_700_000_000u64;
        assert_eq!(jitter_past(base, 0), base);
        assert_eq!(jitter_past(base, TWO_DAYS_SECS), base - TWO_DAYS_SECS);
        assert_eq!(jitter_past(base, TWO_DAYS_SECS + 1), base);
        assert!(jitter_past(base, 0xDEADBEEF) <= base);
        assert!(jitter_past(base, 0xDEADBEEF) >= base - TWO_DAYS_SECS);
    }

    // --- Frozen rumor shapes (CP5 fails if these drift) ---

    #[test]
    fn audit_rumor_sign_event_frozen_shape() {
        let rumor = build_audit_rumor(&AuditRumor {
            guardian_np_hex: GUARDIAN_NP,
            dependant_hex: DEP,
            created_at: 1_700_000_000,
            emit_counter: 7,
            event_kind: Some(1),
            method: None,
            outcome: "auto-approved",
            counterparty_hex: None,
        });
        let json = rumor_json(&rumor).unwrap();
        // The exact wire shape the app's `useAuditLog` parser reads.
        let expected = format!(
            "{{\"id\":\"{id}\",\"pubkey\":\"{GUARDIAN_NP}\",\"created_at\":1700000000,\
             \"kind\":31000,\"tags\":[[\"t\",\"audit\"],\
             [\"d\",\"{DEP}:1700000000007\"],[\"k\",\"1\"],\
             [\"outcome\",\"auto-approved\"]],\"content\":\"\"}}",
            id = hex_encode(&nip46::compute_event_id(&rumor)),
        );
        assert_eq!(json, expected);
    }

    #[test]
    fn audit_rumor_transport_method_carries_method_not_kind() {
        let rumor = build_audit_rumor(&AuditRumor {
            guardian_np_hex: GUARDIAN_NP,
            dependant_hex: DEP,
            created_at: 42,
            emit_counter: 0,
            event_kind: None,
            method: Some("nip44_decrypt"),
            outcome: "denied",
            counterparty_hex: Some(CLIENT),
        });
        assert_eq!(rumor.kind, AUDIT_KIND);
        assert_eq!(
            rumor.tags,
            vec![
                vec!["t".to_string(), "audit".to_string()],
                vec!["d".to_string(), format!("{DEP}:42000")],
                vec!["method".to_string(), "nip44_decrypt".to_string()],
                vec!["outcome".to_string(), "denied".to_string()],
                vec!["p".to_string(), CLIENT.to_string()],
            ],
        );
        assert_eq!(rumor.content, "");
        assert_eq!(rumor.pubkey, GUARDIAN_NP);
    }

    #[test]
    fn approval_notice_frozen_shape() {
        let rumor = build_approval_notice(&ApprovalNotice {
            guardian_np_hex: GUARDIAN_NP,
            client_hex: CLIENT,
            park_id_hex: PARK,
            identity_hex: DEP,
            method: "sign_event",
            event_kind: Some(1),
            park_ttl_secs: 600,
            created_at: 1_700_000_000,
        });
        assert_eq!(rumor.kind, NOTICE_KIND);
        assert_eq!(
            rumor.tags,
            vec![
                vec!["t".to_string(), "approval".to_string()],
                vec!["d".to_string(), format!("{CLIENT}:1")],
                vec!["park".to_string(), PARK.to_string()],
                vec!["client".to_string(), CLIENT.to_string()],
                vec!["identity".to_string(), DEP.to_string()],
                vec!["method".to_string(), "sign_event".to_string()],
                vec!["k".to_string(), "1".to_string()],
                vec!["park-ttl".to_string(), "600".to_string()],
            ],
        );
    }

    #[test]
    fn petition_notice_has_count_and_no_park() {
        let rumor =
            build_petition_notice(GUARDIAN_NP, CLIENT, DEP, "nip44_decrypt", None, 3, 99);
        assert_eq!(rumor.kind, NOTICE_KIND);
        assert!(rumor.tags.iter().any(|t| t[0] == "t" && t[1] == "petition"));
        assert!(rumor.tags.iter().any(|t| t[0] == "count" && t[1] == "3"));
        assert!(!rumor.tags.iter().any(|t| t[0] == "park"));
        assert!(rumor
            .tags
            .iter()
            .any(|t| t[0] == "d" && t[1] == format!("{CLIENT}:nip44_decrypt")));
    }

    #[test]
    fn method_or_kind_key_rules() {
        assert_eq!(method_or_kind_key("sign_event", Some(30023)), "30023");
        assert_eq!(method_or_kind_key("sign_event_compact", Some(1)), "1");
        assert_eq!(method_or_kind_key("nip44_decrypt", None), "nip44_decrypt");
        // A kind never leaks onto a non-signing method's key.
        assert_eq!(method_or_kind_key("nip44_decrypt", Some(1)), "nip44_decrypt");
    }

    // --- The wrap itself, end to end ---

    #[test]
    fn gift_wrap_round_trips_and_seal_signer_is_the_author() {
        let (author_sk, author_pk) = keypair(0x11);
        let (recipient_sk, recipient_pk) = keypair(0x22);
        let (eph_sk, eph_pk) = keypair(0x33);

        let rumor = build_audit_rumor(&AuditRumor {
            guardian_np_hex: &hex_encode(&author_pk),
            dependant_hex: DEP,
            created_at: 1_700_000_000,
            emit_counter: 1,
            event_kind: Some(1),
            method: None,
            outcome: "approved",
            counterparty_hex: None,
        });

        let wrap = gift_wrap(
            &rumor,
            &author_sk,
            &recipient_pk,
            &eph_sk,
            &eph_pk,
            WrapTimes { seal_created_at: 1_699_999_000, wrap_created_at: 1_699_998_000 },
            Some(1_700_000_000 + APPROVAL_EXPIRY_SECS),
            &[0x01; 32],
            &[0x02; 32],
            &k256_sign,
        )
        .unwrap();

        // Wrap layer: ephemeral author, p + expiration tags, valid signature.
        assert_eq!(wrap.kind, GIFT_WRAP_KIND);
        assert_eq!(wrap.pubkey, hex_encode(&eph_pk));
        assert_eq!(wrap.tags[0], vec!["p".to_string(), hex_encode(&recipient_pk)]);
        assert_eq!(
            wrap.tags[1],
            vec!["expiration".to_string(), format!("{}", 1_700_000_000u64 + APPROVAL_EXPIRY_SECS)],
        );
        nip46::verify_signed_event(&wrap).expect("wrap signature verifies");

        // Recipient decrypts wrap -> seal.
        let wrap_conv = nip44::get_conversation_key(&recipient_sk, &eph_pk).unwrap();
        let seal_json = nip44::decrypt(&wrap_conv, &wrap.content).unwrap();
        let seal: SignedEvent = serde_json::from_str(&seal_json).unwrap();
        assert_eq!(seal.kind, SEAL_KIND);
        // The consumer's forgery gate: the seal must be signed by the real
        // guardian NP key, and verify.
        assert_eq!(seal.pubkey, hex_encode(&author_pk));
        assert!(seal.tags.is_empty());
        nip46::verify_signed_event(&seal).expect("seal signature verifies");

        // Seal -> rumor.
        let seal_conv = nip44::get_conversation_key(&recipient_sk, &author_pk).unwrap();
        let rumor_str = nip44::decrypt(&seal_conv, &seal.content).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rumor_str).unwrap();
        assert_eq!(parsed["kind"], 31000);
        assert_eq!(parsed["pubkey"], hex_encode(&author_pk));
        assert_eq!(parsed["content"], "");
        assert_eq!(parsed["id"], hex_encode(&nip46::compute_event_id(&rumor)));
        // The rumor is unsigned and carries no expiration — audit is the
        // permanent record; the NIP-40 tag lives on the wrap alone.
        assert!(parsed.get("sig").is_none());
        assert!(parsed["tags"].as_array().unwrap().iter().all(|t| t[0] != "expiration"));
    }

    #[test]
    fn audit_wrap_carries_no_expiration() {
        let (author_sk, author_pk) = keypair(0x11);
        let (_, recipient_pk) = keypair(0x22);
        let (eph_sk, eph_pk) = keypair(0x33);
        let rumor = build_audit_rumor(&AuditRumor {
            guardian_np_hex: &hex_encode(&author_pk),
            dependant_hex: DEP,
            created_at: 10,
            emit_counter: 0,
            event_kind: Some(1),
            method: None,
            outcome: "auto-denied",
            counterparty_hex: None,
        });
        let wrap = gift_wrap(
            &rumor,
            &author_sk,
            &recipient_pk,
            &eph_sk,
            &eph_pk,
            WrapTimes { seal_created_at: 9, wrap_created_at: 8 },
            None,
            &[0x04; 32],
            &[0x05; 32],
            &k256_sign,
        )
        .unwrap();
        assert_eq!(wrap.tags.len(), 1);
        assert_eq!(wrap.tags[0][0], "p");
    }
}
