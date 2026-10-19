// common/src/owner_pairing.rs
//
// The pure half of Heartwood one-hold pairing (signet-plans
// docs/plans/2026-10-17-heartwood-one-hold-pairing-spec.md, rev 4.1).
//
// An OWNER PAIRING is a non-strict slot whose `allowed_methods` carries the
// owner mark, `heartwood_owner_vault`. The mark is not a callable method
// (`Nip46Method::from_str` maps it to `Unknown`); it records that the owner
// approved this phone with the setup hold, `heartwood_approve_bundle`, on
// its own FULL ACCESS card. No slot codec or storage format changes: the
// mark is one more name in a list every slot already persists.
//
// Everything here is a function of plain data (the slot, the request
// params, a registry lookup the firmware supplies), so the firmware's
// handler, its relay planner and ui-preview all decide and draw the same
// way, and all of it runs in host CI. The firmware wires it in.

use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec::Vec,
};

use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::policy::{
    can_record_client_identity, client_identity_approved, decode_client_key, grant_slot_method,
    grant_slot_signing, record_client_identity, ConnectSlot, IDENTITY_TAG_BYTES, LOGIN_EVENT_KIND,
    MAX_APPROVED_IDENTITIES,
};
use crate::spoken_words;

// ---------------------------------------------------------------------------
// Names and constants
// ---------------------------------------------------------------------------

/// The owner mark (spec 3, 5). A name in a non-strict slot's
/// `allowed_methods`, never a method. Must NOT be in `EXACT_POLICY_METHODS`.
pub const OWNER_MARK: &str = "heartwood_owner_vault";
/// The setup hold (spec 4.1).
pub const BUNDLE_METHOD: &str = "heartwood_approve_bundle";
/// The owner-status probe (spec 4.1).
pub const OWNER_STATUS_METHOD: &str = "heartwood_owner_status";
/// The one-tap narrowing to Extra careful (spec 4.6).
pub const OWNER_NARROW_METHOD: &str = "heartwood_owner_narrow";

/// A Heartwood context whose `purpose` starts with this is a vault context
/// (spec 3).
pub const VAULT_PURPOSE_PREFIX: &str = "signet:vault:";
/// The only kind a vault key signs under Rule V: NIP-78 app data (backups).
pub const VAULT_EVENT_KIND: u64 = 30078;

/// Extra careful's fixed kinds list (spec 4.6): backups, and relays checking
/// who the phone is (plain NIP-42 AUTH; a login code still always asks). In
/// the spec's order; [`is_careful_kinds`] compares as a set.
pub const CAREFUL_KINDS: [u64; 2] = [VAULT_EVENT_KIND, LOGIN_EVENT_KIND];

/// The only names a bundle may carry, in `personas` and in `act_as` (review
/// round W6): the owner's persona and real identity, which is all My Signet
/// sends. Any other name is a malformed bundle, so the card's scope line
/// ([`SCOPE_PERSONA_ONLY`] / [`SCOPE_PERSONA_AND_REAL_NAME`]) always names
/// everything the hold grants. More names can come later, with a card that
/// names them.
pub const BUNDLE_NAMES: [&str; 2] = [PERSONA, NATURAL_PERSON];
/// Most personas one bundle may name (spec 4.1): every name in
/// [`BUNDLE_NAMES`], once.
pub const MAX_BUNDLE_PERSONAS: usize = BUNDLE_NAMES.len();
/// Most names a slot's `allowed_methods` may hold (`slot_codec`'s cap).
pub const MAX_SLOT_METHODS: usize = crate::slot_codec::MAX_METHODS;

/// The names the press adds to `allowed_methods` (spec 4.3 steps 3 to 5):
/// the mark, LIST IDS, encryption both ways, and signing.
pub const BUNDLE_GRANTED_METHODS: [&str; 5] = [
    OWNER_MARK,
    "heartwood_list_identities",
    "nip44_encrypt",
    "nip44_decrypt",
    "sign_event",
];

/// The owner's real identity's registry name. Never granted by Rule D.
pub const NATURAL_PERSON: &str = "natural-person";
/// The owner's default persona's registry name.
pub const PERSONA: &str = "persona";
/// Names under this prefix are children's keys: never in a bundle (outside
/// [`BUNDLE_NAMES`]), and never recorded by Rule D when real.
pub const DEPENDANT_PREFIX: &str = "dependant-";

/// The full-access card's hold, in milliseconds (spec 4.2). Every other card
/// keeps 2 s.
pub const FULL_ACCESS_HOLD_MS: u64 = 5_000;
/// The full-access card's window, in seconds: the enrol window, not the
/// 30 s of other cards, so there is time to read the words (spec 4.2).
pub const FULL_ACCESS_CARD_SECS: u64 = 45;

/// The inverted header. No other card may use it, now or later (spec 4.2):
/// pinned by a test over this crate's sources, and ui-preview should pin the
/// firmware's card builders the same way.
pub const FULL_ACCESS_HEADER: &str = "FULL ACCESS";
/// Scope line when `act_as` leaves the real identity out.
pub const SCOPE_PERSONA_ONLY: &str = "PERSONA ONLY";
/// Scope line when `act_as` includes the real identity.
pub const SCOPE_PERSONA_AND_REAL_NAME: &str = "PERSONA + REAL NAME";
/// What Everyday lets the phone do alone.
pub const EVERYDAY_LINES: &[&str] = &["SIGN IN, POST, BACKUP"];
/// What Extra careful lets the phone do alone, and what still asks. Backups
/// and any other app data (kind 30078) under a granted identity sign alone,
/// so the line names both (review round W9): `SIGNS ALONE: BACKUPS, APP
/// DATA` is 30 characters, past the 24 the Heltec's span holds, so the
/// shorter form drops "SIGNS" and never the claim. Relay logins (plain AUTH)
/// also sign alone; My Signet's style copy says so.
pub const CAREFUL_LINES: &[&str] = &["ALONE: BACKUPS, APP DATA", "ASKS: EVERYTHING ELSE"];
/// The card's last line.
pub const HOLD_LINE: &str = "HOLD 5 SECONDS";
/// The board's hint line until every words page has had its full dwell
/// (review round W2): the comparison, and no hold offered yet.
pub const COMPARE_LINE: &str = "COMPARE ALL 5 WORDS";

/// The board's hint line at rest: [`COMPARE_LINE`] until a hold counts
/// (`armed`), then [`HOLD_LINE`].
pub fn full_access_hint(armed: bool) -> &'static str {
    if armed {
        HOLD_LINE
    } else {
        COMPARE_LINE
    }
}

/// Domain separator for the pairing words (spec 4.2), NUL included.
pub const PAIR_WORDS_DOMAIN: &[u8] = b"heartwood-pair-words\0";
/// How many words the full-access card shows (review round W1): five, 55
/// bits, the phone-enrol card's bar. Three (33 bits) could be ground by a
/// client that holds its own Everything slot and knows the phone's client
/// key ahead of time.
pub const PAIR_WORDS: usize = 5;
/// How many pages the card turns through at rest, two words a page: 1 and
/// 2, then 3 and 4, then 5 (the enrol card's pages; firmware turns them with
/// `phone_unlock::EnrolGate`).
pub const PAIR_WORD_PAGES: usize = PAIR_WORDS.div_ceil(2);
/// The least gap, in seconds, between a FULL ACCESS card closing (approved,
/// declined, expired or refused) and the next bundle that may raise one
/// (review round W3). A bundle sooner than this is refused without a card.
pub const FULL_ACCESS_COOLDOWN_SECS: u64 = 60;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Every refusal of the bundle (spec 4.1 table) and of the owner methods.
///
/// The wire carries only [`Self::message`]: `nip46::build_error_response`
/// keeps the numeric code for logging and never sends it. The spec writes the
/// code in front (`-3 malformed bundle`); My Signet must match the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleError {
    /// `-3 malformed bundle`
    Malformed,
    /// `-3 persona missing`
    PersonaMissing,
    /// `-3 pubkey mismatch`
    PubkeyMismatch,
    /// `unauthorised`: unbound client, strict slot, or (narrow) no mark.
    Unauthorised,
    /// The existing escalate-slot refusal
    /// (`escalate::DEVICE_APPROVAL_REQUIRED`).
    DeviceApprovalRequired,
    /// `unauthorised: pairing shared by another device`
    SharedPairing,
    /// `unauthorised: pairing asks for every request`
    AsksEveryRequest,
    /// `unauthorised: pairing has a kinds list`
    HasKindsList,
    /// `-4 no persona tree on this master`
    NoPersonaTree,
    /// `-4 storage full`
    StorageFull,
    /// `-4 approval list full`
    ApprovalListFull,
    /// `-4 method list full`
    MethodListFull,
    /// `unauthorised: another full access request arrived` (review round
    /// W3): a bundle came while another was waiting, queued or on screen.
    /// Both get this reply, and the waiting card closes with nothing granted.
    AnotherFullAccess,
    /// `unauthorised: full access card shown recently` (review round W3): a
    /// bundle came less than [`FULL_ACCESS_COOLDOWN_SECS`] after the last
    /// FULL ACCESS card closed. No card is shown.
    ShownRecently,
    /// The relay's card queue has no room
    /// ([`crate::approval_queue::BUSY_ERROR`], the same answer as any other
    /// ask gets): checked with the one-card rule, before room and the
    /// registry.
    QueueBusy,
}

impl BundleError {
    /// The JSON-RPC code the firmware logs (`build_error_json`'s `code`).
    pub fn code(&self) -> i32 {
        match self {
            Self::Malformed | Self::PersonaMissing | Self::PubkeyMismatch => -3,
            Self::Unauthorised
            | Self::DeviceApprovalRequired
            | Self::SharedPairing
            | Self::AsksEveryRequest
            | Self::HasKindsList
            | Self::AnotherFullAccess
            | Self::ShownRecently
            | Self::QueueBusy => -1,
            Self::NoPersonaTree | Self::StorageFull | Self::ApprovalListFull | Self::MethodListFull => -4,
        }
    }

    /// The error string on the wire.
    pub fn message(&self) -> &'static str {
        match self {
            Self::Malformed => "malformed bundle",
            Self::PersonaMissing => "persona missing",
            Self::PubkeyMismatch => "pubkey mismatch",
            Self::Unauthorised => "unauthorised",
            Self::DeviceApprovalRequired => crate::escalate::DEVICE_APPROVAL_REQUIRED,
            Self::SharedPairing => "unauthorised: pairing shared by another device",
            Self::AsksEveryRequest => "unauthorised: pairing asks for every request",
            Self::HasKindsList => "unauthorised: pairing has a kinds list",
            Self::NoPersonaTree => "no persona tree on this master",
            Self::StorageFull => "storage full",
            Self::ApprovalListFull => "approval list full",
            Self::MethodListFull => "method list full",
            Self::AnotherFullAccess => "unauthorised: another full access request arrived",
            Self::ShownRecently => "unauthorised: full access card shown recently",
            Self::QueueBusy => crate::approval_queue::BUSY_ERROR,
        }
    }
}

// ---------------------------------------------------------------------------
// Signing style (spec 4.6)
// ---------------------------------------------------------------------------

/// How an owner pairing signs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Style {
    /// `allowed_kinds` empty: every kind signs without a press.
    #[default]
    Everyday,
    /// `allowed_kinds` is [`CAREFUL_KINDS`]: only backups and plain AUTH sign
    /// alone, every other kind asks every time.
    Careful,
}

impl Style {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Everyday => "everyday",
            Self::Careful => "careful",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "everyday" => Some(Self::Everyday),
            "careful" => Some(Self::Careful),
            _ => None,
        }
    }

    /// The card lines naming what the phone may do alone.
    pub fn card_lines(&self) -> &'static [&'static str] {
        match self {
            Self::Everyday => EVERYDAY_LINES,
            Self::Careful => CAREFUL_LINES,
        }
    }
}

/// The style a slot's kinds list stands for, as `heartwood_owner_status` and
/// `heartwood_owner_narrow` report it (review round W4). Separate from
/// [`Style`], which is only ever what a bundle asks for: `custom` can be read
/// back, never requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotStyle {
    /// Empty kinds list.
    Everyday,
    /// Exactly [`CAREFUL_KINDS`], as a set.
    Careful,
    /// Any other non-empty list: an operator narrowed it.
    Custom,
}

impl SlotStyle {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Everyday => "everyday",
            Self::Careful => "careful",
            Self::Custom => "custom",
        }
    }
}

// ---------------------------------------------------------------------------
// The owner mark (spec 2, 5)
// ---------------------------------------------------------------------------

/// Whether the slot's `allowed_methods` carries the owner mark.
pub fn slot_has_owner_mark(slot: &ConnectSlot) -> bool {
    slot.allowed_methods.iter().any(|m| m == OWNER_MARK)
}

/// Whether the slot is an owner pairing: non-strict, not escalating, and
/// carrying the mark. Both gate rules (spec 6) apply only to these.
///
/// An escalating slot is not one while `escalate` is set (review m5): its
/// prompting asks go to a guardian verdict, which the bundle refuses for the
/// same reason (`check_bundle_slot`), so Rule V and Rule D do not apply, its
/// status reads `owner: false` and narrow is refused. The mark itself stays,
/// so clearing `escalate` makes it an owner pairing again, and the no-widen
/// rules in `update_slot_methods` / `update_slot_kinds` key off the mark
/// alone, so they still hold while it escalates.
pub fn is_owner_pairing(slot: &ConnectSlot) -> bool {
    !slot.strict_permissions && !slot.escalate && slot_has_owner_mark(slot)
}

/// Whether a kinds list is exactly Extra careful's, compared as a set.
pub fn is_careful_kinds(kinds: &[u64]) -> bool {
    let mut sorted: Vec<u64> = kinds.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut careful = CAREFUL_KINDS;
    careful.sort_unstable();
    sorted.len() == kinds.len() && sorted[..] == careful[..]
}

/// The style a slot's kinds list stands for: Everyday when empty, Careful
/// when exactly the careful list, Custom for any other list (an operator
/// narrowed it; review round W4).
pub fn slot_style(slot: &ConnectSlot) -> SlotStyle {
    if slot.allowed_kinds.is_empty() {
        SlotStyle::Everyday
    } else if is_careful_kinds(&slot.allowed_kinds) {
        SlotStyle::Careful
    } else {
        SlotStyle::Custom
    }
}

/// Remove the owner mark. True when it was there. For the paths that drop
/// it (spec 5.2): `clear_client_identities` ("Forget approvals", with or
/// without `client_pubkey`) and binding a new client key (done for you in
/// `policy::authorize_pubkey_on_slot`).
pub fn drop_owner_mark(slot: &mut ConnectSlot) -> bool {
    let before = slot.allowed_methods.len();
    slot.allowed_methods.retain(|m| m != OWNER_MARK);
    slot.allowed_methods.len() != before
}

/// Remove every name only the setup hold may grant: the mark and the bundle
/// method itself. True when anything went. For a backup import (done for you
/// in `policy::sanitise_imported_slot`) and a backup export (spec 5.2: omit
/// the mark so new backups import on older firmware).
pub fn strip_owner_names(methods: &mut Vec<String>) -> bool {
    let before = methods.len();
    methods.retain(|m| m != OWNER_MARK && m != BUNDLE_METHOD);
    methods.len() != before
}

/// The method list `update_slot` (legacy management, spec 5.2) may apply to
/// `old`: the mark may be kept or dropped, never added, and
/// `heartwood_approve_bundle` is filtered out always, the way `sign_event`
/// is filtered there today.
pub fn update_slot_methods(old: &ConnectSlot, mut new: Vec<String>) -> Vec<String> {
    let keep_mark = slot_has_owner_mark(old);
    new.retain(|m| m != BUNDLE_METHOD && (keep_mark || m != OWNER_MARK));
    new
}

/// The kinds list `update_slot` may apply (spec 4.6, no silent widening). On
/// a slot that carried the mark BEFORE the update (read from `old`, so an
/// update that drops the mark in the same call still keeps the list), the
/// list may be kept or narrowed, never emptied or extended: anything else
/// keeps the old list. Any other slot takes `new` as today.
pub fn update_slot_kinds(old: &ConnectSlot, new: Vec<u64>) -> Vec<u64> {
    if !slot_has_owner_mark(old) || old.allowed_kinds.is_empty() {
        // Everyday (or not an owner pairing): any list narrows, or nothing
        // changes.
        return new;
    }
    let narrows = !new.is_empty() && new.iter().all(|kind| old.allowed_kinds.contains(kind));
    if narrows {
        new
    } else {
        old.allowed_kinds.clone()
    }
}

// ---------------------------------------------------------------------------
// The pairing words (spec 4.2)
// ---------------------------------------------------------------------------

/// The five words the full-access card shows for a client key:
/// `d = SHA-256("heartwood-pair-words\0" || client_pubkey_32)`, word i =
/// `spoken_words::word(u16_be(d[2i], d[2i+1]) % 2048)` for i = 0..4, so
/// `d[0..10]`. The first three are the words the card showed before it took
/// five. My Signet computes the same over its own client key.
pub fn pair_words(client_pubkey: &[u8; 32]) -> [&'static str; PAIR_WORDS] {
    let mut hasher = Sha256::new();
    hasher.update(PAIR_WORDS_DOMAIN);
    hasher.update(client_pubkey);
    let d = hasher.finalize();
    core::array::from_fn(|i| spoken_words::word_for(&d[2 * i..2 * i + 2]))
}

/// The words page `page` of the card shows at rest, with each word's place
/// counted from 1: `[(1, w1), (2, w2)]`, `[(3, w3), (4, w4)]`, `[(5, w5)]`. A
/// page past the last wraps round.
pub fn pair_word_page<'w>(words: &[&'w str; PAIR_WORDS], page: usize) -> Vec<(usize, &'w str)> {
    let first = (page % PAIR_WORD_PAGES) * 2;
    (first..(first + 2).min(PAIR_WORDS)).map(|i| (i + 1, words[i])).collect()
}

/// A words page as one line, `w1 w2` (the card's own line for that page).
pub fn pair_word_line(words: &[&str; PAIR_WORDS], page: usize) -> String {
    pair_word_page(words, page).iter().map(|(_, w)| *w).collect::<Vec<_>>().join(" ")
}

/// [`pair_words`] for a 64-char lowercase hex client key.
pub fn pair_words_hex(client_hex: &str) -> Option<[&'static str; PAIR_WORDS]> {
    decode_client_key(client_hex).map(|key| pair_words(&key))
}

// ---------------------------------------------------------------------------
// The full-access card (spec 4.2)
// ---------------------------------------------------------------------------

/// The full-access card's text, top to bottom. The OLED builder draws
/// `header` in an inverted bar and holds for [`FULL_ACCESS_HOLD_MS`]; every
/// other line is plain text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullAccessCard {
    pub header: &'static str,
    /// The slot's label, printable ASCII only (anything else becomes `?`),
    /// shortened with `..` past the caller's width.
    pub label: String,
    pub words: [&'static str; PAIR_WORDS],
    /// [`SCOPE_PERSONA_ONLY`] or [`SCOPE_PERSONA_AND_REAL_NAME`].
    pub scope: &'static str,
    /// [`EVERYDAY_LINES`] or [`CAREFUL_LINES`].
    pub style_lines: &'static [&'static str],
    pub hold: &'static str,
}

impl FullAccessCard {
    /// Every line, in order, the header first: header, label, words 1-2,
    /// words 3-4, word 5 (the card's three pages), scope, the style's lines,
    /// the hold line. My Signet's choice screen shows these same lines word
    /// for word (spec A1).
    pub fn lines(&self) -> Vec<String> {
        let mut lines = Vec::with_capacity(4 + PAIR_WORD_PAGES + self.style_lines.len());
        lines.push(self.header.to_string());
        lines.push(self.label.clone());
        lines.extend((0..PAIR_WORD_PAGES).map(|page| pair_word_line(&self.words, page)));
        lines.push(self.scope.to_string());
        lines.extend(self.style_lines.iter().map(|line| line.to_string()));
        lines.push(self.hold.to_string());
        lines
    }
}

/// Whether a grant list includes the owner's real identity.
pub fn act_as_includes_real_name(act_as: &[String]) -> bool {
    act_as.iter().any(|name| name == NATURAL_PERSON)
}

/// Build the full-access card for a bundle. `label_max_chars` is the most
/// characters the label line may take on the panel (at least 3).
pub fn full_access_card(
    label: &str,
    label_max_chars: usize,
    client_pubkey: &[u8; 32],
    act_as: &[String],
    style: Style,
) -> FullAccessCard {
    let printable: String = label
        .chars()
        .map(|c| if (' '..='~').contains(&c) { c } else { '?' })
        .collect();
    let room = label_max_chars.max(3);
    let label = if printable.len() <= room {
        printable
    } else {
        format!("{}..", &printable[..room - 2])
    };
    FullAccessCard {
        header: FULL_ACCESS_HEADER,
        label,
        words: pair_words(client_pubkey),
        scope: if act_as_includes_real_name(act_as) {
            SCOPE_PERSONA_AND_REAL_NAME
        } else {
            SCOPE_PERSONA_ONLY
        },
        style_lines: style.card_lines(),
        hold: HOLD_LINE,
    }
}

// ---------------------------------------------------------------------------
// Bundle params (spec 4.1)
// ---------------------------------------------------------------------------

/// A parsed, structurally valid bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleRequest {
    /// 1 to 4 distinct valid persona names, none a child's, in request order.
    pub personas: Vec<String>,
    /// A non-empty distinct subset of `personas`, in request order.
    pub act_as: Vec<String>,
    /// Name to the pubkey My Signet has on file; every key names a persona.
    pub expect: BTreeMap<String, [u8; 32]>,
    pub create: bool,
    pub style: Style,
}

/// `expect` as a map that refuses a repeated key rather than letting the
/// last one win.
struct ExpectMap(BTreeMap<String, String>);

impl<'de> Deserialize<'de> for ExpectMap {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = ExpectMap;
            fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                f.write_str("a map of persona name to hex pubkey")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<ExpectMap, A::Error> {
                let mut out = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, String>()? {
                    if out.insert(key, value).is_some() {
                        return Err(de::Error::custom("duplicate expect entry"));
                    }
                }
                Ok(ExpectMap(out))
            }
        }
        deserializer.deserialize_map(V)
    }
}

/// Present-but-null is refused, not read as absent.
fn some_non_null<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBundle {
    v: u64,
    personas: Vec<String>,
    act_as: Vec<String>,
    #[serde(default, deserialize_with = "some_non_null")]
    expect: Option<ExpectMap>,
    create: bool,
    #[serde(default, deserialize_with = "some_non_null")]
    style: Option<String>,
}

fn has_duplicates(names: &[String]) -> bool {
    names.iter().enumerate().any(|(i, name)| names[..i].contains(name))
}

fn decode_pubkey_hex(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    crate::hex::hex_decode(&value.to_ascii_lowercase()).ok()?.try_into().ok()
}

/// Parse the bundle's NIP-46 params: exactly one param, a JSON string.
pub fn parse_bundle_params(params: &[Value]) -> Result<BundleRequest, BundleError> {
    match params {
        [Value::String(json)] => parse_bundle(json),
        _ => Err(BundleError::Malformed),
    }
}

/// Parse and structurally validate a bundle (every spec 4.1 row that needs
/// neither the slot nor the registry). Order: shape, `v`, `style`;
/// `personas` count, validity and duplicates; any name in either list
/// outside [`BUNDLE_NAMES`] (a child's included, review round W6); `act_as`;
/// `expect`. Every refusal here is `malformed bundle`.
pub fn parse_bundle(json: &str) -> Result<BundleRequest, BundleError> {
    let raw: RawBundle = serde_json::from_str(json).map_err(|_| BundleError::Malformed)?;
    if raw.v != 1 {
        return Err(BundleError::Malformed);
    }
    let style = match raw.style.as_deref() {
        None => Style::Everyday,
        Some(s) => Style::parse(s).ok_or(BundleError::Malformed)?,
    };
    if raw.personas.is_empty() || raw.personas.len() > MAX_BUNDLE_PERSONAS {
        return Err(BundleError::Malformed);
    }
    if raw.personas.iter().any(|name| crate::validate::validate_persona_name(name).is_err())
        || has_duplicates(&raw.personas)
    {
        return Err(BundleError::Malformed);
    }
    if !raw
        .personas
        .iter()
        .chain(raw.act_as.iter())
        .all(|name| BUNDLE_NAMES.contains(&name.as_str()))
    {
        return Err(BundleError::Malformed);
    }
    if raw.act_as.is_empty()
        || has_duplicates(&raw.act_as)
        || !raw.act_as.iter().all(|name| raw.personas.contains(name))
    {
        return Err(BundleError::Malformed);
    }
    let mut expect = BTreeMap::new();
    if let Some(ExpectMap(map)) = raw.expect {
        for (name, value) in map {
            if !raw.personas.contains(&name) {
                return Err(BundleError::Malformed);
            }
            let key = decode_pubkey_hex(&value).ok_or(BundleError::Malformed)?;
            expect.insert(name, key);
        }
    } else if !raw.create {
        return Err(BundleError::Malformed);
    }
    if !raw.create && !raw.personas.iter().all(|name| expect.contains_key(name)) {
        return Err(BundleError::Malformed);
    }
    Ok(BundleRequest {
        personas: raw.personas,
        act_as: raw.act_as,
        expect,
        create: raw.create,
        style,
    })
}

// ---------------------------------------------------------------------------
// Slot checks (spec 4.1 table, the slot rows)
// ---------------------------------------------------------------------------

/// Every client key a slot authorises, from all three places one can live.
fn authorised_client_keys(slot: &ConnectSlot) -> Vec<String> {
    let mut keys: Vec<String> = slot
        .current_pubkey
        .iter()
        .chain(slot.authorized_pubkeys.iter())
        .map(|key| key.to_ascii_lowercase())
        .collect();
    if let Some(grants) = &slot.client_grants {
        keys.extend(grants.client_keys().iter().map(|key| crate::hex::hex_encode(key)));
    }
    keys.sort_unstable();
    keys.dedup();
    keys
}

/// The slot rows of spec 4.1, in table order: bound, non-strict, not
/// escalate, this client alone, `auto_approve`, no kinds list (other than
/// Extra careful's). `slot` is the requesting client's slot
/// (`find_slot_by_pubkey`), `None` when unbound.
///
/// A slot that already carries the owner mark may hold any kinds list
/// (review round W5): an operator may have narrowed it, and the bundle's
/// hold is the consent to replace it with the chosen style's list
/// ([`apply_bundle_press`]). Only a slot without the mark is refused for its
/// list.
pub fn check_bundle_slot(slot: Option<&ConnectSlot>, client_hex: &str) -> Result<(), BundleError> {
    let Some(slot) = slot else {
        return Err(BundleError::Unauthorised);
    };
    if slot.strict_permissions {
        return Err(BundleError::Unauthorised);
    }
    if slot.escalate {
        return Err(BundleError::DeviceApprovalRequired);
    }
    let Some(client) = decode_client_key(client_hex) else {
        return Err(BundleError::Unauthorised);
    };
    let keys = authorised_client_keys(slot);
    if keys.len() != 1 || decode_client_key(&keys[0]) != Some(client) {
        return Err(BundleError::SharedPairing);
    }
    if !slot.auto_approve {
        return Err(BundleError::AsksEveryRequest);
    }
    if !slot_has_owner_mark(slot) && !slot.allowed_kinds.is_empty() && !is_careful_kinds(&slot.allowed_kinds) {
        return Err(BundleError::HasKindsList);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Registry plan (spec 4.1 table, the registry rows)
// ---------------------------------------------------------------------------

/// What the press will do for each name: use a registered key, or derive one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundlePlan {
    /// One per `personas` entry, same order: `Some` when already registered
    /// (its pubkey), `None` when the press must derive and register it.
    pub resolved: Vec<(String, Option<[u8; 32]>)>,
}

impl BundlePlan {
    /// How many names the press derives.
    pub fn derive_count(&self) -> usize {
        self.resolved.iter().filter(|(_, key)| key.is_none()).count()
    }

    /// The registered key of a name, if any.
    pub fn registered(&self, name: &str) -> Option<[u8; 32]> {
        self.resolved.iter().find(|(n, _)| n == name).and_then(|(_, key)| *key)
    }
}

/// Resolve every name against the registry (`lookup`: name to its
/// registered x-only pubkey at index 0, `None` when not registered). Refuses
/// nothing: [`check_bundle_registry`] judges the result, after the room
/// checks (review round W7).
pub fn resolve_bundle(request: &BundleRequest, lookup: impl Fn(&str) -> Option<[u8; 32]>) -> BundlePlan {
    BundlePlan {
        resolved: request
            .personas
            .iter()
            .map(|name| (name.clone(), lookup(name)))
            .collect(),
    }
}

/// The registry rows of spec 4.1: `create: false` with an unregistered name
/// is `persona missing`; an `expect` entry for a registered name that
/// differs is `pubkey mismatch`.
pub fn check_bundle_registry(request: &BundleRequest, plan: &BundlePlan) -> Result<(), BundleError> {
    if !request.create && plan.resolved.iter().any(|(_, key)| key.is_none()) {
        return Err(BundleError::PersonaMissing);
    }
    for (name, key) in &plan.resolved {
        if let (Some(registered), Some(expected)) = (key, request.expect.get(name)) {
            if registered != expected {
                return Err(BundleError::PubkeyMismatch);
            }
        }
    }
    Ok(())
}

/// [`resolve_bundle`] then [`check_bundle_registry`].
pub fn plan_bundle(
    request: &BundleRequest,
    lookup: impl Fn(&str) -> Option<[u8; 32]>,
) -> Result<BundlePlan, BundleError> {
    let plan = resolve_bundle(request, lookup);
    check_bundle_registry(request, &plan)?;
    Ok(plan)
}

/// The `expect` check for a key the press derived (or computed): a name the
/// registry did not hold before the card has no registered key for
/// [`plan_bundle`] to compare, so the firmware compares the derived key here
/// as soon as it has it. Ideally before the card (derivation is a pure
/// computation; only registering is a write), else straight after the
/// derive and before any slot step.
pub fn check_expect(request: &BundleRequest, name: &str, pubkey: &[u8; 32]) -> Result<(), BundleError> {
    match request.expect.get(name) {
        Some(expected) if expected != pubkey => Err(BundleError::PubkeyMismatch),
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Room (spec 4.1 table, the -4 rows)
// ---------------------------------------------------------------------------

/// How many identity grants the slot already holds, in either slot shape.
pub fn slot_grant_count(slot: &ConnectSlot) -> usize {
    match &slot.client_grants {
        Some(grants) => grants.grant_count(),
        None => slot.approved_identities.len() / (IDENTITY_TAG_BYTES * 2),
    }
}

/// How many names the press would add to `allowed_methods`.
pub fn bundle_methods_to_add(slot: &ConnectSlot) -> usize {
    BUNDLE_GRANTED_METHODS
        .iter()
        .filter(|name| !slot.allowed_methods.iter().any(|m| m == *name))
        .count()
}

/// The -4 rows of spec 4.1, in table order: the persona tree and registry
/// room (only when a name must be derived), grant room for the not-yet-
/// granted `act_as` entries, and method-list room. `has_tree` is whether the
/// master has a persona tree; `registry_free` how many more personas the
/// registry can take.
pub fn check_bundle_room(
    slot: &ConnectSlot,
    client_hex: &str,
    request: &BundleRequest,
    plan: &BundlePlan,
    has_tree: bool,
    registry_free: usize,
) -> Result<(), BundleError> {
    let derives = plan.derive_count();
    if derives > 0 && !has_tree {
        return Err(BundleError::NoPersonaTree);
    }
    if derives > registry_free {
        return Err(BundleError::StorageFull);
    }
    let needed = request
        .act_as
        .iter()
        .filter(|name| match plan.registered(name) {
            Some(key) => !client_identity_approved(slot, Some(client_hex), &key),
            None => true,
        })
        .count();
    let room = MAX_APPROVED_IDENTITIES.saturating_sub(slot_grant_count(slot));
    if needed > room {
        return Err(BundleError::ApprovalListFull);
    }
    if slot.allowed_methods.len() + bundle_methods_to_add(slot) > MAX_SLOT_METHODS {
        return Err(BundleError::MethodListFull);
    }
    Ok(())
}

/// Facts about the board the bundle's checks need beyond the slot.
#[derive(Debug, Clone, Copy)]
pub struct BundleBoard {
    /// The master has a persona tree (`requires_tree_mode` would pass).
    pub has_tree: bool,
    /// How many more personas the registry can register.
    pub registry_free: usize,
}

/// Every check of spec 4.1, before any card, in the order that leaks least:
/// the params' shape (needs nothing), then the slot (so an unbound client,
/// a strict slot or a shared pairing learns nothing about the registry),
/// then `admission`, then room, then the registry (`persona missing`,
/// `pubkey mismatch`).
///
/// `admission` is the one-card-at-a-time rule
/// ([`full_access_admission`], review round W3) on the passes that may raise
/// a card, `|| Ok(())` on the pass a hold already answered. It runs before
/// room and the registry (review round 2, S3): after them, a right `expect`
/// guess reached `full access card shown recently` and a wrong one got
/// `pubkey mismatch`, so the minute after any FULL ACCESS card was a
/// card-free oracle. Now every bundle in that minute, or while another
/// waits, gets the same refusal whatever it guesses. A bundle refused here
/// for another waiting still closes that card, though it might later have
/// failed the registry: the same client could as well send a valid one.
///
/// Room before the registry (review round W7): a bound, exclusive
/// Everything slot could otherwise learn, with no card, whether a guessed
/// npub is a name's key, from a `pubkey mismatch` where a match would have
/// failed on room. Now a request that would not fit fails on room whatever
/// it guesses, and one that fits either fails on the registry or raises the
/// card the owner sees. The firmware's derive-then-[`check_expect`] step for
/// names not yet registered runs after this, so after room too.
///
/// On `Ok` the firmware raises the FULL ACCESS card; on `Err` it answers
/// `err.message()` and changes nothing.
pub fn validate_bundle(
    params: &[Value],
    slot: Option<&ConnectSlot>,
    client_hex: &str,
    board: BundleBoard,
    admission: impl FnOnce() -> Result<(), BundleError>,
    lookup: impl Fn(&str) -> Option<[u8; 32]>,
) -> Result<(BundleRequest, BundlePlan), BundleError> {
    let request = parse_bundle_params(params)?;
    check_bundle_slot(slot, client_hex)?;
    let slot = slot.ok_or(BundleError::Unauthorised)?;
    admission()?;
    let plan = resolve_bundle(&request, lookup);
    check_bundle_room(slot, client_hex, &request, &plan, board.has_tree, board.registry_free)?;
    check_bundle_registry(&request, &plan)?;
    Ok((request, plan))
}

// ---------------------------------------------------------------------------
// The press (spec 4.3, steps 2 to 5)
// ---------------------------------------------------------------------------

/// Apply the press to the slot, after step 1 (resolve or derive and register
/// every name) gave `act_as_pubkeys`, the keys of the `act_as` names. Adds
/// and never removes, except the kinds list, which the hold consents to
/// replacing: Extra careful sets exactly [`CAREFUL_KINDS`], and Everyday
/// empties Extra careful's list or, on a slot that already carried the
/// owner mark, any list (review round W5: an operator may have narrowed it).
/// Run inside one snapshot + `persist_slot_mutation_or_rollback`. True when
/// the slot changed.
///
/// Returns `Err(ApprovalListFull)` without a complete grant set only if a
/// grant could not be recorded (the room check should have caught it): the
/// caller must then roll the slot back.
pub fn apply_bundle_press(
    slot: &mut ConnectSlot,
    client_hex: &str,
    act_as_pubkeys: &[[u8; 32]],
    style: Style,
) -> Result<bool, BundleError> {
    let had_mark = slot_has_owner_mark(slot);
    let before = (
        slot.allowed_methods.clone(),
        slot.allowed_kinds.clone(),
        slot.signing_approved,
        slot.approved_identities.clone(),
        slot.client_grants.clone(),
    );
    for identity in act_as_pubkeys {
        if !client_identity_approved(slot, Some(client_hex), identity)
            && !record_client_identity(slot, client_hex, identity)
        {
            return Err(BundleError::ApprovalListFull);
        }
    }
    grant_slot_method(slot, OWNER_MARK);
    grant_slot_method(slot, "heartwood_list_identities");
    grant_slot_method(slot, "nip44_encrypt");
    grant_slot_method(slot, "nip44_decrypt");
    grant_slot_signing(slot);
    match style {
        Style::Careful => slot.allowed_kinds = CAREFUL_KINDS.to_vec(),
        Style::Everyday => {
            if had_mark || is_careful_kinds(&slot.allowed_kinds) {
                slot.allowed_kinds.clear();
            }
        }
    }
    let after = (
        &slot.allowed_methods,
        &slot.allowed_kinds,
        slot.signing_approved,
        &slot.approved_identities,
        &slot.client_grants,
    );
    Ok(after != (&before.0, &before.1, before.2, &before.3, &before.4))
}

/// The bundle's success reply (spec 4.1 "On success"): `pubkeys` has one
/// entry per `personas` name, `act_as` echoes the names granted, `owner` is
/// true, `style` is the style now in force.
pub fn bundle_success_json(pubkeys: &[(String, [u8; 32])], act_as: &[String], style: Style) -> String {
    let mut map = serde_json::Map::new();
    for (name, key) in pubkeys {
        map.insert(name.clone(), Value::String(crate::hex::hex_encode(key)));
    }
    serde_json::json!({
        "v": 1,
        "pubkeys": Value::Object(map),
        "act_as": act_as,
        "owner": true,
        "style": style.as_str(),
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// Owner status and narrow (spec 4.1, 4.6)
// ---------------------------------------------------------------------------

/// `heartwood_owner_status`'s reply for the caller's slot (`None` when
/// unbound): `owner` false on a strict or unbound slot; `style` is
/// `everyday`, `careful` or `custom` ([`slot_style`]).
pub fn owner_status_json(slot: Option<&ConnectSlot>) -> String {
    let owner = slot.is_some_and(is_owner_pairing);
    let style = slot.map_or(SlotStyle::Everyday, slot_style);
    serde_json::json!({ "owner": owner, "style": style.as_str() }).to_string()
}

/// Parse `heartwood_owner_narrow`'s params: one JSON-string param, exactly
/// `{"v":1,"style":"careful"}`.
pub fn parse_narrow_params(params: &[Value]) -> Result<(), BundleError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Raw {
        v: u64,
        style: String,
    }
    let [Value::String(json)] = params else {
        return Err(BundleError::Malformed);
    };
    let raw: Raw = serde_json::from_str(json).map_err(|_| BundleError::Malformed)?;
    if raw.v != 1 || raw.style != "careful" {
        return Err(BundleError::Malformed);
    }
    Ok(())
}

/// Narrow the caller's own owner pairing to Extra careful: sets
/// [`CAREFUL_KINDS`] when `allowed_kinds` is empty, does nothing otherwise
/// (never widens; a custom list stays as it is). `Unauthorised` without the
/// mark (or unbound). Returns whether it changed and the style now in force
/// (`custom` for a list an operator narrowed, review round W4); a change
/// goes through snapshot + `persist_slot_mutation_or_rollback`.
pub fn owner_narrow(slot: Option<&mut ConnectSlot>) -> Result<(bool, SlotStyle), BundleError> {
    let Some(slot) = slot else {
        return Err(BundleError::Unauthorised);
    };
    if !is_owner_pairing(slot) {
        return Err(BundleError::Unauthorised);
    }
    if !slot.allowed_kinds.is_empty() {
        return Ok((false, slot_style(slot)));
    }
    slot.allowed_kinds = CAREFUL_KINDS.to_vec();
    Ok((true, SlotStyle::Careful))
}

/// `heartwood_owner_narrow`'s reply: the style now in force and whether
/// this call changed it.
pub fn owner_narrow_json(style: SlotStyle, changed: bool) -> String {
    serde_json::json!({ "style": style.as_str(), "changed": changed }).to_string()
}

// ---------------------------------------------------------------------------
// One FULL ACCESS card at a time (review round W3)
// ---------------------------------------------------------------------------

/// Whether a bundle that passed every other check may raise a FULL ACCESS
/// card now. `another_waiting`: a FULL ACCESS card is already waiting,
/// queued or on screen; `last_closed_ms`: when the last FULL ACCESS card
/// closed, whatever its outcome (approved, declined, expired, refused), on
/// the same clock as `now_ms`, `None` if none has since boot.
///
/// - Another waiting: [`BundleError::AnotherFullAccess`]. The caller also
///   closes the waiting card with the same reply and grants nothing.
/// - Closed less than [`FULL_ACCESS_COOLDOWN_SECS`] ago:
///   [`BundleError::ShownRecently`], and no card.
///
/// So a client that keeps sending bundles can block pairing, but its bundle
/// never reaches a card the owner might hold while racing another one, and
/// the owner sees the refusals.
pub fn full_access_admission(another_waiting: bool, last_closed_ms: Option<u64>, now_ms: u64) -> Result<(), BundleError> {
    if another_waiting {
        return Err(BundleError::AnotherFullAccess);
    }
    if last_closed_ms.is_some_and(|closed| now_ms.saturating_sub(closed) < FULL_ACCESS_COOLDOWN_SECS * 1000) {
        return Err(BundleError::ShownRecently);
    }
    Ok(())
}

/// [`full_access_admission`], then the card queue's room: `queue_busy` is
/// whether the relay would answer this bundle's card busy
/// (`approval_queue::unshared_ask_busy`; always false on the cable, whose
/// card blocks). The whole of what `validate_bundle`'s admission step
/// checks, after the slot and before room and the registry, so a full queue
/// gives a right and a wrong `expect` guess the same answer (review round
/// 2). Another FULL ACCESS card waiting comes first, so a racing bundle
/// still closes it however full the queue is.
pub fn bundle_admission(
    another_waiting: bool,
    queue_busy: bool,
    last_closed_ms: Option<u64>,
    now_ms: u64,
) -> Result<(), BundleError> {
    full_access_admission(another_waiting, last_closed_ms, now_ms)?;
    if queue_busy {
        return Err(BundleError::QueueBusy);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Rule V and Rule D (spec 6)
// ---------------------------------------------------------------------------

/// Whether a context purpose is a vault purpose: the prefix and at least one
/// character after it.
pub fn is_vault_purpose(purpose: &str) -> bool {
    purpose.len() > VAULT_PURPOSE_PREFIX.len() && purpose.starts_with(VAULT_PURPOSE_PREFIX)
}

/// What Rule V needs to know about a request's context, built the same way by
/// the handler's `plan_gate` and the relay's pre-dispatch planner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VaultContext {
    /// The caller SUPPLIED a Heartwood context (top-level `heartwood`) whose
    /// purpose is a vault purpose. A session's active identity
    /// (`resolve_active_context`) never counts.
    pub explicit_vault: bool,
    /// The kind of the event to sign, for `sign_event`.
    pub event_kind: Option<u64>,
}

impl VaultContext {
    /// No vault context: every gate decision is today's.
    pub const NONE: Self = Self { explicit_vault: false, event_kind: None };

    /// From the caller-supplied context's purpose (`None` when the caller
    /// supplied none) and the event kind (for `sign_event`).
    pub fn from_explicit(explicit_purpose: Option<&str>, event_kind: Option<u64>) -> Self {
        Self {
            explicit_vault: explicit_purpose.is_some_and(is_vault_purpose),
            event_kind,
        }
    }
}

/// Rule V's method set: `get_public_key`, `nip44_encrypt`, `nip44_decrypt`,
/// and `sign_event` / `sign_event_compact` of kind 30078.
pub fn rule_v_method(method: &str, event_kind: Option<u64>) -> bool {
    match method {
        "get_public_key" | "nip44_encrypt" | "nip44_decrypt" => true,
        "sign_event" | "sign_event_compact" => event_kind == Some(VAULT_EVENT_KIND),
        _ => false,
    }
}

/// Rule V: on an owner pairing, a request with an explicit vault context and
/// a Rule V method skips the identity card (nothing recorded). The tier still
/// applies; `policy::gate_request_with_vault` calls this at its place in the
/// gate.
pub fn rule_v_allows(slot: &ConnectSlot, method: &str, explicit_context: bool, vault: VaultContext) -> bool {
    explicit_context && vault.explicit_vault && is_owner_pairing(slot) && rule_v_method(method, vault.event_kind)
}

/// A real identity's registry name: the owner's `natural-person`, or a
/// child's `dependant-<n>-np` (read broadly: any `dependant-` name ending
/// `-np`, so nothing shaped like a child's real key slips through).
pub fn is_real_identity_name(name: &str) -> bool {
    name == NATURAL_PERSON
        || (name.len() > DEPENDANT_PREFIX.len() + 3
            && name.starts_with(DEPENDANT_PREFIX)
            && name.ends_with("-np"))
}

/// Rule D: whether a `heartwood_derive_persona` on this slot records the new
/// identity for the requesting client (`record_client_identity`). Only on an
/// owner pairing, only for a name this derive newly registered (never for a
/// lookup of an existing name), never for a real identity, and only while
/// the grant list has room. Its approval tier is unchanged.
pub fn rule_d_records(slot: &ConnectSlot, name: &str, newly_registered: bool) -> bool {
    newly_registered && is_owner_pairing(slot) && !is_real_identity_name(name) && can_record_client_identity(slot)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{
        authorize_pubkey_on_slot, sanitise_imported_slot, EXACT_POLICY_METHODS,
    };
    use alloc::vec;

    const CLIENT: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const OTHER: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const NP: [u8; 32] = [0x11; 32];
    const PERSONA: [u8; 32] = [0x33; 32];

    fn hex(key: &[u8; 32]) -> String {
        crate::hex::hex_encode(key)
    }

    /// An "Everything" pairing made over the cable: non-strict, auto, no
    /// kinds list, bound to CLIENT alone.
    fn everything_slot() -> ConnectSlot {
        ConnectSlot {
            slot_index: 0,
            label: "My Signet".to_string(),
            secret: "ab".repeat(32),
            current_pubkey: Some(CLIENT.to_string()),
            allowed_methods: vec!["nip44_encrypt".into(), "nip44_decrypt".into(), "get_public_key".into()],
            allowed_kinds: vec![],
            auto_approve: true,
            signing_approved: false,
            strict_permissions: false,
            authorized_pubkeys: vec![CLIENT.to_string()],
            escalate: false,
            petition_on_deny: false,
            audit_child_wrap: false,
            guardian_notice_wrap: false,
            bound_identity: None,
            approved_identities: String::new(),
            was_bound: true,
            client_grants: None,
        }
    }

    fn owner_slot() -> ConnectSlot {
        let mut slot = everything_slot();
        apply_bundle_press(&mut slot, CLIENT, &[PERSONA], Style::Everyday).unwrap();
        slot
    }

    fn bundle(json: &str) -> Result<BundleRequest, BundleError> {
        parse_bundle_params(&[Value::String(json.to_string())])
    }

    fn create_bundle() -> String {
        r#"{"v":1,"personas":["natural-person","persona"],"act_as":["persona"],"create":true}"#.to_string()
    }

    fn registry(name: &str) -> Option<[u8; 32]> {
        match name {
            "natural-person" => Some(NP),
            "persona" => Some(PERSONA),
            _ => None,
        }
    }

    /// A registry holding the persona alone: the real identity is derived
    /// by the press.
    fn persona_only(name: &str) -> Option<[u8; 32]> {
        (name == "persona").then_some(PERSONA)
    }

    // --- 4.2 words and card ---

    #[test]
    fn the_pairing_words_match_the_frozen_vector() {
        // The vector My Signet checks its own computation against.
        let key = decode_client_key(CLIENT).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(b"heartwood-pair-words\0");
        hasher.update(key);
        let d = hasher.finalize();
        let by_hand = [0, 1, 2, 3, 4].map(|i| {
            spoken_words::word(usize::from(u16::from_be_bytes([d[2 * i], d[2 * i + 1]])) % 2048)
        });
        assert_eq!(pair_words(&key), by_hand);
        assert_eq!(pair_words_hex(CLIENT), Some(by_hand));
        // Five words from d[0..10] (review round W1); the first three are
        // the three-word card's, unchanged.
        assert_eq!(pair_words(&key), ["nice", "never", "repair", "area", "upgrade"]);
        assert!(pair_words(&key).iter().all(|w| w.len() <= spoken_words::WORDLIST_MAX_LEN));
        assert_eq!(pair_words_hex("not hex"), None);
        assert_eq!(pair_words_hex(&CLIENT.to_ascii_uppercase()), None, "lowercase hex only");
    }

    #[test]
    fn the_full_access_card_reads_as_the_spec_draws_it() {
        let key = decode_client_key(CLIENT).unwrap();
        let card = full_access_card("My Signet", 21, &key, &["persona".to_string()], Style::Everyday);
        let w = pair_words(&key);
        assert_eq!(
            card.lines(),
            vec![
                "FULL ACCESS".to_string(),
                "My Signet".to_string(),
                format!("{} {}", w[0], w[1]),
                format!("{} {}", w[2], w[3]),
                w[4].to_string(),
                "PERSONA ONLY".to_string(),
                "SIGN IN, POST, BACKUP".to_string(),
                "HOLD 5 SECONDS".to_string(),
            ]
        );
        // The three word lines are the three pages the board turns through.
        assert_eq!(pair_word_page(&w, 0), vec![(1, w[0]), (2, w[1])]);
        assert_eq!(pair_word_page(&w, 1), vec![(3, w[2]), (4, w[3])]);
        assert_eq!(pair_word_page(&w, 2), vec![(5, w[4])]);
        assert_eq!(pair_word_page(&w, PAIR_WORD_PAGES), pair_word_page(&w, 0), "a page past the last wraps");
        assert_eq!(PAIR_WORD_PAGES, 3);
        // The board's hint offers no hold until every page has been shown.
        assert_eq!(full_access_hint(false), "COMPARE ALL 5 WORDS");
        assert_eq!(full_access_hint(true), HOLD_LINE);
        let careful = full_access_card(
            "My Signet",
            21,
            &key,
            &["natural-person".to_string(), "persona".to_string()],
            Style::Careful,
        );
        let lines = careful.lines();
        assert_eq!(lines[5], "PERSONA + REAL NAME");
        assert_eq!(&lines[6..8], &["ALONE: BACKUPS, APP DATA".to_string(), "ASKS: EVERYTHING ELSE".to_string()]);
        assert_eq!(lines.last().unwrap(), "HOLD 5 SECONDS");
        assert_eq!(lines.len(), 9);
    }

    #[test]
    fn the_longest_fixed_card_line_is_24_characters() {
        // The spec's own words, which My Signet shows verbatim, so they are
        // not shortened here. `ALONE: BACKUPS, APP DATA` (review round W9) is
        // 24 characters, what the Heltec's span holds in its 5 px small font
        // (ui-preview checks every panel). The OLED builder lays them out; it
        // never rewords them.
        let longest = [FULL_ACCESS_HEADER, SCOPE_PERSONA_ONLY, SCOPE_PERSONA_AND_REAL_NAME, HOLD_LINE]
            .iter()
            .chain(EVERYDAY_LINES)
            .chain(CAREFUL_LINES)
            .map(|line| line.len())
            .max();
        assert_eq!(longest, Some(24));
        assert_eq!(CAREFUL_LINES[0].len(), 24);
        // Extra careful's line names both things that sign alone, never less.
        assert!(CAREFUL_LINES[0].contains("BACKUPS") && CAREFUL_LINES[0].contains("APP DATA"));
        // Two longest words and a space: one page's line.
        assert!(2 * spoken_words::WORDLIST_MAX_LEN + 1 <= 24);
    }

    #[test]
    fn the_card_label_is_printable_ascii_and_clamped() {
        let key = [7u8; 32];
        let card = full_access_card("Phone\u{202e}\n\u{e9}", 21, &key, &["persona".to_string()], Style::Everyday);
        assert_eq!(card.label, "Phone???");
        let long = full_access_card(&"x".repeat(40), 10, &key, &["persona".to_string()], Style::Everyday);
        assert_eq!(long.label, format!("{}..", "x".repeat(8)));
        assert_eq!(long.label.len(), 10);
    }

    #[test]
    fn only_the_full_access_builder_uses_the_full_access_header() {
        // Spec 4.2: no other card may use the inverted FULL ACCESS bar. This
        // pins common's card-text sources (the header as a string literal);
        // ui-preview should pin the firmware's builders the same way.
        let literal = format!("\"{}\"", ["FULL", " ACCESS"].concat());
        let sources: &[(&str, &str)] = &[
            ("approval_queue.rs", include_str!("approval_queue.rs")),
            ("escalate.rs", include_str!("escalate.rs")),
            ("nip59.rs", include_str!("nip59.rs")),
            ("note_cmd.rs", include_str!("note_cmd.rs")),
            ("note_fmt.rs", include_str!("note_fmt.rs")),
            ("phone_unlock.rs", include_str!("phone_unlock.rs")),
            ("policy.rs", include_str!("policy.rs")),
            ("nip46.rs", include_str!("nip46.rs")),
            ("kinds.rs", include_str!("kinds.rs")),
            ("types.rs", include_str!("types.rs")),
            ("net_config.rs", include_str!("net_config.rs")),
        ];
        for (name, source) in sources {
            assert!(!source.contains(&literal), "{name} spells the FULL ACCESS header");
        }
        assert_eq!(format!("\"{FULL_ACCESS_HEADER}\""), literal);
    }

    // --- 4.1 params ---

    #[test]
    fn a_well_formed_bundle_parses() {
        let request = bundle(&create_bundle()).unwrap();
        assert_eq!(request.personas, vec!["natural-person", "persona"]);
        assert_eq!(request.act_as, vec!["persona"]);
        assert!(request.create);
        assert!(request.expect.is_empty());
        assert_eq!(request.style, Style::Everyday);
        let with_expect = format!(
            r#"{{"v":1,"personas":["natural-person","persona"],"act_as":["natural-person","persona"],"expect":{{"natural-person":"{}","persona":"{}"}},"create":false,"style":"careful"}}"#,
            hex(&NP),
            hex(&PERSONA).to_ascii_uppercase()
        );
        let request = bundle(&with_expect).unwrap();
        assert!(!request.create);
        assert_eq!(request.style, Style::Careful);
        assert_eq!(request.expect.get("persona"), Some(&PERSONA));
    }

    #[test]
    fn every_malformed_row_is_refused() {
        let np = hex(&NP);
        let cases: Vec<String> = vec![
            // Not exactly one string param is handled below; these are bodies.
            "not json".into(),
            "[]".into(),
            r#"{"v":2,"personas":["persona"],"act_as":["persona"],"create":true}"#.into(),
            r#"{"v":"1","personas":["persona"],"act_as":["persona"],"create":true}"#.into(),
            r#"{"personas":["persona"],"act_as":["persona"],"create":true}"#.into(),
            r#"{"v":1,"personas":["persona"],"act_as":["persona"],"create":"yes"}"#.into(),
            r#"{"v":1,"personas":["persona"],"act_as":["persona"]}"#.into(),
            r#"{"v":1,"personas":["persona"],"act_as":["persona"],"create":true,"style":"loose"}"#.into(),
            r#"{"v":1,"personas":["persona"],"act_as":["persona"],"create":true,"style":null}"#.into(),
            r#"{"v":1,"personas":["persona"],"act_as":["persona"],"create":true,"extra":1}"#.into(),
            // create:false needs expect, covering every name.
            r#"{"v":1,"personas":["persona"],"act_as":["persona"],"create":false}"#.into(),
            format!(r#"{{"v":1,"personas":["natural-person","persona"],"act_as":["persona"],"expect":{{"natural-person":"{np}"}},"create":false}}"#),
            r#"{"v":1,"personas":["persona"],"act_as":["persona"],"expect":null,"create":true}"#.into(),
            // 1 to 4 personas, valid, distinct.
            r#"{"v":1,"personas":[],"act_as":["persona"],"create":true}"#.into(),
            r#"{"v":1,"personas":["a","b","c","d","e"],"act_as":["a"],"create":true}"#.into(),
            r#"{"v":1,"personas":["persona","persona"],"act_as":["persona"],"create":true}"#.into(),
            r#"{"v":1,"personas":[""],"act_as":[""],"create":true}"#.into(),
            r#"{"v":1,"personas":["a|b"],"act_as":["a|b"],"create":true}"#.into(),
            // act_as a non-empty, distinct subset.
            r#"{"v":1,"personas":["persona"],"act_as":[],"create":true}"#.into(),
            r#"{"v":1,"personas":["persona"],"act_as":["persona","persona"],"create":true}"#.into(),
            r#"{"v":1,"personas":["persona"],"act_as":["natural-person"],"create":true}"#.into(),
            // expect names only listed personas, with 64-hex keys, once each.
            format!(r#"{{"v":1,"personas":["persona"],"act_as":["persona"],"expect":{{"other":"{np}"}},"create":true}}"#),
            r#"{"v":1,"personas":["persona"],"act_as":["persona"],"expect":{"persona":"abc"},"create":true}"#.into(),
            format!(r#"{{"v":1,"personas":["persona"],"act_as":["persona"],"expect":{{"persona":"{np}","persona":"{np}"}},"create":true}}"#),
            r#"{"v":1,"v":1,"personas":["persona"],"act_as":["persona"],"create":true}"#.into(),
        ];
        for case in &cases {
            assert_eq!(bundle(case), Err(BundleError::Malformed), "{case}");
        }
        let good = Value::String(create_bundle());
        assert_eq!(parse_bundle_params(&[]), Err(BundleError::Malformed));
        assert_eq!(parse_bundle_params(&[good.clone(), good.clone()]), Err(BundleError::Malformed));
        assert_eq!(
            parse_bundle_params(&[serde_json::from_str::<Value>(&create_bundle()).unwrap()]),
            Err(BundleError::Malformed),
            "the param is a JSON string, not an object"
        );
        assert!(parse_bundle_params(&[good]).is_ok());
    }

    #[test]
    fn a_bundle_names_only_the_persona_and_the_real_identity() {
        // Review round W6: the card's scope line names PERSONA and REAL
        // NAME, so a bundle may carry nothing else. A child's name, an extra
        // persona or any other valid persona name is a malformed bundle, in
        // either list.
        for case in [
            r#"{"v":1,"personas":["dependant-0-np"],"act_as":["dependant-0-np"],"create":true}"#,
            r#"{"v":1,"personas":["persona","dependant-1-persona"],"act_as":["persona"],"create":true}"#,
            r#"{"v":1,"personas":["persona"],"act_as":["dependant-0-persona"],"create":true}"#,
            r#"{"v":1,"personas":["persona","work"],"act_as":["persona","work"],"create":true}"#,
            r#"{"v":1,"personas":["persona","work","anon"],"act_as":["persona"],"create":true}"#,
            r#"{"v":1,"personas":["persona-1"],"act_as":["persona-1"],"create":true}"#,
            r#"{"v":1,"personas":["Persona"],"act_as":["Persona"],"create":true}"#,
        ] {
            assert_eq!(bundle(case), Err(BundleError::Malformed), "{case}");
        }
        assert_eq!(MAX_BUNDLE_PERSONAS, 2);
        for (personas, act_as) in [
            (r#"["persona"]"#, r#"["persona"]"#),
            (r#"["natural-person"]"#, r#"["natural-person"]"#),
            (r#"["natural-person","persona"]"#, r#"["persona"]"#),
            (r#"["persona","natural-person"]"#, r#"["natural-person","persona"]"#),
        ] {
            let json = format!(r#"{{"v":1,"personas":{personas},"act_as":{act_as},"create":true}}"#);
            assert!(bundle(&json).is_ok(), "{json}");
        }
    }

    #[test]
    fn create_false_with_a_missing_name_is_refused_before_the_card() {
        let json = format!(
            r#"{{"v":1,"personas":["persona","natural-person"],"act_as":["persona"],"expect":{{"persona":"{}","natural-person":"{}"}},"create":false}}"#,
            hex(&PERSONA),
            hex(&NP)
        );
        let request = bundle(&json).unwrap();
        assert_eq!(plan_bundle(&request, persona_only), Err(BundleError::PersonaMissing));
        let slot = everything_slot();
        let before = slot.clone();
        let params = [Value::String(json)];
        let board = BundleBoard { has_tree: true, registry_free: 8 };
        assert_eq!(
            validate_bundle(&params, Some(&slot), CLIENT, board, || Ok(()), persona_only).unwrap_err(),
            BundleError::PersonaMissing
        );
        // Validation is pure: the slot is untouched.
        assert_eq!(slot.allowed_methods, before.allowed_methods);
        assert!(!slot_has_owner_mark(&slot));
    }

    #[test]
    fn an_expect_mismatch_is_refused_before_the_card() {
        let request = bundle(&format!(
            r#"{{"v":1,"personas":["natural-person","persona"],"act_as":["persona"],"expect":{{"natural-person":"{}","persona":"{}"}},"create":false}}"#,
            hex(&[0x99; 32]),
            hex(&PERSONA)
        ))
        .unwrap();
        assert_eq!(plan_bundle(&request, registry), Err(BundleError::PubkeyMismatch));
        // A match plans with every name resolved.
        let ok = bundle(&format!(
            r#"{{"v":1,"personas":["natural-person","persona"],"act_as":["persona"],"expect":{{"natural-person":"{}","persona":"{}"}},"create":false}}"#,
            hex(&NP),
            hex(&PERSONA)
        ))
        .unwrap();
        let plan = plan_bundle(&ok, registry).unwrap();
        assert_eq!(plan.derive_count(), 0);
        assert_eq!(plan.registered("persona"), Some(PERSONA));
        // A name the press derives is checked once its key exists.
        let derive = bundle(&format!(
            r#"{{"v":1,"personas":["natural-person"],"act_as":["natural-person"],"expect":{{"natural-person":"{}"}},"create":true}}"#,
            hex(&NP)
        ))
        .unwrap();
        let plan = plan_bundle(&derive, persona_only).unwrap();
        assert_eq!(plan.derive_count(), 1);
        assert_eq!(check_expect(&derive, "natural-person", &PERSONA), Err(BundleError::PubkeyMismatch));
        assert_eq!(check_expect(&derive, "natural-person", &NP), Ok(()));
        assert_eq!(check_expect(&derive, "persona", &NP), Ok(()), "a name with no expect entry");
    }

    #[test]
    fn room_is_checked_before_the_registry_so_a_guess_learns_nothing_without_a_card() {
        // Review round W7. A bound, exclusive Everything slot guesses the
        // persona's npub. With no room for the press, a right and a wrong
        // guess get the same room refusal; with room, a wrong guess is
        // refused and a right one raises the card (the owner sees it).
        let guess = |key: [u8; 32]| {
            [Value::String(format!(
                r#"{{"v":1,"personas":["persona"],"act_as":["persona"],"expect":{{"persona":"{}"}},"create":false}}"#,
                hex(&key)
            ))]
        };
        let board = BundleBoard { has_tree: true, registry_free: 8 };
        let mut full = everything_slot();
        for i in 0..16u8 {
            assert!(record_client_identity(&mut full, CLIENT, &[0x40 + i; 32]));
        }
        for key in [PERSONA, [0x99; 32]] {
            assert_eq!(
                validate_bundle(&guess(key), Some(&full), CLIENT, board, || Ok(()), registry).unwrap_err(),
                BundleError::ApprovalListFull,
                "no room: the same answer whatever the guess"
            );
        }
        let room = everything_slot();
        assert_eq!(
            validate_bundle(&guess([0x99; 32]), Some(&room), CLIENT, board, || Ok(()), registry).unwrap_err(),
            BundleError::PubkeyMismatch
        );
        assert!(validate_bundle(&guess(PERSONA), Some(&room), CLIENT, board, || Ok(()), registry).is_ok());
        // A missing name with create:false the same way: room first.
        let missing = [Value::String(format!(
            r#"{{"v":1,"personas":["natural-person"],"act_as":["natural-person"],"expect":{{"natural-person":"{}"}},"create":false}}"#,
            hex(&NP)
        ))];
        assert_eq!(
            validate_bundle(&missing, Some(&full), CLIENT, board, || Ok(()), persona_only).unwrap_err(),
            BundleError::ApprovalListFull
        );
        assert_eq!(
            validate_bundle(&missing, Some(&room), CLIENT, board, || Ok(()), persona_only).unwrap_err(),
            BundleError::PersonaMissing
        );
    }

    #[test]
    fn the_one_card_rule_comes_before_room_and_the_registry_so_a_guess_learns_nothing() {
        // Review round 2, S3. During the minute after a FULL ACCESS card
        // closed, or while another waits, a right and a wrong `expect` guess
        // get the same refusal, and the registry is never read; outside it,
        // a wrong guess is refused and a right one passes to the card.
        let guess = |key: [u8; 32]| {
            [Value::String(format!(
                r#"{{"v":1,"personas":["persona"],"act_as":["persona"],"expect":{{"persona":"{}"}},"create":false}}"#,
                hex(&key)
            ))]
        };
        let board = BundleBoard { has_tree: true, registry_free: 8 };
        let slot = everything_slot();
        let unread = |_: &str| -> Option<[u8; 32]> { panic!("registry read before the one-card rule") };
        let closed = 1_000_000u64;
        for (waiting, now, refusal) in [
            (false, closed + 30_000, BundleError::ShownRecently),
            (true, closed + 30_000, BundleError::AnotherFullAccess),
            (true, closed + 600_000, BundleError::AnotherFullAccess),
        ] {
            for key in [PERSONA, [0x99; 32]] {
                assert_eq!(
                    validate_bundle(
                        &guess(key),
                        Some(&slot),
                        CLIENT,
                        board,
                        || full_access_admission(waiting, Some(closed), now),
                        unread,
                    )
                    .unwrap_err(),
                    refusal,
                    "the same answer whatever the guess"
                );
            }
        }
        // Room comes after the rule too: a slot with no room is refused by
        // the rule first.
        let mut full = everything_slot();
        for i in 0..16u8 {
            assert!(record_client_identity(&mut full, CLIENT, &[0x40 + i; 32]));
        }
        assert_eq!(
            validate_bundle(
                &guess(PERSONA),
                Some(&full),
                CLIENT,
                board,
                || full_access_admission(false, Some(closed), closed + 1),
                unread,
            )
            .unwrap_err(),
            BundleError::ShownRecently
        );
        // A full card queue the same way (review round 2): busy whatever
        // the guess, and a bundle racing a waiting card still closes it.
        for key in [PERSONA, [0x99; 32]] {
            assert_eq!(
                validate_bundle(
                    &guess(key),
                    Some(&slot),
                    CLIENT,
                    board,
                    || bundle_admission(false, true, None, closed),
                    unread,
                )
                .unwrap_err(),
                BundleError::QueueBusy
            );
        }
        assert_eq!(bundle_admission(true, true, None, closed), Err(BundleError::AnotherFullAccess));
        assert_eq!(bundle_admission(false, true, Some(closed), closed + 1), Err(BundleError::ShownRecently));
        assert_eq!(bundle_admission(false, false, Some(closed), closed + 60_000), Ok(()));
        assert_eq!(BundleError::QueueBusy.message(), "signer is busy with another approval; retry shortly");
        assert_eq!(BundleError::QueueBusy.code(), -1);
        // Past the minute with nothing waiting, the registry decides.
        let after = || full_access_admission(false, Some(closed), closed + 60_000);
        assert_eq!(
            validate_bundle(&guess([0x99; 32]), Some(&slot), CLIENT, board, after, registry).unwrap_err(),
            BundleError::PubkeyMismatch
        );
        assert!(validate_bundle(&guess(PERSONA), Some(&slot), CLIENT, board, after, registry).is_ok());
    }

    // --- 4.1 slot rows ---

    #[test]
    fn every_slot_row_is_refused_with_its_message() {
        assert_eq!(check_bundle_slot(Some(&everything_slot()), CLIENT), Ok(()));
        assert_eq!(check_bundle_slot(None, CLIENT), Err(BundleError::Unauthorised));

        let mut strict = everything_slot();
        strict.strict_permissions = true;
        assert_eq!(check_bundle_slot(Some(&strict), CLIENT), Err(BundleError::Unauthorised));

        let mut escalate = everything_slot();
        escalate.escalate = true;
        assert_eq!(check_bundle_slot(Some(&escalate), CLIENT), Err(BundleError::DeviceApprovalRequired));
        assert_eq!(BundleError::DeviceApprovalRequired.message(), crate::escalate::DEVICE_APPROVAL_REQUIRED);

        let mut shared = everything_slot();
        shared.authorized_pubkeys.push(OTHER.to_string());
        assert_eq!(check_bundle_slot(Some(&shared), CLIENT), Err(BundleError::SharedPairing));
        let mut other_current = everything_slot();
        other_current.current_pubkey = Some(OTHER.to_string());
        assert_eq!(check_bundle_slot(Some(&other_current), CLIENT), Err(BundleError::SharedPairing));
        let mut grant_member = everything_slot();
        let mut snapshot = crate::client_grants::GrantSnapshot::from_legacy(&grant_member).unwrap();
        snapshot.add_client(decode_client_key(OTHER).unwrap()).unwrap();
        grant_member.client_grants = Some(snapshot);
        assert_eq!(check_bundle_slot(Some(&grant_member), CLIENT), Err(BundleError::SharedPairing));

        let mut asks = everything_slot();
        asks.auto_approve = false;
        assert_eq!(check_bundle_slot(Some(&asks), CLIENT), Err(BundleError::AsksEveryRequest));

        let mut posting = everything_slot();
        posting.allowed_kinds = vec![1, 7];
        assert_eq!(check_bundle_slot(Some(&posting), CLIENT), Err(BundleError::HasKindsList));
        let mut careful = everything_slot();
        careful.allowed_kinds = vec![22242, 30078];
        assert_eq!(check_bundle_slot(Some(&careful), CLIENT), Ok(()), "Extra careful's list may re-run");
        let mut careful_plus = everything_slot();
        careful_plus.allowed_kinds = vec![22242, 30078, 1];
        assert_eq!(check_bundle_slot(Some(&careful_plus), CLIENT), Err(BundleError::HasKindsList));

        for (error, message) in [
            (BundleError::SharedPairing, "unauthorised: pairing shared by another device"),
            (BundleError::AsksEveryRequest, "unauthorised: pairing asks for every request"),
            (BundleError::HasKindsList, "unauthorised: pairing has a kinds list"),
            (BundleError::Unauthorised, "unauthorised"),
        ] {
            assert_eq!(error.message(), message);
        }
    }

    #[test]
    fn slot_refusals_come_before_the_registry_is_consulted() {
        // An unbound or strict caller learns nothing about names or keys.
        let params = [Value::String(format!(
            r#"{{"v":1,"personas":["persona"],"act_as":["persona"],"expect":{{"persona":"{}"}},"create":false}}"#,
            hex(&[0x99; 32])
        ))];
        let board = BundleBoard { has_tree: true, registry_free: 8 };
        let lookup = |_: &str| -> Option<[u8; 32]> { panic!("registry consulted before the slot checks") };
        // Nor does the one-card rule run first: an unbound client must not
        // close the owner's waiting card (review round 2, S3).
        let admission = || -> Result<(), BundleError> { panic!("admission checked before the slot checks") };
        assert_eq!(validate_bundle(&params, None, CLIENT, board, admission, lookup).unwrap_err(), BundleError::Unauthorised);
        let mut strict = everything_slot();
        strict.strict_permissions = true;
        assert_eq!(
            validate_bundle(&params, Some(&strict), CLIENT, board, admission, lookup).unwrap_err(),
            BundleError::Unauthorised
        );
    }

    // --- 4.1 room rows ---

    #[test]
    fn the_room_rows_refuse_when_the_press_would_not_fit() {
        let slot = everything_slot();
        let request = bundle(r#"{"v":1,"personas":["persona","natural-person"],"act_as":["persona","natural-person"],"create":true}"#).unwrap();
        let plan = plan_bundle(&request, persona_only).unwrap();
        assert_eq!(plan.derive_count(), 1);
        assert_eq!(check_bundle_room(&slot, CLIENT, &request, &plan, true, 1), Ok(()));
        assert_eq!(check_bundle_room(&slot, CLIENT, &request, &plan, false, 1), Err(BundleError::NoPersonaTree));
        assert_eq!(check_bundle_room(&slot, CLIENT, &request, &plan, true, 0), Err(BundleError::StorageFull));

        // A bundle that derives nothing needs no tree and no registry room.
        let lookup_only = bundle(&create_bundle()).unwrap();
        let plan_only = plan_bundle(&lookup_only, registry).unwrap();
        assert_eq!(check_bundle_room(&slot, CLIENT, &lookup_only, &plan_only, false, 0), Ok(()));

        // Grant room: 15 recorded leaves room for one, not two.
        let mut nearly_full = everything_slot();
        for i in 0..15u8 {
            assert!(record_client_identity(&mut nearly_full, CLIENT, &[0x40 + i; 32]));
        }
        assert_eq!(slot_grant_count(&nearly_full), 15);
        assert_eq!(
            check_bundle_room(&nearly_full, CLIENT, &request, &plan, true, 8),
            Err(BundleError::ApprovalListFull)
        );
        assert_eq!(check_bundle_room(&nearly_full, CLIENT, &lookup_only, &plan_only, true, 8), Ok(()));
        // An identity already granted needs no room.
        let mut full = nearly_full.clone();
        assert!(record_client_identity(&mut full, CLIENT, &PERSONA));
        assert_eq!(check_bundle_room(&full, CLIENT, &lookup_only, &plan_only, true, 8), Ok(()));

        // Method room: 32-name cap, counting only names the press adds.
        let mut crowded = everything_slot();
        while crowded.allowed_methods.len() < MAX_SLOT_METHODS - 1 {
            let n = crowded.allowed_methods.len();
            crowded.allowed_methods.push(format!("x{n}"));
        }
        assert_eq!(bundle_methods_to_add(&crowded), 3);
        assert_eq!(
            check_bundle_room(&crowded, CLIENT, &lookup_only, &plan_only, true, 8),
            Err(BundleError::MethodListFull)
        );
        let marked = owner_slot();
        assert_eq!(bundle_methods_to_add(&marked), 0);

        for (error, code, message) in [
            (BundleError::NoPersonaTree, -4, "no persona tree on this master"),
            (BundleError::StorageFull, -4, "storage full"),
            (BundleError::ApprovalListFull, -4, "approval list full"),
            (BundleError::MethodListFull, -4, "method list full"),
            (BundleError::Malformed, -3, "malformed bundle"),
            (BundleError::PersonaMissing, -3, "persona missing"),
            (BundleError::PubkeyMismatch, -3, "pubkey mismatch"),
        ] {
            assert_eq!((error.code(), error.message()), (code, message));
        }
    }

    // --- 4.3 the press ---

    #[test]
    fn the_press_grants_the_mark_signing_and_the_names() {
        let mut slot = everything_slot();
        assert!(apply_bundle_press(&mut slot, CLIENT, &[PERSONA], Style::Everyday).unwrap());
        assert!(is_owner_pairing(&slot));
        for name in BUNDLE_GRANTED_METHODS {
            assert!(slot.allowed_methods.iter().any(|m| m == name), "{name}");
        }
        assert_eq!(slot.allowed_methods[0], "sign_event");
        assert!(slot.signing_approved);
        assert!(slot.allowed_kinds.is_empty());
        assert!(client_identity_approved(&slot, Some(CLIENT), &PERSONA));
        assert!(!client_identity_approved(&slot, Some(CLIENT), &NP));
        assert!(!slot.allowed_methods.iter().any(|m| m == BUNDLE_METHOD));
        assert!(!EXACT_POLICY_METHODS.contains(&OWNER_MARK));
        assert!(!EXACT_POLICY_METHODS.contains(&BUNDLE_METHOD));
    }

    #[test]
    fn running_it_again_adds_and_never_removes() {
        let mut slot = owner_slot();
        slot.allowed_methods.push("heartwood_derive_persona".into());
        let before = slot.clone();
        assert!(!apply_bundle_press(&mut slot, CLIENT, &[PERSONA], Style::Everyday).unwrap(), "a no-op re-run");
        assert_eq!(slot.allowed_methods, before.allowed_methods);
        assert!(apply_bundle_press(&mut slot, CLIENT, &[PERSONA, NP], Style::Everyday).unwrap());
        assert!(client_identity_approved(&slot, Some(CLIENT), &PERSONA));
        assert!(client_identity_approved(&slot, Some(CLIENT), &NP));
        for name in &before.allowed_methods {
            assert!(slot.allowed_methods.contains(name), "{name}");
        }
    }

    #[test]
    fn the_style_sets_exactly_the_careful_list_and_everyday_empties_only_it() {
        let mut slot = everything_slot();
        apply_bundle_press(&mut slot, CLIENT, &[PERSONA], Style::Careful).unwrap();
        assert_eq!(slot.allowed_kinds, vec![30078, 22242]);
        assert!(is_careful_kinds(&slot.allowed_kinds));
        assert_eq!(slot_style(&slot), SlotStyle::Careful);
        apply_bundle_press(&mut slot, CLIENT, &[PERSONA], Style::Everyday).unwrap();
        assert!(slot.allowed_kinds.is_empty());
        assert_eq!(slot_style(&slot), SlotStyle::Everyday);
        assert!(!is_careful_kinds(&[30078]));
        assert!(!is_careful_kinds(&[30078, 22242, 30078]));
        assert!(is_careful_kinds(&[22242, 30078]));
    }

    #[test]
    fn on_a_marked_slot_the_hold_replaces_any_kinds_list() {
        // Review round W5: an operator narrowed an owner pairing's list. The
        // bundle is no longer refused for it, and the press sets the chosen
        // style's list exactly.
        for (style, expected) in [(Style::Everyday, vec![]), (Style::Careful, CAREFUL_KINDS.to_vec())] {
            let mut slot = owner_slot();
            slot.allowed_kinds = vec![30078];
            assert_eq!(slot_style(&slot), SlotStyle::Custom);
            assert_eq!(check_bundle_slot(Some(&slot), CLIENT), Ok(()));
            assert!(apply_bundle_press(&mut slot, CLIENT, &[PERSONA], style).unwrap());
            assert_eq!(slot.allowed_kinds, expected, "{style:?}");
            assert!(slot_has_owner_mark(&slot));
        }
        // Without the mark, any list but the careful one is still refused,
        // and the careful one is still accepted.
        let mut plain = everything_slot();
        plain.allowed_kinds = vec![30078];
        assert_eq!(check_bundle_slot(Some(&plain), CLIENT), Err(BundleError::HasKindsList));
        assert_eq!(BundleError::HasKindsList.message(), "unauthorised: pairing has a kinds list");
        plain.allowed_kinds = vec![22242, 30078];
        assert_eq!(check_bundle_slot(Some(&plain), CLIENT), Ok(()));
        // The other slot rows are unchanged on a marked slot.
        let mut strict = owner_slot();
        strict.allowed_kinds = vec![1];
        strict.escalate = true;
        assert_eq!(check_bundle_slot(Some(&strict), CLIENT), Err(BundleError::DeviceApprovalRequired));
        strict.escalate = false;
        strict.auto_approve = false;
        assert_eq!(check_bundle_slot(Some(&strict), CLIENT), Err(BundleError::AsksEveryRequest));
        strict.strict_permissions = true;
        assert_eq!(check_bundle_slot(Some(&strict), CLIENT), Err(BundleError::Unauthorised));
    }

    #[test]
    fn a_failed_grant_reports_so_the_caller_rolls_back() {
        let mut slot = everything_slot();
        for i in 0..16u8 {
            assert!(record_client_identity(&mut slot, CLIENT, &[0x40 + i; 32]));
        }
        assert_eq!(
            apply_bundle_press(&mut slot, CLIENT, &[PERSONA], Style::Everyday),
            Err(BundleError::ApprovalListFull)
        );
    }

    #[test]
    fn the_success_reply_is_the_spec_shape() {
        let reply = bundle_success_json(
            &[("natural-person".to_string(), NP), ("persona".to_string(), PERSONA)],
            &["persona".to_string()],
            Style::Everyday,
        );
        let value: Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "v": 1,
                "pubkeys": { "natural-person": hex(&NP), "persona": hex(&PERSONA) },
                "act_as": ["persona"],
                "owner": true,
                "style": "everyday",
            })
        );
    }

    // --- 4.6 status and narrow ---

    #[test]
    fn owner_status_answers_owner_and_style() {
        let parse = |s: String| serde_json::from_str::<Value>(&s).unwrap();
        assert_eq!(parse(owner_status_json(None)), serde_json::json!({"owner": false, "style": "everyday"}));
        assert_eq!(
            parse(owner_status_json(Some(&everything_slot()))),
            serde_json::json!({"owner": false, "style": "everyday"})
        );
        let mut slot = owner_slot();
        assert_eq!(parse(owner_status_json(Some(&slot))), serde_json::json!({"owner": true, "style": "everyday"}));
        slot.allowed_kinds = CAREFUL_KINDS.to_vec();
        assert_eq!(parse(owner_status_json(Some(&slot))), serde_json::json!({"owner": true, "style": "careful"}));
        // Review round W4: any other list is custom.
        slot.allowed_kinds = vec![22242];
        assert_eq!(parse(owner_status_json(Some(&slot))), serde_json::json!({"owner": true, "style": "custom"}));
        slot.allowed_kinds = vec![30078, 22242, 1];
        assert_eq!(parse(owner_status_json(Some(&slot))), serde_json::json!({"owner": true, "style": "custom"}));
        slot.allowed_kinds = CAREFUL_KINDS.to_vec();
        slot.strict_permissions = true;
        assert_eq!(parse(owner_status_json(Some(&slot))), serde_json::json!({"owner": false, "style": "careful"}));
        // "custom" is read back, never asked for.
        assert_eq!(Style::parse("custom"), None);
    }

    #[test]
    fn narrowing_never_widens_and_needs_the_mark() {
        let ok = [Value::String(r#"{"v":1,"style":"careful"}"#.into())];
        assert_eq!(parse_narrow_params(&ok), Ok(()));
        for bad in [r#"{"v":1,"style":"everyday"}"#, r#"{"v":2,"style":"careful"}"#, r#"{"v":1}"#, r#"{"v":1,"style":"careful","x":1}"#] {
            assert_eq!(parse_narrow_params(&[Value::String(bad.into())]), Err(BundleError::Malformed), "{bad}");
        }
        assert_eq!(parse_narrow_params(&[]), Err(BundleError::Malformed));

        let mut slot = owner_slot();
        assert_eq!(owner_narrow(Some(&mut slot)), Ok((true, SlotStyle::Careful)));
        assert_eq!(slot.allowed_kinds, CAREFUL_KINDS.to_vec());
        assert_eq!(owner_narrow(Some(&mut slot)), Ok((false, SlotStyle::Careful)));
        slot.allowed_kinds = vec![30078];
        assert_eq!(owner_narrow(Some(&mut slot)), Ok((false, SlotStyle::Custom)));
        assert_eq!(slot.allowed_kinds, vec![30078], "a narrower list is left alone");
        let mut plain = everything_slot();
        assert_eq!(owner_narrow(Some(&mut plain)), Err(BundleError::Unauthorised));
        assert!(plain.allowed_kinds.is_empty());
        assert_eq!(owner_narrow(None), Err(BundleError::Unauthorised));
        assert_eq!(
            serde_json::from_str::<Value>(&owner_narrow_json(SlotStyle::Careful, true)).unwrap(),
            serde_json::json!({"style": "careful", "changed": true})
        );
        assert_eq!(
            serde_json::from_str::<Value>(&owner_narrow_json(SlotStyle::Custom, false)).unwrap(),
            serde_json::json!({"style": "custom", "changed": false})
        );
    }

    // --- W3 one FULL ACCESS card at a time ---

    #[test]
    fn a_second_bundle_or_one_within_a_minute_never_reaches_a_card() {
        assert_eq!(full_access_admission(false, None, 0), Ok(()));
        // Another waiting: both get this reply (the caller closes the other).
        assert_eq!(full_access_admission(true, None, 5_000), Err(BundleError::AnotherFullAccess));
        assert_eq!(full_access_admission(true, Some(0), 500_000), Err(BundleError::AnotherFullAccess));
        // Within 60 s of the last card closing, whatever its outcome.
        let closed = 1_000_000;
        assert_eq!(full_access_admission(false, Some(closed), closed), Err(BundleError::ShownRecently));
        assert_eq!(full_access_admission(false, Some(closed), closed + 59_999), Err(BundleError::ShownRecently));
        assert_eq!(full_access_admission(false, Some(closed), closed + 60_000), Ok(()));
        // A clock that reads earlier than the close fails closed.
        assert_eq!(full_access_admission(false, Some(closed), closed - 1), Err(BundleError::ShownRecently));
        assert_eq!(FULL_ACCESS_COOLDOWN_SECS, 60);
        // The wire strings, exactly; both code -1.
        assert_eq!(BundleError::AnotherFullAccess.message(), "unauthorised: another full access request arrived");
        assert_eq!(BundleError::ShownRecently.message(), "unauthorised: full access card shown recently");
        assert_eq!(BundleError::AnotherFullAccess.code(), -1);
        assert_eq!(BundleError::ShownRecently.code(), -1);
    }

    // --- 5.2 who adds and removes the mark ---

    #[test]
    fn update_slot_may_keep_or_drop_the_mark_but_never_add_it() {
        let plain = everything_slot();
        let asked = vec!["sign_event".to_string(), OWNER_MARK.to_string(), BUNDLE_METHOD.to_string()];
        assert_eq!(update_slot_methods(&plain, asked.clone()), vec!["sign_event".to_string()]);
        let owner = owner_slot();
        assert_eq!(update_slot_methods(&owner, asked), vec!["sign_event".to_string(), OWNER_MARK.to_string()]);
        assert_eq!(update_slot_methods(&owner, vec!["sign_event".into()]), vec!["sign_event".to_string()]);
    }

    #[test]
    fn update_slot_never_widens_an_owner_pairings_kinds() {
        let mut owner = owner_slot();
        owner.allowed_kinds = CAREFUL_KINDS.to_vec();
        assert_eq!(update_slot_kinds(&owner, vec![]), CAREFUL_KINDS.to_vec(), "emptying widens");
        assert_eq!(update_slot_kinds(&owner, vec![30078, 22242, 1]), CAREFUL_KINDS.to_vec(), "extending widens");
        assert_eq!(update_slot_kinds(&owner, vec![1]), CAREFUL_KINDS.to_vec());
        assert_eq!(update_slot_kinds(&owner, vec![30078]), vec![30078], "narrowing is applied");
        let everyday = owner_slot();
        assert_eq!(update_slot_kinds(&everyday, vec![1, 7]), vec![1, 7], "any list narrows Everyday");
        let mut plain = everything_slot();
        plain.allowed_kinds = CAREFUL_KINDS.to_vec();
        assert!(update_slot_kinds(&plain, vec![]).is_empty(), "no mark: today's behaviour");
    }

    #[test]
    fn binding_a_second_client_key_drops_the_mark() {
        let mut slot = owner_slot();
        assert!(authorize_pubkey_on_slot(&mut slot, CLIENT), "the current key reconnecting");
        assert!(slot_has_owner_mark(&slot));
        assert!(authorize_pubkey_on_slot(&mut slot, OTHER));
        assert!(!slot_has_owner_mark(&slot));

        let mut granted = owner_slot();
        granted.client_grants = Some(crate::client_grants::GrantSnapshot::from_legacy(&granted).unwrap());
        assert!(authorize_pubkey_on_slot(&mut granted, CLIENT));
        assert!(slot_has_owner_mark(&granted));
        assert!(authorize_pubkey_on_slot(&mut granted, OTHER));
        assert!(!slot_has_owner_mark(&granted));
    }

    #[test]
    fn forget_approvals_drops_the_mark() {
        let mut slot = owner_slot();
        assert!(drop_owner_mark(&mut slot));
        assert!(!drop_owner_mark(&mut slot));
        assert!(!is_owner_pairing(&slot));
    }

    #[test]
    fn an_import_strips_the_mark_and_the_bundle_and_still_succeeds() {
        let mut slot = owner_slot();
        slot.allowed_methods.push(BUNDLE_METHOD.to_string());
        slot.allowed_kinds = CAREFUL_KINDS.to_vec();
        assert_eq!(sanitise_imported_slot(&mut slot), Ok(true));
        assert!(!slot_has_owner_mark(&slot));
        assert!(!slot.allowed_methods.iter().any(|m| m == BUNDLE_METHOD));
        assert!(slot.allowed_kinds.is_empty());
        let mut methods = vec![OWNER_MARK.to_string(), "nip44_encrypt".into(), BUNDLE_METHOD.to_string()];
        assert!(strip_owner_names(&mut methods));
        assert_eq!(methods, vec!["nip44_encrypt".to_string()]);
    }

    // --- 6 Rule V and Rule D ---

    #[test]
    fn rule_v_covers_exactly_its_methods_and_kind() {
        let vault = VaultContext::from_explicit(Some("signet:vault:contacts"), None);
        let owner = owner_slot();
        for method in ["get_public_key", "nip44_encrypt", "nip44_decrypt"] {
            assert!(rule_v_allows(&owner, method, true, vault), "{method}");
        }
        let backup = VaultContext::from_explicit(Some("signet:vault:contacts"), Some(30078));
        assert!(rule_v_allows(&owner, "sign_event", true, backup));
        assert!(rule_v_allows(&owner, "sign_event_compact", true, backup));
        let post = VaultContext::from_explicit(Some("signet:vault:contacts"), Some(1));
        assert!(!rule_v_allows(&owner, "sign_event", true, post));
        for method in ["nip04_encrypt", "nip04_decrypt", "heartwood_switch", "heartwood_note_send"] {
            assert!(!rule_v_allows(&owner, method, true, backup), "{method}");
        }
        // Explicit only, a vault purpose only, an owner pairing only.
        assert!(!rule_v_allows(&owner, "nip44_encrypt", false, vault));
        assert!(!rule_v_allows(&owner, "nip44_encrypt", true, VaultContext::NONE));
        assert!(!rule_v_allows(&owner, "nip44_encrypt", true, VaultContext::from_explicit(Some("signet:vault:"), None)));
        assert!(!rule_v_allows(&owner, "nip44_encrypt", true, VaultContext::from_explicit(Some("nostr:persona:x"), None)));
        assert!(!rule_v_allows(&owner, "nip44_encrypt", true, VaultContext::from_explicit(None, None)));
        assert!(!rule_v_allows(&everything_slot(), "nip44_encrypt", true, vault));
        let mut strict = owner_slot();
        strict.strict_permissions = true;
        assert!(!rule_v_allows(&strict, "nip44_encrypt", true, vault));
    }

    #[test]
    fn an_escalating_slot_is_not_an_owner_pairing_while_it_escalates() {
        // Review m5: an operator setting `escalate` on the owner phone's
        // slot turns both gate rules off, as the bundle is refused there.
        let mut slot = owner_slot();
        slot.escalate = true;
        assert!(slot_has_owner_mark(&slot), "the mark stays");
        assert!(!is_owner_pairing(&slot));
        let vault = VaultContext { explicit_vault: true, event_kind: Some(VAULT_EVENT_KIND) };
        assert!(!rule_v_allows(&slot, "nip44_encrypt", true, vault));
        assert!(!rule_v_allows(&slot, "sign_event", true, vault));
        assert!(!rule_d_records(&slot, "persona-1", true));
        let status: Value = serde_json::from_str(&owner_status_json(Some(&slot))).unwrap();
        assert_eq!(status["owner"], false);
        assert_eq!(owner_narrow(Some(&mut slot)), Err(BundleError::Unauthorised));
        // The no-widen rule keys off the mark, so it still holds.
        let mut careful = slot.clone();
        careful.allowed_kinds = CAREFUL_KINDS.to_vec();
        assert_eq!(update_slot_kinds(&careful, vec![]), CAREFUL_KINDS.to_vec());
        // Escalation cleared: an owner pairing again.
        slot.escalate = false;
        assert!(is_owner_pairing(&slot));
        assert!(rule_v_allows(&slot, "nip44_encrypt", true, vault));
        assert!(rule_d_records(&slot, "persona-1", true));
    }

    #[test]
    fn rule_d_records_only_new_non_real_names_on_owner_pairings() {
        let owner = owner_slot();
        assert!(rule_d_records(&owner, "persona-1", true));
        assert!(rule_d_records(&owner, "dependant-0-persona", true));
        assert!(rule_d_records(&owner, "dependant-3-persona-2", true));
        assert!(!rule_d_records(&owner, "persona-1", false), "a lookup records nothing");
        for real in ["natural-person", "dependant-0-np", "dependant-12-np"] {
            assert!(is_real_identity_name(real), "{real}");
            assert!(!rule_d_records(&owner, real, true), "{real}");
        }
        assert!(!is_real_identity_name("dependant--np"));
        assert!(!is_real_identity_name("persona-np"));
        assert!(!rule_d_records(&everything_slot(), "persona-1", true), "no mark, no Rule D");
        let mut full = owner_slot();
        for i in 0..16u8 {
            record_client_identity(&mut full, CLIENT, &[0x40 + i; 32]);
        }
        assert!(!can_record_client_identity(&full));
        assert!(!rule_d_records(&full, "persona-1", true), "the list is full");
    }
}
