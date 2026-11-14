// common/src/site_link.rs
//
// The pure half of site links made by the Heartwood, with a hold
// (signet-plans docs/plans/2026-11-14-heartwood-site-links-with-a-hold-design.md).
//
// A phone paired with full access (an owner pairing) asks the device for a
// site's sign-in link (`heartwood_link_create`). The device checks the gate
// rules, shows a LINK card, and only on a 2 s hold creates a strict slot on
// the identity's master and answers the `bunker://` link, the same reply
// `create_client_v2` gives. For 60 s after the hold the first key to bind
// that slot also gets the identity grant, so the site's first signature
// asks nothing. `heartwood_link_status` and `heartwood_link_revoke` let the
// phone check and remove what it made. No slot field, marker or codec
// change: the only new state is the RAM ledger here.
//
// Everything is a function of plain data (slots, the request params, a few
// facts the firmware supplies), so it runs in host CI. The firmware glue is
// `firmware/src/relay/site_link.rs`.

use alloc::{
    borrow::Cow,
    format,
    string::{String, ToString},
    vec::Vec,
};

use serde_json::Value;

use crate::mgmt::{classify_credential_fingerprint, credential_fingerprint, CredentialFingerprintMatch};
use crate::owner_pairing::is_owner_pairing;
use crate::policy::{
    client_identity_approved, evaluate_slot_policy_for_event, find_slot_by_pubkey, next_slot_index,
    validate_exact_slot_policy, ApprovalTier, ConnectSlot, ExactSlotPolicy, MAX_ALLOWED_KINDS,
};

// ---------------------------------------------------------------------------
// Names and constants
// ---------------------------------------------------------------------------

pub const METHOD_CREATE: &str = "heartwood_link_create";
pub const METHOD_STATUS: &str = "heartwood_link_status";
pub const METHOD_REVOKE: &str = "heartwood_link_revoke";

/// How long after the hold completes the first bind of the new slot also
/// gets the identity grant (design 4.2). The held-reply lifetime
/// (`held_reply::HELD_REPLY_TTL_SECS`) is the same length.
pub const INHERIT_WINDOW_MS: u64 = 60_000;

/// How long a decline or a timeout from one client keeps that client's next
/// link ask from reaching the card (design 4.4). None after an approval.
pub const COOLDOWN_MS: u64 = 60_000;

/// The only methods a site link may carry (design 4.3 rule 6).
pub const LINK_METHODS: [&str; 4] = ["get_public_key", "sign_event", "nip44_encrypt", "nip44_decrypt"];

/// The longest label a link request may carry. My Signet's
/// `mysignet:<host>:<8 hex>` is far inside it.
pub const MAX_LABEL_LEN: usize = 64;

/// Live inherit entries kept at once. Beyond it the oldest is dropped, which
/// only costs that link the ordinary `REMEMBER AS` card at its first
/// signature.
pub const MAX_LIVE_LINKS: usize = 4;

/// Clients cooling down at once; beyond it the oldest is dropped.
pub const MAX_COOLDOWNS: usize = 8;

/// The text a hold that answers a changed slot table gives, the same words
/// the dispatcher's resume check uses.
pub const APPROVAL_CHANGED: &str = "approval_changed: pairing or permissions changed; send the request again";

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

/// Why a link request is refused. Every refusal in gate rules 1 to 7 is a
/// reply with no card.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkError {
    /// Params missing or of the wrong shape.
    Malformed,
    /// Asked over the cable (or the Pi): links are made over the board's
    /// relay connection, where the card queue lives.
    RelayOnly,
    /// A short press or B on the card.
    Declined,
    /// The card's window ran out.
    Timeout,
    /// The card queue is full.
    Busy,
    /// A second link ask while one waited or was shown: both are refused.
    AnotherLink,
    /// Inside the minute after a decline or a timeout from this client.
    ShownRecently,
    /// The identity's master has 16 slots, or NVS cannot hold the table.
    NoRoom,
    /// Rule 1: the asking connection is not an owner pairing.
    NotOwnerPairing,
    /// Rule 2: no master or persona on this device has that key.
    IdentityNotServed,
    /// Rule 3: the asking key has no slot on the identity's master that
    /// signs as it.
    NotApprovedForIdentity,
    /// Rule 6: the request asks for more than the phone's own slot does
    /// silently.
    WiderThanPhone,
    /// Rule 4: a family flag on the phone's slot, or, for status and
    /// revoke, on the target.
    FamilySlot,
    /// Rule 5: the owner's or a child's real identity.
    RealIdentity,
    /// A slot-table change between the card and the hold.
    ApprovalChanged,
    /// A label lookup with no live link from this client (the 60 s are up,
    /// or it was never made here).
    UnknownLink,
    /// The fingerprint names a credential this slot no longer holds.
    StaleFingerprint,
    /// Revoke reached an owner pairing.
    OwnerPairingTarget,
}

impl LinkError {
    pub fn code(&self) -> i32 {
        match self {
            Self::Malformed => -3,
            _ => -1,
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            Self::Malformed => "malformed link request",
            Self::RelayOnly => "site links are made over the board's relay connection",
            Self::Declined => "declined",
            Self::Timeout => "timeout",
            Self::Busy => crate::approval_queue::BUSY_ERROR,
            Self::AnotherLink => "another link request arrived",
            Self::ShownRecently => "shown recently",
            Self::NoRoom => "no room",
            Self::NotOwnerPairing => "not an owner pairing",
            Self::IdentityNotServed => "identity not served",
            Self::NotApprovedForIdentity => "not approved for identity",
            Self::WiderThanPhone => "wider than this phone's access",
            Self::FamilySlot => "family slot",
            Self::RealIdentity => "real identity",
            Self::ApprovalChanged => APPROVAL_CHANGED,
            Self::UnknownLink => "unknown link: label lookups last 60 s; use the fingerprint",
            Self::StaleFingerprint => "stale_client_slot: slot credential changed; refresh clients and try again",
            Self::OwnerPairingTarget => "not a site link: owner pairing",
        }
    }
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/// `heartwood_link_create` `{ identity, label, policy: { allowed_methods,
/// allowed_kinds, auto_approve } }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateRequest {
    pub identity: [u8; 32],
    pub label: String,
    pub allowed_methods: Vec<String>,
    pub allowed_kinds: Vec<u64>,
    pub auto_approve: bool,
}

/// What a status or revoke names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkTarget {
    /// `{ slot_index, expected_secret_fingerprint }`: any slot whose
    /// credential the caller can name.
    Fingerprint { slot_index: u8, fingerprint: String },
    /// `{ label }`: only a link this client made inside the last minute.
    Label(String),
}

/// `heartwood_link_status` / `heartwood_link_revoke`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupRequest {
    pub identity: [u8; 32],
    pub target: LinkTarget,
}

/// `params[0]` as an object, also accepting it JSON-encoded in a string, as
/// the other object-taking extensions do. Borrowed when it is one already.
fn first_object(params: &[Value]) -> Option<Cow<'_, serde_json::Map<String, Value>>> {
    match params.first()? {
        Value::Object(map) => Some(Cow::Borrowed(map)),
        Value::String(text) => match serde_json::from_str::<Value>(text).ok()? {
            Value::Object(map) => Some(Cow::Owned(map)),
            _ => None,
        },
        _ => None,
    }
}

fn hex32(value: Option<&Value>) -> Option<[u8; 32]> {
    let text = value?.as_str()?;
    crate::policy::decode_client_key(text)
}

/// Printable ASCII, not blank, at most [`MAX_LABEL_LEN`]. Refused rather
/// than cleaned, so the echo equals the request.
pub fn valid_label(label: &str) -> bool {
    !label.trim().is_empty()
        && label.len() <= MAX_LABEL_LEN
        && label.bytes().all(|b| b == b' ' || b.is_ascii_graphic())
}

pub fn parse_create(params: &[Value]) -> Result<CreateRequest, LinkError> {
    let map = first_object(params).ok_or(LinkError::Malformed)?;
    let identity = hex32(map.get("identity")).ok_or(LinkError::Malformed)?;
    let label = map.get("label").and_then(Value::as_str).ok_or(LinkError::Malformed)?;
    if !valid_label(label) {
        return Err(LinkError::Malformed);
    }
    let policy = map.get("policy").and_then(Value::as_object).ok_or(LinkError::Malformed)?;
    // Plain loops, not `collect::<Option<Vec<_>>>`: the image is tight.
    // Both lists are capped before anything is copied: no link names more
    // than the four methods, nor more kinds than any slot may hold.
    let methods = policy.get("allowed_methods").and_then(Value::as_array).ok_or(LinkError::Malformed)?;
    if methods.len() > LINK_METHODS.len() {
        return Err(LinkError::Malformed);
    }
    let mut allowed_methods = Vec::new();
    for item in methods {
        allowed_methods.push(item.as_str().ok_or(LinkError::Malformed)?.to_string());
    }
    let mut allowed_kinds = Vec::new();
    match policy.get("allowed_kinds") {
        Some(Value::Array(items)) if items.len() <= MAX_ALLOWED_KINDS => {
            for item in items {
                allowed_kinds.push(item.as_u64().ok_or(LinkError::Malformed)?);
            }
        }
        None | Some(Value::Null) => {}
        _ => return Err(LinkError::Malformed),
    }
    let auto_approve = match policy.get("auto_approve") {
        Some(Value::Bool(b)) => *b,
        _ => return Err(LinkError::Malformed),
    };
    Ok(CreateRequest { identity, label: label.to_string(), allowed_methods, allowed_kinds, auto_approve })
}

pub fn parse_lookup(params: &[Value]) -> Result<LookupRequest, LinkError> {
    let map = first_object(params).ok_or(LinkError::Malformed)?;
    let identity = hex32(map.get("identity")).ok_or(LinkError::Malformed)?;
    let fingerprint = map.get("expected_secret_fingerprint");
    let target = match (map.get("slot_index"), fingerprint, map.get("label")) {
        (Some(index), Some(fp), None) => {
            let slot_index = index.as_u64().filter(|i| *i < 256).ok_or(LinkError::Malformed)? as u8;
            let fp = fp.as_str().ok_or(LinkError::Malformed)?;
            if classify_credential_fingerprint(Some(fp), fp) != CredentialFingerprintMatch::Match {
                return Err(LinkError::Malformed);
            }
            LinkTarget::Fingerprint { slot_index, fingerprint: fp.to_string() }
        }
        (None, None, Some(label)) => {
            let label = label.as_str().filter(|l| valid_label(l)).ok_or(LinkError::Malformed)?;
            LinkTarget::Label(label.to_string())
        }
        _ => return Err(LinkError::Malformed),
    };
    Ok(LookupRequest { identity, target })
}

// ---------------------------------------------------------------------------
// The gate (design 4.3)
// ---------------------------------------------------------------------------

/// A family flag: escalate, petition, child wrap or guardian copy.
pub fn has_family_flags(slot: &ConnectSlot) -> bool {
    slot.escalate || slot.petition_on_deny || slot.audit_child_wrap || slot.guardian_notice_wrap
}

/// Whether any client key has ever held this slot.
pub fn slot_is_bound(slot: &ConnectSlot) -> bool {
    slot.current_pubkey.is_some() || !slot.authorized_pubkeys.is_empty() || slot.was_bound
}

/// What the firmware knows of the named identity.
#[derive(Debug, Clone, Copy)]
pub struct ServedIdentity<'a> {
    /// The master that owns it (itself, for a master).
    pub master_slot: u8,
    /// A Rule D name: `natural-person` or `dependant-<n>-np`.
    pub real: bool,
    /// That master's slot table.
    pub table: &'a [ConnectSlot],
}

/// Rule 1, plus rule 4 on the asking slot: an owner pairing (non-strict, not
/// escalate, marked) with no family flag.
pub fn check_asker(asking: Option<&ConnectSlot>) -> Result<&ConnectSlot, LinkError> {
    let asking = asking.ok_or(LinkError::NotOwnerPairing)?;
    if !is_owner_pairing(asking) {
        return Err(LinkError::NotOwnerPairing);
    }
    if has_family_flags(asking) {
        return Err(LinkError::FamilySlot);
    }
    Ok(asking)
}

/// Rules 1 to 5 shared by all three methods: returns the phone's own slot on
/// the identity's master (the asking slot itself when the identity is on the
/// asking master).
pub fn check_phone<'a>(
    asking: Option<&ConnectSlot>,
    client_hex: &str,
    identity: &[u8; 32],
    served: Option<ServedIdentity<'a>>,
) -> Result<(&'a ConnectSlot, ServedIdentity<'a>), LinkError> {
    check_asker(asking)?;
    let served = served.ok_or(LinkError::IdentityNotServed)?;
    let phone = find_slot_by_pubkey(served.table, client_hex)
        .filter(|slot| client_identity_approved(slot, Some(client_hex), identity))
        .ok_or(LinkError::NotApprovedForIdentity)?;
    if has_family_flags(phone) {
        return Err(LinkError::FamilySlot);
    }
    if served.real {
        return Err(LinkError::RealIdentity);
    }
    Ok((phone, served))
}

/// Rule 6: whether a validated policy stays inside what the phone's own slot
/// does silently. Each method must be one of the four and one the phone
/// auto-approves (`get_public_key` always, as the caller answers it before
/// any policy); each kind one the phone signs silently, any kind only when
/// the phone's list is empty and it signs silently. The request's
/// `auto_approve` does not loosen it: a link that asks each time still names
/// only what the phone does silently.
pub fn within_phone(phone: &ConnectSlot, policy: &ExactSlotPolicy) -> bool {
    let silent = |method: &str, kind: Option<u64>| {
        evaluate_slot_policy_for_event(phone, method, kind, false) == ApprovalTier::AutoApprove
    };
    for method in &policy.allowed_methods {
        if !LINK_METHODS.contains(&method.as_str()) || !(method == "get_public_key" || silent(method, None)) {
            return false;
        }
    }
    if !policy.signing_approved || (phone.allowed_kinds.is_empty() && silent("sign_event", None)) {
        return true;
    }
    !policy.allowed_kinds.is_empty()
        && policy.allowed_kinds.iter().all(|k| phone.allowed_kinds.contains(k) && silent("sign_event", Some(*k)))
}

/// A create that passed rules 1 to 6 and the table check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatePlan {
    pub master_slot: u8,
    /// The policy the new slot gets: exactly the request's, bound to the
    /// identity, no family flag whatever the request says.
    pub policy: ExactSlotPolicy,
}

/// Rules 1 to 6. Room (rule 7) and the retry are [`gate`]'s.
pub fn check_create(
    asking: Option<&ConnectSlot>,
    client_hex: &str,
    served: Option<ServedIdentity<'_>>,
    request: &CreateRequest,
) -> Result<CreatePlan, LinkError> {
    let (phone, served) = check_phone(asking, client_hex, &request.identity, served)?;
    let mut policy = validate_exact_slot_policy(
        request.allowed_methods.clone(),
        request.allowed_kinds.clone(),
        request.auto_approve,
    )
    .map_err(|_| LinkError::Malformed)?;
    if !within_phone(phone, &policy) {
        return Err(LinkError::WiderThanPhone);
    }
    policy.bound_identity = Some(crate::hex::hex_encode(&request.identity));
    Ok(CreatePlan { master_slot: served.master_slot, policy })
}

/// What a create that passed the gate does.
#[derive(Debug, Clone)]
pub enum Gate<'a> {
    /// The same link again (design 4.5): answered with [`create_reply`] for
    /// this slot, no card, nothing written.
    Retry(&'a ConnectSlot),
    /// A new link: the card, then the hold.
    Plan(CreatePlan),
}

/// Rules 1 to 6, then the idempotent retry, then room in the table and NVS
/// (rule 7; the firmware's RNG is its own). The retry comes before room so
/// a lost reply is always answered, even when its link took the last slot.
/// The hold runs this again against the tables as they are then.
pub fn gate<'a>(
    asking: Option<&ConnectSlot>,
    client_hex: &str,
    served: Option<ServedIdentity<'a>>,
    request: &CreateRequest,
    ledger: &LinkLedger,
    now_ms: u64,
    nvs: Option<crate::nvs_room::NvsRoom>,
) -> Result<Gate<'a>, LinkError> {
    let plan = check_create(asking, client_hex, served, request)?;
    let table = served.ok_or(LinkError::IdentityNotServed)?.table;
    if let Some(made) = retry_target(ledger, client_hex, request, plan.master_slot, table, now_ms) {
        return Ok(Gate::Retry(made));
    }
    if next_slot_index(table).is_none() {
        return Err(LinkError::NoRoom);
    }
    check_save_room(table, &request.label, &plan.policy, &request.identity, nvs)?;
    Ok(Gate::Plan(plan))
}

/// Before the card (design 4.3 to 4.5): [`gate`], then the cooldown. A
/// cooling client still gets its retry and every rule's own refusal; only
/// a new card waits out the minute. The one-card rule is the caller's, as
/// it reads the card queue.
pub fn before_card<'a>(
    asking: Option<&ConnectSlot>,
    client_hex: &str,
    served: Option<ServedIdentity<'a>>,
    request: &CreateRequest,
    ledger: &LinkLedger,
    now_ms: u64,
    nvs: Option<crate::nvs_room::NvsRoom>,
) -> Result<Gate<'a>, LinkError> {
    let gate = gate(asking, client_hex, served, request, ledger, now_ms, nvs)?;
    if matches!(gate, Gate::Plan(_)) && ledger.cooling(client_hex, now_ms) {
        return Err(LinkError::ShownRecently);
    }
    Ok(gate)
}

/// Which gate a create meets: the card's, or the hold's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    /// Before the card: [`before_card`].
    Card,
    /// At the hold (design 4.4): a slot-table write on any master since the
    /// card (`epoch_current` false) answers `approval_changed` before
    /// anything else; otherwise [`gate`] again, with no cooldown, against
    /// the tables as they are now.
    Hold { epoch_current: bool },
}

/// [`before_card`] or the hold's check, as `check` says.
#[allow(clippy::too_many_arguments)]
pub fn check<'a>(
    check: Check,
    asking: Option<&ConnectSlot>,
    client_hex: &str,
    served: Option<ServedIdentity<'a>>,
    request: &CreateRequest,
    ledger: &LinkLedger,
    now_ms: u64,
    nvs: Option<crate::nvs_room::NvsRoom>,
) -> Result<Gate<'a>, LinkError> {
    match check {
        Check::Card => before_card(asking, client_hex, served, request, ledger, now_ms, nvs),
        Check::Hold { epoch_current: false } => Err(LinkError::ApprovalChanged),
        Check::Hold { epoch_current: true } => gate(asking, client_hex, served, request, ledger, now_ms, nvs),
    }
}

/// A request a waiting LINK card holds (queued or on screen).
#[derive(Debug, Clone, Copy)]
pub struct HeldLink<'a> {
    pub client_hex: &'a str,
    pub id: &'a str,
    pub params: &'a [Value],
}

/// A create set against the LINK cards already waiting (design 4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Waiting {
    /// No LINK card waits.
    Nothing,
    /// A copy of a waiting card's own request (the same client, id and
    /// params, heard again): no reply, and the card stays.
    Copy,
    /// Some other LINK ask waits.
    Another,
}

pub fn against_waiting<'h>(
    held: impl IntoIterator<Item = HeldLink<'h>>,
    client_hex: &str,
    id: &str,
    params: &[Value],
) -> Waiting {
    let mut another = false;
    for h in held {
        if h.client_hex == client_hex && h.id == id && h.params == params {
            return Waiting::Copy;
        }
        another = true;
    }
    if another {
        Waiting::Another
    } else {
        Waiting::Nothing
    }
}

/// What a parsed create does before any card.
#[derive(Debug)]
pub enum CardStep<'a, T> {
    /// A copy of the waiting card's request: nothing is answered.
    Ignore,
    /// The same link again: answered with [`create_reply`], no card.
    Retry(&'a ConnectSlot),
    /// A second link ask: every waiting LINK card closes refused
    /// [`LinkError::AnotherLink`] and the asker hears
    /// [`LinkLedger::another_link`].
    RefuseBoth,
    /// The card, with what the gate's caller needs to draw it.
    Show(CreatePlan, T),
}

/// The order before the card (design 4.3 to 4.5): a copy of the waiting
/// card's own request is ignored before anything else; then the card's
/// [`check`] (`gate`), whose refusals and retry come before the one-card
/// rule, so an ask that would be refused anyway closes no one's card;
/// then, with a LINK card waiting, both are refused.
pub fn card_step<'a, T>(
    waiting: Waiting,
    gate: impl FnOnce() -> Result<(Gate<'a>, T), LinkError>,
) -> Result<CardStep<'a, T>, LinkError> {
    if waiting == Waiting::Copy {
        return Ok(CardStep::Ignore);
    }
    Ok(match gate()? {
        (Gate::Retry(made), _) => CardStep::Retry(made),
        (Gate::Plan(_), _) if waiting == Waiting::Another => CardStep::RefuseBoth,
        (Gate::Plan(plan), extra) => CardStep::Show(plan, extra),
    })
}

/// How a LINK card closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkClose {
    /// The 2 s hold: the slot is made (or the hold's check refuses it).
    Held,
    /// A short press or B.
    Declined,
    /// Its window ran out on screen, or it waited out the queue's TTL
    /// behind other cards.
    TimedOut,
    /// Closed unanswered: [`LinkError::AnotherLink`] (a second ask), or
    /// [`LinkError::ApprovalChanged`] (a slot-table write while it waited).
    Refused(LinkError),
}

/// The title of a refused LINK card's NOT DONE screen.
pub const LINK_BLOCKED: &str = "Link blocked";

impl LinkClose {
    /// The refusal a refused card carries, by its message.
    pub fn refused(message: &str) -> Self {
        Self::Refused(if message == APPROVAL_CHANGED { LinkError::ApprovalChanged } else { LinkError::AnotherLink })
    }

    /// Whether the close starts the phone's cooldown: anything but the hold,
    /// except a card the slot tables overtook, whose phone is told to send
    /// the request again.
    pub fn cools(self) -> bool {
        !matches!(self, Self::Held | Self::Refused(LinkError::ApprovalChanged))
    }

    /// The NOT DONE screen a refused card draws, whether it was on screen or
    /// still queued: (title, reason). Any other close draws what every
    /// card's does.
    pub fn blocked(self) -> Option<(&'static str, &'static str)> {
        match self {
            Self::Refused(LinkError::ApprovalChanged) => Some((LINK_BLOCKED, "Slots changed")),
            Self::Refused(_) => Some((LINK_BLOCKED, "2nd request")),
            _ => None,
        }
    }
}

/// What a LINK ask weighs against the card queue's byte budget: its
/// params as they are (their compact JSON), which nothing else bounds as
/// tightly, and the overhead every ask carries.
pub fn ask_weight(params: &[Value]) -> usize {
    serde_json::to_string(params).map_or(usize::MAX, |p| p.len()).saturating_add(ASK_OVERHEAD)
}

/// The overhead every queued ask is weighed with.
pub const ASK_OVERHEAD: usize = 256;

/// Whether a site-link request heard over the cable is NACKed unanswered.
/// In the WiFi loop (`relay_loop`) the cable copy is heartwoodd bridging the
/// same request the board also hears on the relay: a `RelayOnly` reply
/// would be published and could reach the phone before the relay copy's
/// card is held, so it gets a NACK, which heartwoodd does not publish. The
/// USB-bridged loop has no relay, and answers `RelayOnly`.
pub fn cable_nacks(method: &str, relay_loop: bool) -> bool {
    relay_loop && crate::nip46::Nip46Method::from_str(method).is_site_link()
}

/// A stand-in for a 64-hex secret or client key, where only its length
/// counts.
const STAND_IN: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

/// The slot the hold will create, as `create_slot_with_exact_policy` builds
/// it (strict, an empty grant snapshot), with a stand-in secret.
pub fn planned_slot(table: &[ConnectSlot], label: &str, policy: &ExactSlotPolicy) -> Option<ConnectSlot> {
    Some(ConnectSlot {
        slot_index: next_slot_index(table)?,
        label: label.to_string(),
        secret: STAND_IN.to_string(),
        current_pubkey: None,
        allowed_methods: policy.allowed_methods.clone(),
        allowed_kinds: policy.allowed_kinds.clone(),
        auto_approve: policy.auto_approve,
        signing_approved: policy.signing_approved,
        strict_permissions: true,
        authorized_pubkeys: Vec::new(),
        escalate: false,
        petition_on_deny: false,
        audit_child_wrap: false,
        guardian_notice_wrap: false,
        bound_identity: policy.bound_identity.clone(),
        approved_identities: String::new(),
        was_bound: false,
        client_grants: Some(crate::client_grants::GrantSnapshot::empty()),
    })
}

/// The serialised length of the identity's table once the link exists and
/// its site has bound and been granted the identity, the largest the two
/// writes it causes make it (`owner_pairing::save_room_need` takes it).
pub fn save_room_len(table: &[ConnectSlot], label: &str, policy: &ExactSlotPolicy, identity: &[u8; 32]) -> Option<usize> {
    let mut slot = planned_slot(table, label, policy)?;
    crate::policy::authorize_pubkey_on_slot(&mut slot, STAND_IN);
    crate::policy::record_client_identity(&mut slot, STAND_IN, identity);
    // The table's array with one more element, without cloning the table.
    let table_len = serde_json::to_string(table).ok()?.len();
    let slot_len = serde_json::to_string(&slot).ok()?.len();
    Some(table_len + slot_len + usize::from(!table.is_empty()))
}

/// Rule 7's NVS half: the projected table fits beside the old one. No stats
/// (`None`) passes, as the bundle's check does; the write stays the
/// authority.
pub fn check_save_room(
    table: &[ConnectSlot],
    label: &str,
    policy: &ExactSlotPolicy,
    identity: &[u8; 32],
    nvs: Option<crate::nvs_room::NvsRoom>,
) -> Result<(), LinkError> {
    use crate::owner_pairing::{save_room_need, save_room_verdict, RegistryTail};
    let Some(nvs) = nvs else {
        return Ok(());
    };
    let len = save_room_len(table, label, policy, identity).ok_or(LinkError::NoRoom)?;
    let registry = RegistryTail { count: 0, count_stored: true, chunk_len: None };
    save_room_verdict(save_room_need(&[], registry, Some(len), nvs.pages()), nvs).map_err(|_| LinkError::NoRoom)
}

// ---------------------------------------------------------------------------
// Status and revoke targets
// ---------------------------------------------------------------------------

/// Where a status or revoke target stands.
#[derive(Debug, Clone, Copy)]
pub enum Found<'a> {
    Slot(&'a ConnectSlot),
    /// No slot at that index, or the label's link is gone.
    Missing,
    /// A slot at that index holding another credential.
    Mismatch,
}

impl PartialEq for Found<'_> {
    /// Two finds are the same when they name the same slot and credential.
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Slot(a), Self::Slot(b)) => a.slot_index == b.slot_index && a.secret == b.secret,
            (Self::Missing, Self::Missing) | (Self::Mismatch, Self::Mismatch) => true,
            _ => false,
        }
    }
}

/// Find a status or revoke target on the identity's master. The label form
/// reaches only a live entry this client made for this identity.
pub fn find_target<'a>(
    ledger: &LinkLedger,
    served: &ServedIdentity<'a>,
    client_hex: &str,
    request: &LookupRequest,
    now_ms: u64,
) -> Result<Found<'a>, LinkError> {
    let (slot_index, fingerprint) = match &request.target {
        LinkTarget::Fingerprint { slot_index, fingerprint } => (*slot_index, fingerprint.clone()),
        LinkTarget::Label(label) => {
            let entry = ledger
                .live_for_label(client_hex, label, now_ms)
                .filter(|e| e.master_slot == served.master_slot && e.identity == request.identity)
                .ok_or(LinkError::UnknownLink)?;
            (entry.slot_index, entry.fingerprint.clone())
        }
    };
    let Some(slot) = served.table.iter().find(|s| s.slot_index == slot_index) else {
        return Ok(Found::Missing);
    };
    Ok(match classify_credential_fingerprint(Some(&fingerprint), &credential_fingerprint(&slot.secret)) {
        CredentialFingerprintMatch::Match => Found::Slot(slot),
        _ if matches!(request.target, LinkTarget::Label(_)) => Found::Missing,
        _ => Found::Mismatch,
    })
}

/// A target status or revoke may never touch: an owner pairing, or a slot
/// with a family flag.
pub fn check_target(slot: &ConnectSlot) -> Result<(), LinkError> {
    if crate::owner_pairing::slot_has_owner_mark(slot) {
        return Err(LinkError::OwnerPairingTarget);
    }
    if has_family_flags(slot) {
        return Err(LinkError::FamilySlot);
    }
    Ok(())
}

/// `{ <first>: <is>, "bound": <bound> }`, the status reply and a revoke that
/// changes nothing.
fn flag_reply(first: &str, is: bool, bound: bool) -> Value {
    let mut map = serde_json::Map::new();
    map.insert(first.into(), Value::Bool(is));
    map.insert("bound".into(), Value::Bool(bound));
    Value::Object(map)
}

/// The status reply `{ exists, bound }`.
pub fn status_reply(found: Found<'_>) -> Result<Value, LinkError> {
    Ok(match found {
        Found::Slot(slot) => {
            check_target(slot)?;
            flag_reply("exists", true, slot_is_bound(slot))
        }
        Found::Missing | Found::Mismatch => flag_reply("exists", false, false),
    })
}

/// What a revoke does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevokePlan {
    /// Remove this slot.
    Remove { slot_index: u8, fingerprint: String },
    /// Answer with no change: a bound slot named by label alone.
    Keep(Value),
}

pub fn plan_revoke(found: Found<'_>, by_label: bool) -> Result<RevokePlan, LinkError> {
    match found {
        Found::Slot(slot) => {
            check_target(slot)?;
            if by_label && slot_is_bound(slot) {
                return Ok(RevokePlan::Keep(flag_reply("revoked", false, true)));
            }
            Ok(RevokePlan::Remove { slot_index: slot.slot_index, fingerprint: credential_fingerprint(&slot.secret) })
        }
        Found::Missing if by_label => Ok(RevokePlan::Keep(flag_reply("revoked", false, false))),
        Found::Missing => Err(LinkError::UnknownLink),
        Found::Mismatch => Err(LinkError::StaleFingerprint),
    }
}

/// The revoke reply, `revoke_client`'s shape.
pub fn revoked_reply(slot_index: u8, fingerprint: &str) -> Value {
    serde_json::json!({ "slot_index": slot_index, "secret_fingerprint": fingerprint, "revoked": true })
}

/// The create reply, `create_client_v2`'s fields less its `note`.
pub fn create_reply(slot: &ConnectSlot, npub_hex: &str, bunker_uri: &str) -> Value {
    serde_json::json!({
        "slot_index": slot.slot_index,
        "label": slot.label,
        "secret": slot.secret,
        "secret_fingerprint": credential_fingerprint(&slot.secret),
        "npub_hex": npub_hex,
        "bunker_uri": bunker_uri,
        "allowed_methods": slot.allowed_methods,
        "allowed_kinds": slot.allowed_kinds,
        "auto_approve": slot.auto_approve,
        "signing_approved": slot.signing_approved,
        "policy_version": 2,
    })
}

// ---------------------------------------------------------------------------
// The card (design 4.4)
// ---------------------------------------------------------------------------

/// What the LINK card says, before it is fitted to a panel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkCard {
    /// The site, from the phone's label. Unchecked: drawn with a leading `?`.
    pub site: String,
    /// The identity's card label (`encoding::identity_label`).
    pub identity: String,
    /// The identity's master, when it is not the asking connection's.
    pub master: Option<u8>,
    /// What the link may do, worked out by the device from the policy.
    pub scope: String,
    /// The asking slot's label.
    pub from: String,
}

fn printable(text: &str) -> String {
    text.chars().map(|c| if c == ' ' || c.is_ascii_graphic() { c } else { '_' }).collect()
}

/// The site a label names: the host of `<app>:<host>:<8 hex>` (My Signet's
/// form), otherwise the whole label.
pub fn site_of(label: &str) -> String {
    let mut parts = label.split(':');
    let site = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(app), Some(host), Some(tag), None)
            if !app.is_empty()
                && !host.is_empty()
                && tag.len() == 8
                && tag.bytes().all(|b| b.is_ascii_hexdigit()) =>
        {
            host
        }
        _ => label,
    };
    printable(site.trim())
}

/// The longest scope line: the narrowest panel's small row (128 px, 5 px
/// glyphs, inside the margins) holds 24.
pub const SCOPE_CHARS: usize = 24;

/// The scope line. A link that may decrypt says so first, whatever else it
/// may do: `DECRYPT, NO SIGN, NO ASK`, `DECRYPT+3 KINDS, NO ASK`. Every
/// line fits [`SCOPE_CHARS`].
pub fn scope_line(policy: &ExactSlotPolicy) -> String {
    let decrypt = policy.allowed_methods.iter().any(|m| m == "nip44_decrypt");
    let auto = policy.auto_approve;
    let mut line = String::from(if decrypt { "DECRYPT" } else { "" });
    if !policy.signing_approved {
        line.push_str(if decrypt { ", NO SIGN, " } else { "NO SIGNING, " });
        line.push_str(match (auto, decrypt) {
            (true, true) => "NO ASK",
            (true, false) => "NO ASKING",
            _ => "ASKS",
        });
    } else if !auto {
        line.push_str(if decrypt { ", ASKS EACH TIME" } else { "ASKS EACH TIME" });
    } else {
        if decrypt {
            line.push('+');
        }
        match policy.allowed_kinds.len() {
            0 => line.push_str("ANY KIND"),
            1 => line.push_str("1 KIND"),
            n => {
                line.push_str(&n.to_string());
                line.push_str(" KINDS");
            }
        }
        line.push_str(if decrypt { ", NO ASK" } else { ", NO ASKING" });
    }
    line
}

pub fn link_card(
    label: &str,
    identity_label: &str,
    identity_master: u8,
    asking_master: u8,
    policy: &ExactSlotPolicy,
    from_label: &str,
) -> LinkCard {
    LinkCard {
        site: site_of(label),
        identity: printable(identity_label),
        master: (identity_master != asking_master).then_some(identity_master),
        scope: scope_line(policy),
        from: printable(from_label),
    }
}

/// `text` cut to `room` characters; when cut, its tail is kept behind `..`
/// (a host's end is the part that names who runs it).
fn keep_tail(text: &str, room: usize) -> String {
    let len = text.chars().count();
    if len <= room {
        return text.to_string();
    }
    if room <= 2 {
        return text.chars().skip(len - room).collect();
    }
    let tail: String = text.chars().skip(len - (room - 2)).collect();
    format!("..{tail}")
}

fn keep_head(text: &str, room: usize) -> String {
    text.chars().take(room).collect()
}

impl LinkCard {
    /// `LINK ?<site>?` in at most `chars` (never more than
    /// `encoding::HEADING_CHARS`).
    pub fn heading(&self, chars: usize) -> String {
        let chars = chars.min(crate::encoding::HEADING_CHARS);
        let room = chars.saturating_sub("LINK ??".len());
        format!("LINK ?{}?", keep_tail(&self.site, room))
    }

    /// `AS <identity>`, with ` M<n>` when the identity is on another master.
    pub fn as_line(&self, chars: usize) -> String {
        let master = self.master.map(|m| format!(" M{m}")).unwrap_or_default();
        let room = chars.saturating_sub(3 + master.len());
        format!("AS {}{master}", keep_head(&self.identity, room))
    }

    pub fn scope_line(&self, chars: usize) -> String {
        keep_head(&self.scope, chars)
    }

    /// `FROM <slot label>`.
    pub fn from_line(&self, chars: usize) -> String {
        format!("FROM {}", keep_head(&self.from, chars.saturating_sub(5)))
    }

    /// Every line in the given widths: heading, AS, scope, FROM.
    pub fn lines(&self, header: usize, body: usize, small: usize) -> [String; 4] {
        [self.heading(header), self.as_line(body), self.scope_line(small), self.from_line(small)]
    }
}

// ---------------------------------------------------------------------------
// RAM state (design 4.2, 4.4)
// ---------------------------------------------------------------------------

/// A link made by a hold, waiting for its site's first bind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkEntry {
    pub master_slot: u8,
    pub slot_index: u8,
    /// `mgmt::credential_fingerprint` of the slot secret, so a reused index
    /// never matches.
    pub fingerprint: String,
    pub identity: [u8; 32],
    /// The phone that asked, lowercase hex.
    pub client: String,
    pub label: String,
    /// Device uptime, 60 s after the hold completed. A retry never moves it.
    pub deadline_ms: u64,
}

/// The inherit entries and the per-client cooldowns. RAM only: a restart
/// clears both, and the first signature then gets the ordinary card.
#[derive(Debug, Default)]
pub struct LinkLedger {
    entries: Vec<LinkEntry>,
    cooldowns: Vec<(String, u64)>,
}

impl LinkLedger {
    pub const fn new() -> Self {
        Self { entries: Vec::new(), cooldowns: Vec::new() }
    }

    /// Record a link made by a hold that completed at `now_ms`.
    pub fn record(
        &mut self,
        master_slot: u8,
        slot_index: u8,
        fingerprint: String,
        identity: [u8; 32],
        client: &str,
        label: &str,
        now_ms: u64,
    ) {
        self.clear_slot(master_slot, slot_index);
        // Entries expire in the order they were made, so the oldest is the
        // one to drop, live or not; every read checks the deadline.
        if self.entries.len() >= MAX_LIVE_LINKS {
            self.entries.remove(0);
        }
        self.entries.push(LinkEntry {
            master_slot,
            slot_index,
            fingerprint,
            identity,
            client: client.to_string(),
            label: label.to_string(),
            deadline_ms: now_ms.saturating_add(INHERIT_WINDOW_MS),
        });
    }

    /// The live entry this client made under this label.
    pub fn live_for_label(&self, client: &str, label: &str, now_ms: u64) -> Option<&LinkEntry> {
        self.entries
            .iter()
            .rev()
            .find(|e| now_ms < e.deadline_ms && e.client == client && e.label == label)
    }

    /// The first bind of a slot: the entry is cleared whatever the outcome,
    /// and its identity returned only inside the window and only for the
    /// same credential.
    pub fn take_on_bind(&mut self, master_slot: u8, slot_index: u8, secret: &str, now_ms: u64) -> Option<[u8; 32]> {
        let at = self.entries.iter().position(|e| e.master_slot == master_slot && e.slot_index == slot_index)?;
        let entry = self.entries.remove(at);
        (now_ms < entry.deadline_ms && entry.fingerprint == credential_fingerprint(secret))
            .then_some(entry.identity)
    }

    /// Any revoke of the slot.
    pub fn clear_slot(&mut self, master_slot: u8, slot_index: u8) {
        // `record` clears a slot before adding it, so there is at most one.
        if let Some(at) = self.entries.iter().position(|e| e.master_slot == master_slot && e.slot_index == slot_index) {
            self.entries.remove(at);
        }
    }

    /// A decline, a timeout or a refused card from this client (design
    /// 4.4). One entry per client, restarted; beyond the cap the oldest is
    /// dropped.
    pub fn start_cooldown(&mut self, client: &str, now_ms: u64) {
        if let Some(at) = self.cooldowns.iter().position(|(c, _)| c == client) {
            self.cooldowns.remove(at);
        } else if self.cooldowns.len() >= MAX_COOLDOWNS {
            self.cooldowns.remove(0);
        }
        self.cooldowns.push((client.to_string(), now_ms.saturating_add(COOLDOWN_MS)));
    }

    /// A second link ask while a LINK card waits (design 4.4): both are
    /// refused, and the asker cools, so asking again cannot keep a card up.
    /// The waiting card's client cools when its card closes
    /// ([`LinkLedger::card_closed`]).
    pub fn another_link(&mut self, client: &str, now_ms: u64) -> LinkError {
        self.start_cooldown(client, now_ms);
        LinkError::AnotherLink
    }

    /// A LINK card closed: anything but a hold cools its client
    /// ([`LinkClose::cools`]).
    pub fn card_closed(&mut self, client: &str, close: LinkClose, now_ms: u64) {
        if close.cools() {
            self.start_cooldown(client, now_ms);
        }
    }

    pub fn cooling(&self, client: &str, now_ms: u64) -> bool {
        self.cooldowns.iter().any(|(c, until)| c == client && now_ms < *until)
    }

    pub fn live_count(&self, now_ms: u64) -> usize {
        self.entries.iter().filter(|e| now_ms < e.deadline_ms).count()
    }
}

/// An idempotent retry (design 4.5): the same client and label, its entry
/// live, its slot still unbound on the same credential and identity. The
/// caller answers with [`create_reply`] for the returned slot and no card.
pub fn retry_target<'a>(
    ledger: &LinkLedger,
    client_hex: &str,
    request: &CreateRequest,
    master_slot: u8,
    table: &'a [ConnectSlot],
    now_ms: u64,
) -> Option<&'a ConnectSlot> {
    let entry = ledger
        .live_for_label(client_hex, &request.label, now_ms)
        .filter(|e| e.master_slot == master_slot && e.identity == request.identity)?;
    table.iter().find(|s| {
        s.slot_index == entry.slot_index
            && !slot_is_bound(s)
            && entry.fingerprint == credential_fingerprint(&s.secret)
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::owner_pairing::{apply_bundle_press, Style, CAREFUL_KINDS, OWNER_MARK};
    use alloc::vec;

    const PHONE: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const SITE: &str = "2222222222222222222222222222222222222222222222222222222222222222"; // pragma: allow-secret — fixed test pubkey
    const PERSONA: [u8; 32] = [0x33; 32];
    const MASTER1: [u8; 32] = [0x44; 32];

    fn base_slot(index: u8, label: &str) -> ConnectSlot {
        ConnectSlot {
            slot_index: index,
            label: label.to_string(),
            secret: format!("{index:02x}").repeat(32),
            current_pubkey: Some(PHONE.to_string()),
            allowed_methods: vec!["nip44_encrypt".into(), "nip44_decrypt".into(), "get_public_key".into()],
            allowed_kinds: vec![],
            auto_approve: true,
            signing_approved: false,
            strict_permissions: false,
            authorized_pubkeys: vec![PHONE.to_string()],
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

    /// The phone's owner pairing on master 0, Everyday, acting as PERSONA.
    fn owner(style: Style) -> ConnectSlot {
        let mut slot = base_slot(0, "My Signet");
        apply_bundle_press(&mut slot, PHONE, &[PERSONA], style).unwrap();
        slot
    }

    /// The phone's relay-made strict slot on master 1, signing as master 1.
    fn strict_m1(kinds: Vec<u64>) -> ConnectSlot {
        let mut slot = base_slot(0, "phone m1");
        slot.strict_permissions = true;
        slot.allowed_methods = LINK_METHODS.iter().map(|m| m.to_string()).collect();
        slot.allowed_kinds = kinds;
        slot.signing_approved = true;
        slot.client_grants = Some(crate::client_grants::GrantSnapshot::empty());
        assert!(crate::policy::authorize_pubkey_on_slot(&mut slot, PHONE));
        assert!(crate::policy::record_client_identity(&mut slot, PHONE, &MASTER1));
        slot
    }

    fn served(master_slot: u8, table: &[ConnectSlot]) -> Option<ServedIdentity<'_>> {
        Some(ServedIdentity { master_slot, real: false, table })
    }

    fn request(identity: [u8; 32], kinds: Vec<u64>) -> CreateRequest {
        CreateRequest {
            identity,
            label: "mysignet:kithmoot.com:0123abcd".into(),
            allowed_methods: vec!["get_public_key".into(), "sign_event".into(), "nip44_encrypt".into(), "nip44_decrypt".into()],
            allowed_kinds: kinds,
            auto_approve: true,
        }
    }

    fn params(json: &str) -> Vec<Value> {
        vec![serde_json::from_str(json).unwrap()]
    }

    // --- parsing ---

    #[test]
    fn create_params_parse_and_refuse_bad_shapes() {
        let ok = parse_create(&params(
            r#"{"identity":"3333333333333333333333333333333333333333333333333333333333333333","label":"mysignet:kithmoot.com:0123abcd","policy":{"allowed_methods":["sign_event"],"allowed_kinds":[1,7],"auto_approve":true}}"#,
        ))
        .unwrap();
        assert_eq!(ok.identity, PERSONA);
        assert_eq!(ok.allowed_kinds, vec![1, 7]);
        // A string-encoded object reads the same.
        let text = vec![Value::String(r#"{"identity":"3333333333333333333333333333333333333333333333333333333333333333","label":"x","policy":{"allowed_methods":[],"auto_approve":false}}"#.into())];
        assert!(parse_create(&text).is_ok());
        for bad in [
            r#"{"label":"x","policy":{"allowed_methods":[],"auto_approve":true}}"#,
            r#"{"identity":"33","label":"x","policy":{"allowed_methods":[],"auto_approve":true}}"#,
            r#"{"identity":"3333333333333333333333333333333333333333333333333333333333333333","label":"","policy":{"allowed_methods":[],"auto_approve":true}}"#,
            r#"{"identity":"3333333333333333333333333333333333333333333333333333333333333333","label":"tab\there","policy":{"allowed_methods":[],"auto_approve":true}}"#,
            r#"{"identity":"3333333333333333333333333333333333333333333333333333333333333333","label":"x","policy":{"allowed_methods":[],"auto_approve":"yes"}}"#,
            r#"{"identity":"3333333333333333333333333333333333333333333333333333333333333333","label":"x"}"#,
        ] {
            assert_eq!(parse_create(&params(bad)), Err(LinkError::Malformed), "{bad}");
        }
        let long = "a".repeat(MAX_LABEL_LEN + 1);
        assert!(!valid_label(&long));
        assert!(valid_label(&"a".repeat(MAX_LABEL_LEN)));
        // Both lists are capped while parsing: four methods, 64 kinds.
        let with = |methods: &str, kinds: &str| {
            params(&format!(
                r#"{{"identity":"{}","label":"x","policy":{{"allowed_methods":{methods},"allowed_kinds":{kinds},"auto_approve":true}}}}"#,
                "33".repeat(32)
            ))
        };
        let four = r#"["get_public_key","sign_event","nip44_encrypt","nip44_decrypt"]"#;
        let five = r#"["get_public_key","sign_event","nip44_encrypt","nip44_decrypt","sign_event"]"#;
        let kinds = |n: usize| serde_json::to_string(&(0..n as u64).collect::<Vec<_>>()).unwrap();
        assert!(parse_create(&with(four, &kinds(MAX_ALLOWED_KINDS))).is_ok());
        assert_eq!(parse_create(&with(five, "[]")), Err(LinkError::Malformed));
        assert_eq!(parse_create(&with(four, &kinds(MAX_ALLOWED_KINDS + 1))), Err(LinkError::Malformed));
        // An object param is read in place, not copied.
        assert!(matches!(first_object(&with(four, "[]")), Some(Cow::Borrowed(_))));
    }

    #[test]
    fn lookup_params_take_exactly_one_form() {
        let id = "3333333333333333333333333333333333333333333333333333333333333333";
        let fp = "ab".repeat(32);
        let by_fp = parse_lookup(&params(&format!(r#"{{"identity":"{id}","slot_index":3,"expected_secret_fingerprint":"{fp}"}}"#))).unwrap();
        assert_eq!(by_fp.target, LinkTarget::Fingerprint { slot_index: 3, fingerprint: fp.clone() });
        let by_label = parse_lookup(&params(&format!(r#"{{"identity":"{id}","label":"mysignet:a:0123abcd"}}"#))).unwrap();
        assert_eq!(by_label.target, LinkTarget::Label("mysignet:a:0123abcd".into()));
        for bad in [
            format!(r#"{{"identity":"{id}"}}"#),
            format!(r#"{{"identity":"{id}","slot_index":3}}"#),
            format!(r#"{{"identity":"{id}","slot_index":3,"expected_secret_fingerprint":"AB{}"}}"#, "ab".repeat(31)),
            format!(r#"{{"identity":"{id}","slot_index":300,"expected_secret_fingerprint":"{fp}"}}"#),
            format!(r#"{{"identity":"{id}","slot_index":3,"expected_secret_fingerprint":"{fp}","label":"x"}}"#),
        ] {
            assert_eq!(parse_lookup(&params(&bad)), Err(LinkError::Malformed), "{bad}");
        }
    }

    // --- the gate, rows 1, 2, 8, 9, 10, 17 ---

    #[test]
    fn row_1_a_persona_on_the_asking_master_passes_with_the_identity_bound() {
        let table = vec![owner(Style::Everyday)];
        let plan = check_create(Some(&table[0]), PHONE, served(0, &table), &request(PERSONA, vec![])).unwrap();
        assert_eq!(plan.master_slot, 0);
        assert_eq!(plan.policy.bound_identity.as_deref(), Some(crate::hex::hex_encode(&PERSONA).as_str()));
        assert!(!plan.policy.escalate && !plan.policy.petition_on_deny);
        assert!(!plan.policy.audit_child_wrap && !plan.policy.guardian_notice_wrap);
    }

    #[test]
    fn row_2_master_one_through_a_strict_or_a_usb_slot() {
        let asking = owner(Style::Everyday);
        let strict = vec![strict_m1(vec![])];
        assert!(check_create(Some(&asking), PHONE, served(1, &strict), &request(MASTER1, vec![])).is_ok());
        // USB-made: non-strict, signing earned by its first held signature.
        let mut usb = base_slot(2, "phone m1 usb");
        usb.allowed_methods.push("sign_event".into());
        usb.signing_approved = true;
        crate::policy::record_client_identity(&mut usb, PHONE, &MASTER1);
        let usb = vec![usb];
        assert!(check_create(Some(&asking), PHONE, served(1, &usb), &request(MASTER1, vec![])).is_ok());
    }

    #[test]
    fn rule_1_only_an_owner_pairing_may_ask() {
        let table = vec![owner(Style::Everyday)];
        let req = request(PERSONA, vec![]);
        assert_eq!(check_create(None, PHONE, served(0, &table), &req).unwrap_err(), LinkError::NotOwnerPairing);
        // A site link (strict) and a child slot (strict, escalate) never reach it.
        let site = strict_m1(vec![]);
        assert_eq!(check_create(Some(&site), PHONE, served(0, &table), &req).unwrap_err(), LinkError::NotOwnerPairing);
        let mut child = owner(Style::Everyday);
        child.escalate = true;
        assert_eq!(check_create(Some(&child), PHONE, served(0, &table), &req).unwrap_err(), LinkError::NotOwnerPairing);
        // An unmarked non-strict slot is no owner pairing either.
        let unmarked = base_slot(0, "plain");
        assert_eq!(check_create(Some(&unmarked), PHONE, served(0, &table), &req).unwrap_err(), LinkError::NotOwnerPairing);
        // Row 9: an owner pairing carrying any other family flag.
        let mut flagged = owner(Style::Everyday);
        flagged.petition_on_deny = true;
        assert_eq!(check_create(Some(&flagged), PHONE, served(0, &table), &req).unwrap_err(), LinkError::FamilySlot);
    }

    #[test]
    fn rules_2_and_3_the_identity_must_be_served_and_already_signed_as() {
        let asking = owner(Style::Everyday);
        let table = vec![asking.clone()];
        let req = request(MASTER1, vec![]);
        assert_eq!(check_create(Some(&asking), PHONE, None, &req).unwrap_err(), LinkError::IdentityNotServed);
        // Master 1 serves it, but the phone never signed as it there.
        let mut unapproved = strict_m1(vec![]);
        unapproved.client_grants = Some(crate::client_grants::GrantSnapshot::empty());
        assert!(crate::policy::authorize_pubkey_on_slot(&mut unapproved, PHONE));
        let m1 = vec![unapproved];
        assert_eq!(check_create(Some(&asking), PHONE, served(1, &m1), &req).unwrap_err(), LinkError::NotApprovedForIdentity);
        // Row 17: a key per master. The phone's master-1 slot holds another key.
        let mut other_key = strict_m1(vec![]);
        other_key.current_pubkey = Some(SITE.into());
        other_key.authorized_pubkeys = vec![SITE.into()];
        let m1 = vec![other_key];
        assert_eq!(check_create(Some(&asking), PHONE, served(1, &m1), &req).unwrap_err(), LinkError::NotApprovedForIdentity);
        // On its own master, the owner pairing must act as the identity too.
        assert_eq!(
            check_create(Some(&asking), PHONE, served(0, &table), &request([0x55; 32], vec![])).unwrap_err(),
            LinkError::NotApprovedForIdentity
        );
    }

    #[test]
    fn rules_4_and_5_family_slots_and_real_identities_are_refused() {
        let asking = owner(Style::Everyday);
        let mut child = strict_m1(vec![]);
        child.audit_child_wrap = true;
        let m1 = vec![child];
        let req = request(MASTER1, vec![]);
        assert_eq!(check_create(Some(&asking), PHONE, served(1, &m1), &req).unwrap_err(), LinkError::FamilySlot);
        let m1 = vec![strict_m1(vec![])];
        let real = Some(ServedIdentity { master_slot: 1, real: true, table: &m1 });
        assert_eq!(check_create(Some(&asking), PHONE, real, &req).unwrap_err(), LinkError::RealIdentity);
    }

    #[test]
    fn row_8_the_ceiling_is_what_the_phone_signs_silently() {
        let asking = owner(Style::Everyday);
        let m1 = vec![strict_m1(vec![1, 7])];
        // Any kind is wider than kinds 1 and 7.
        let err = check_create(Some(&asking), PHONE, served(1, &m1), &request(MASTER1, vec![])).unwrap_err();
        assert_eq!(err, LinkError::WiderThanPhone);
        assert_eq!(err.message(), "wider than this phone's access");
        // Inside those kinds works, and so does a subset.
        assert!(check_create(Some(&asking), PHONE, served(1, &m1), &request(MASTER1, vec![7, 1])).is_ok());
        assert!(check_create(Some(&asking), PHONE, served(1, &m1), &request(MASTER1, vec![7])).is_ok());
        // A kind outside is wider.
        assert!(check_create(Some(&asking), PHONE, served(1, &m1), &request(MASTER1, vec![1, 4])).is_err());
        // An Extra careful owner pairing signs only backups and AUTH silently.
        let careful = owner(Style::Careful);
        let table = vec![careful.clone()];
        let err = check_create(Some(&careful), PHONE, served(0, &table), &request(PERSONA, vec![])).unwrap_err();
        assert_eq!(err, LinkError::WiderThanPhone);
        assert!(check_create(Some(&careful), PHONE, served(0, &table), &request(PERSONA, CAREFUL_KINDS.to_vec())).is_ok());
        for kind in CAREFUL_KINDS.iter() {
            assert!(check_create(Some(&careful), PHONE, served(0, &table), &request(PERSONA, vec![*kind])).is_ok());
        }
        // A kind the Careful pairing would ask about is wider.
        assert_eq!(
            check_create(Some(&careful), PHONE, served(0, &table), &request(PERSONA, vec![1])).unwrap_err(),
            LinkError::WiderThanPhone
        );
    }

    #[test]
    fn the_ceiling_is_the_evaluator_not_the_list() {
        let asking = owner(Style::Everyday);
        // Listed but asking each time: nothing but get_public_key is silent.
        let mut asks = strict_m1(vec![]);
        asks.auto_approve = false;
        let m1 = vec![asks];
        for method in ["sign_event", "nip44_encrypt", "nip44_decrypt"] {
            let mut one = request(MASTER1, vec![]);
            one.allowed_methods = vec![method.into()];
            assert_eq!(check_create(Some(&asking), PHONE, served(1, &m1), &one), Err(LinkError::WiderThanPhone), "{method}");
        }
        // The request's own auto_approve does not loosen it.
        let mut req = request(MASTER1, vec![]);
        req.auto_approve = false;
        assert_eq!(check_create(Some(&asking), PHONE, served(1, &m1), &req).unwrap_err(), LinkError::WiderThanPhone);
        let mut pubkey_only = request(MASTER1, vec![]);
        pubkey_only.allowed_methods = vec!["get_public_key".into()];
        assert!(check_create(Some(&asking), PHONE, served(1, &m1), &pubkey_only).is_ok());
        // A non-strict slot that has not yet earned sign_event cannot hand it on.
        let usb = base_slot(2, "usb");
        let methods = |list: &[&str]| {
            validate_exact_slot_policy(list.iter().map(|m| m.to_string()).collect(), vec![], true).unwrap()
        };
        assert!(within_phone(&usb, &methods(&["get_public_key", "nip44_encrypt", "nip44_decrypt"])));
        assert!(!within_phone(&usb, &methods(&["get_public_key", "sign_event"])));
        // A method outside the four is wider, even one the phone has.
        let mut odd = request(PERSONA, vec![]);
        odd.allowed_methods.push("heartwood_list_identities".into());
        let table = vec![owner(Style::Everyday)];
        assert_eq!(check_create(Some(&table[0]), PHONE, served(0, &table), &odd).unwrap_err(), LinkError::WiderThanPhone);
        // Kinds without sign_event are malformed, as for create_client_v2.
        let mut kinds_only = request(PERSONA, vec![1]);
        kinds_only.allowed_methods = vec!["get_public_key".into()];
        assert_eq!(check_create(Some(&table[0]), PHONE, served(0, &table), &kinds_only).unwrap_err(), LinkError::Malformed);
    }

    #[test]
    fn row_5_a_full_table_or_full_nvs_refuses_before_the_card() {
        let asking = owner(Style::Everyday);
        let mut table = vec![asking.clone()];
        for i in 1..16 {
            table.push(base_slot(i, "other"));
        }
        let ledger = LinkLedger::new();
        assert!(check_create(Some(&asking), PHONE, served(0, &table), &request(PERSONA, vec![])).is_ok());
        assert_eq!(
            gate(Some(&asking), PHONE, served(0, &table), &request(PERSONA, vec![]), &ledger, 0, None).unwrap_err(),
            LinkError::NoRoom
        );
        let table = vec![asking];
        let plan = check_create(Some(&table[0]), PHONE, served(0, &table), &request(PERSONA, vec![])).unwrap();
        let label = "mysignet:kithmoot.com:0123abcd";
        assert_eq!(check_save_room(&table, label, &plan.policy, &PERSONA, None), Ok(()));
        let roomy = crate::nvs_room::NvsRoom { free_entries: 400, total_entries: 630, reclaimable_entries: 0 };
        let len = save_room_len(&table, label, &plan.policy, &PERSONA).unwrap();
        // The length is the projected table's, counted without cloning it.
        let mut bound = planned_slot(&table, label, &plan.policy).unwrap();
        crate::policy::authorize_pubkey_on_slot(&mut bound, STAND_IN);
        crate::policy::record_client_identity(&mut bound, STAND_IN, &PERSONA);
        assert_eq!(len, serde_json::to_string(&[table.clone(), vec![bound.clone()]].concat()).unwrap().len());
        assert_eq!(save_room_len(&[], label, &plan.policy, &PERSONA), Some(serde_json::to_string(&[bound]).unwrap().len()));
        let need = crate::owner_pairing::save_room_need(&[], crate::owner_pairing::RegistryTail { count: 0, count_stored: true, chunk_len: None }, Some(len), roomy.pages());
        assert_eq!(check_save_room(&table, label, &plan.policy, &PERSONA, Some(roomy)), Ok(()), "{len} {need:?}");
        let full = crate::nvs_room::NvsRoom { free_entries: 130, total_entries: 630, reclaimable_entries: 0 };
        assert_eq!(check_save_room(&table, label, &plan.policy, &PERSONA, Some(full)), Err(LinkError::NoRoom));
        assert_eq!(
            gate(Some(&table[0]), PHONE, served(0, &table), &request(PERSONA, vec![]), &ledger, 0, Some(full)).unwrap_err(),
            LinkError::NoRoom
        );
        assert!(matches!(
            gate(Some(&table[0]), PHONE, served(0, &table), &request(PERSONA, vec![]), &ledger, 0, Some(roomy)),
            Ok(Gate::Plan(p)) if p == plan
        ));
        // The projection covers the bind and the grant that follow.
        let bare = serde_json::to_string(&[table.clone(), vec![planned_slot(&table, label, &plan.policy).unwrap()]].concat()).unwrap();
        assert!(save_room_len(&table, label, &plan.policy, &PERSONA).unwrap() > bare.len());
    }

    #[test]
    fn the_planned_slot_is_strict_with_an_empty_grant_snapshot() {
        let table = vec![owner(Style::Everyday)];
        let plan = check_create(Some(&table[0]), PHONE, served(0, &table), &request(PERSONA, vec![1])).unwrap();
        let slot = planned_slot(&table, "l", &plan.policy).unwrap();
        assert_eq!(slot.slot_index, 1);
        assert!(slot.strict_permissions && !slot_is_bound(&slot) && !has_family_flags(&slot));
        assert!(!slot.allowed_methods.iter().any(|m| m == OWNER_MARK));
        // The site's key does not inherit the binding: its grant is the
        // ledger's to record.
        assert!(!client_identity_approved(&slot, Some(SITE), &PERSONA));
    }

    // --- the card, rows 20 and the T-Display limits ---

    #[test]
    fn the_card_names_the_unchecked_site_the_identity_and_the_device_scope() {
        let table = vec![owner(Style::Everyday)];
        let plan = check_create(Some(&table[0]), PHONE, served(0, &table), &request(PERSONA, vec![])).unwrap();
        let card = link_card("mysignet:kithmoot.com:0123abcd", "persona", 0, 0, &plan.policy, "My Signet");
        assert_eq!(card.lines(21, 18, 25), ["LINK ?kithmoot.com?", "AS persona", "DECRYPT+ANY KIND, NO ASK", "FROM My Signet"]);
        // Row 20: another master is named; the same master is not.
        let card = link_card("mysignet:kithmoot.com:0123abcd", "master1", 1, 0, &plan.policy, "My Signet");
        assert_eq!(card.as_line(18), "AS master1 M1");
        // Not My Signet's form: the whole label, its tail kept when cut.
        assert_eq!(site_of("Some App"), "Some App");
        assert_eq!(site_of("a:b:nothex!!"), "a:b:nothex!!");
        let card = link_card("mysignet:login.example.co.uk:0123abcd", "p", 0, 0, &plan.policy, "x");
        assert_eq!(card.heading(21), "LINK ?..xample.co.uk?");
        assert_eq!(card.heading(17), "LINK ?..le.co.uk?");
    }

    #[test]
    fn every_card_line_fits_the_narrowest_panel() {
        // 128x64: header 21, body 18, small 25. 172 portrait: header and
        // body 17, small 24.
        let long = "x".repeat(MAX_LABEL_LEN);
        for (header, body, small) in [(21, 18, 25), (17, 17, 24), (24, 24, 34), (21, 32, 45)] {
            for master in [0u8, 7] {
                for policy in [
                    validate_exact_slot_policy(vec!["sign_event".into()], (0..64).collect(), true).unwrap(),
                    validate_exact_slot_policy(vec!["sign_event".into()], vec![], false).unwrap(),
                    validate_exact_slot_policy(vec!["nip44_decrypt".into()], vec![], false).unwrap(),
                    validate_exact_slot_policy(vec!["nip44_decrypt".into()], vec![], true).unwrap(),
                    validate_exact_slot_policy(vec!["sign_event".into(), "nip44_decrypt".into()], (0..64).collect(), true)
                        .unwrap(),
                ] {
                    let card = link_card(&long, "?abcdefgh", master, 0, &policy, &long);
                    let lines = card.lines(header, body, small);
                    assert!(lines[0].len() <= header.min(crate::encoding::HEADING_CHARS), "{lines:?}");
                    assert!(lines[1].len() <= body, "{lines:?}");
                    assert!(lines[2].len() <= small && lines[3].len() <= small, "{lines:?}");
                    // The scope is never cut, so its decryption word survives.
                    assert_eq!(lines[2], scope_line(&policy), "{lines:?}");
                    assert!(lines[0].starts_with("LINK ?") && lines[0].ends_with('?'));
                    assert!(lines.iter().all(|l| l.bytes().all(|b| b == b' ' || b.is_ascii_graphic())));
                }
            }
        }
        // The identity label, at its 9 characters, is never cut, even with
        // a master marker on the narrowest body line.
        let policy = validate_exact_slot_policy(vec![], vec![], true).unwrap();
        assert_eq!(link_card("s", "?abcdefgh", 7, 0, &policy, "f").as_line(17), "AS ?abcdefgh M7");
    }

    #[test]
    fn the_scope_is_worked_out_from_the_policy() {
        let p = |m: &[&str], k: Vec<u64>, auto| {
            scope_line(&validate_exact_slot_policy(m.iter().map(|s| s.to_string()).collect(), k, auto).unwrap())
        };
        assert_eq!(p(&["sign_event"], vec![], true), "ANY KIND, NO ASKING");
        assert_eq!(p(&["sign_event"], vec![1], true), "1 KIND, NO ASKING");
        assert_eq!(p(&["sign_event"], vec![1, 7, 7], true), "2 KINDS, NO ASKING");
        assert_eq!(p(&["sign_event"], vec![1], false), "ASKS EACH TIME");
        assert_eq!(p(&["get_public_key"], vec![], true), "NO SIGNING, NO ASKING");
        assert_eq!(p(&["nip44_encrypt"], vec![], false), "NO SIGNING, ASKS");
        // Decryption is always named, first (review: the card once read
        // "NO SIGNING, NO ASKING" for a link that reads DMs silently).
        assert_eq!(p(&["get_public_key", "nip44_decrypt"], vec![], true), "DECRYPT, NO SIGN, NO ASK");
        assert_eq!(p(&["nip44_decrypt"], vec![], false), "DECRYPT, NO SIGN, ASKS");
        assert_eq!(p(&["sign_event", "nip44_decrypt"], vec![1], false), "DECRYPT, ASKS EACH TIME");
        assert_eq!(p(&["sign_event", "nip44_decrypt"], vec![], true), "DECRYPT+ANY KIND, NO ASK");
        assert_eq!(p(&["sign_event", "nip44_decrypt"], vec![1], true), "DECRYPT+1 KIND, NO ASK");
        assert_eq!(p(&["sign_event", "nip44_decrypt"], (0..64).collect(), true), "DECRYPT+64 KINDS, NO ASK");
        // Every combination fits the narrowest small row and names
        // decryption exactly when the link may decrypt.
        for methods in [&["get_public_key"][..], &["nip44_encrypt"], &["sign_event"], &["sign_event", "nip44_encrypt"]] {
            for decrypt in [false, true] {
                let mut m: Vec<&str> = methods.to_vec();
                if decrypt {
                    m.push("nip44_decrypt");
                }
                let signs = m.contains(&"sign_event");
                for kinds in [vec![], vec![1], (0..64).collect::<Vec<u64>>()] {
                    if !signs && !kinds.is_empty() {
                        continue;
                    }
                    for auto in [false, true] {
                        let line = p(&m, kinds.clone(), auto);
                        assert!(line.len() <= SCOPE_CHARS, "{line}");
                        assert_eq!(line.contains("DECRYPT"), decrypt, "{line}");
                    }
                }
            }
        }
    }

    // --- the ledger, rows 3, 4, 6, 11, 18 ---

    #[test]
    fn row_18_the_inherit_window_runs_60_s_from_the_hold_and_the_first_bind_clears_it() {
        let secret = "ab".repeat(32);
        let fp = credential_fingerprint(&secret);
        let mut ledger = LinkLedger::new();
        ledger.record(1, 3, fp.clone(), MASTER1, PHONE, "l", 10_000);
        assert_eq!(ledger.take_on_bind(1, 3, &secret, 69_999), Some(MASTER1));
        // Cleared by that bind: a second bind inherits nothing.
        assert_eq!(ledger.take_on_bind(1, 3, &secret, 70_000), None);
        // 61 s after the hold: nothing, and the entry is gone.
        ledger.record(1, 3, fp.clone(), MASTER1, PHONE, "l", 10_000);
        assert_eq!(ledger.take_on_bind(1, 3, &secret, 71_000), None);
        assert_eq!(ledger.live_count(0), 0);
        // A reused index on another credential never matches, and is cleared.
        ledger.record(1, 3, fp.clone(), MASTER1, PHONE, "l", 10_000);
        assert_eq!(ledger.take_on_bind(1, 3, &"cd".repeat(32), 20_000), None);
        assert_eq!(ledger.take_on_bind(1, 3, &secret, 20_000), None);
        // Another master's slot 3 is another slot.
        ledger.record(1, 3, fp.clone(), MASTER1, PHONE, "l", 10_000);
        assert_eq!(ledger.take_on_bind(0, 3, &secret, 20_000), None);
        // A revoke inside the window clears it.
        ledger.clear_slot(1, 3);
        assert_eq!(ledger.take_on_bind(1, 3, &secret, 20_000), None);
    }

    #[test]
    fn row_6_a_restart_forgets_every_entry() {
        // RAM only: a fresh ledger (a restart) has nothing to inherit.
        let ledger = LinkLedger::new();
        assert_eq!(ledger.live_count(0), 0);
        assert!(!ledger.cooling(PHONE, 0));
    }

    #[test]
    fn row_11_a_retry_finds_the_same_unbound_link_and_never_moves_the_deadline() {
        let table = vec![owner(Style::Everyday)];
        let plan = check_create(Some(&table[0]), PHONE, served(0, &table), &request(PERSONA, vec![])).unwrap();
        let req = request(PERSONA, vec![]);
        let mut link = planned_slot(&table, &req.label, &plan.policy).unwrap();
        link.secret = "ab".repeat(32);
        let table = vec![table[0].clone(), link.clone()];
        let mut ledger = LinkLedger::new();
        ledger.record(0, link.slot_index, credential_fingerprint(&link.secret), PERSONA, PHONE, &req.label, 1_000);
        assert_eq!(retry_target(&ledger, PHONE, &req, 0, &table, 30_000).map(|s| s.slot_index), Some(1));
        // Another client with the same label finds nothing.
        assert!(retry_target(&ledger, SITE, &req, 0, &table, 30_000).is_none());
        // Looking it up does not move the deadline.
        assert!(retry_target(&ledger, PHONE, &req, 0, &table, 61_000).is_none());
        // Once bound, a retry is a new ask.
        let mut bound = link.clone();
        bound.current_pubkey = Some(SITE.into());
        let table = vec![table[0].clone(), bound];
        assert!(retry_target(&ledger, PHONE, &req, 0, &table, 30_000).is_none());
        // The reply has create_client_v2's fields, less its note.
        let reply = create_reply(&link, "33", "bunker://33?secret=ab");
        for key in [
            "slot_index", "label", "secret", "secret_fingerprint", "npub_hex", "bunker_uri",
            "allowed_methods", "allowed_kinds", "auto_approve", "signing_approved", "policy_version",
        ] {
            assert!(reply.get(key).is_some(), "{key}");
        }
        assert!(reply.get("note").is_none());
        assert_eq!(reply["policy_version"], 2);
        assert_eq!(reply["label"], req.label.as_str());
    }

    #[test]
    fn rows_3_and_4_a_decline_or_timeout_cools_that_client_for_a_minute() {
        let mut ledger = LinkLedger::new();
        ledger.start_cooldown(PHONE, 5_000);
        assert!(ledger.cooling(PHONE, 64_999));
        assert!(!ledger.cooling(PHONE, 65_000));
        assert!(!ledger.cooling(SITE, 6_000));
        // The cap drops the oldest, and only it.
        let mut ledger = LinkLedger::new();
        let client = |i: u64| format!("{i:064x}");
        for i in 0..=(MAX_COOLDOWNS as u64) {
            ledger.start_cooldown(&client(i), 10_000 + i);
        }
        assert_eq!(ledger.cooldowns.len(), MAX_COOLDOWNS);
        assert!(!ledger.cooling(&client(0), 10_100), "the oldest went");
        for i in 1..=(MAX_COOLDOWNS as u64) {
            assert!(ledger.cooling(&client(i), 10_100), "{i} kept");
        }
        // A client cooled again keeps one entry, restarted, and pushes no
        // one else out.
        ledger.start_cooldown(&client(1), 20_000);
        assert_eq!(ledger.cooldowns.len(), MAX_COOLDOWNS);
        assert!(ledger.cooling(&client(1), 79_999) && !ledger.cooling(&client(1), 80_000));
        assert!(ledger.cooling(&client(2), 10_100));
    }

    #[test]
    fn row_7_a_second_ask_refuses_both_and_cools_both_phones() {
        let mut ledger = LinkLedger::new();
        // The asker cools at once; the waiting card's phone as its card
        // closes refused. Neither can raise a card for the minute.
        assert_eq!(ledger.another_link(SITE, 1_000), LinkError::AnotherLink);
        ledger.card_closed(PHONE, LinkClose::Refused(LinkError::AnotherLink), 1_000);
        assert!(ledger.cooling(SITE, 60_999) && ledger.cooling(PHONE, 60_999));
        // The same phone asking twice: one entry.
        ledger.another_link(PHONE, 2_000);
        assert_eq!(ledger.cooldowns.len(), 2);
        // A hold cools no one.
        let mut held = LinkLedger::new();
        held.card_closed(PHONE, LinkClose::Held, 1_000);
        assert!(!held.cooling(PHONE, 1_001));
    }

    #[test]
    fn a_cable_copy_of_a_link_method_is_nacked_only_in_the_wifi_loop() {
        for method in [METHOD_CREATE, METHOD_STATUS, METHOD_REVOKE] {
            assert!(cable_nacks(method, true), "{method}");
            // The USB-bridged loop answers RelayOnly.
            assert!(!cable_nacks(method, false), "{method}");
        }
        for method in ["sign_event", "heartwood_approve_bundle", "heartwood_link_other", ""] {
            assert!(!cable_nacks(method, true), "{method}");
        }
    }

    #[test]
    fn a_copy_of_the_waiting_request_is_ignored_and_any_other_ask_refuses_both() {
        let params = vec![serde_json::json!({"identity": "33"})];
        let other = vec![serde_json::json!({"identity": "44"})];
        let held = |client_hex, id| HeldLink { client_hex, id, params: &params };
        assert_eq!(against_waiting([], PHONE, "1", &params), Waiting::Nothing);
        assert_eq!(against_waiting([held(PHONE, "1")], PHONE, "1", &params), Waiting::Copy);
        // The same id with other params, another id, or another phone.
        assert_eq!(against_waiting([held(PHONE, "1")], PHONE, "1", &other), Waiting::Another);
        assert_eq!(against_waiting([held(PHONE, "1")], PHONE, "2", &params), Waiting::Another);
        assert_eq!(against_waiting([held(SITE, "1")], PHONE, "1", &params), Waiting::Another);
        // A copy of any waiting card's request, wherever it stands.
        assert_eq!(against_waiting([held(SITE, "9"), held(PHONE, "1")], PHONE, "1", &params), Waiting::Copy);

        let asking = owner(Style::Everyday);
        let req = request(PERSONA, vec![]);
        let plan = check_create(Some(&asking), PHONE, served(0, &[asking.clone()]), &req).unwrap();
        let made = asking.clone();
        let show = || Ok((Gate::Plan(plan.clone()), "drawn"));
        // A copy never reaches the gate.
        let never = || -> Result<(Gate<'_>, &str), LinkError> { panic!("a copy reached the gate") };
        assert!(matches!(card_step(Waiting::Copy, never), Ok(CardStep::Ignore)));
        assert!(matches!(card_step(Waiting::Nothing, show), Ok(CardStep::Show(p, "drawn")) if p == plan));
        assert!(matches!(card_step(Waiting::Another, show), Ok(CardStep::RefuseBoth)));
        // A retry or a refusal closes no one's card.
        assert!(matches!(
            card_step(Waiting::Another, || Ok((Gate::Retry(&made), "drawn"))),
            Ok(CardStep::Retry(s)) if s.slot_index == made.slot_index
        ));
        let refused = card_step::<&str>(Waiting::Another, || Err(LinkError::ShownRecently));
        assert_eq!(refused.unwrap_err(), LinkError::ShownRecently);
    }

    #[test]
    fn a_link_card_cools_its_phone_and_draws_by_how_it_closed() {
        use LinkClose::*;
        for (close, cools, blocked) in [
            (Held, false, None),
            (Declined, true, None),
            (TimedOut, true, None),
            (Refused(LinkError::AnotherLink), true, Some((LINK_BLOCKED, "2nd request"))),
            (Refused(LinkError::ApprovalChanged), false, Some((LINK_BLOCKED, "Slots changed"))),
        ] {
            assert_eq!(close.cools(), cools, "{close:?}");
            assert_eq!(close.blocked(), blocked, "{close:?}");
            if let Some((title, why)) = blocked {
                assert!(title.len() <= SCOPE_CHARS && why.len() <= SCOPE_CHARS);
            }
            let mut ledger = LinkLedger::new();
            ledger.card_closed(PHONE, close, 1_000);
            assert_eq!(ledger.cooling(PHONE, 60_999), cools, "{close:?}");
            assert!(!ledger.cooling(PHONE, 61_000));
        }
        // A refused card's refusal, read back from its message.
        assert_eq!(LinkClose::refused(LinkError::AnotherLink.message()), Refused(LinkError::AnotherLink));
        assert_eq!(LinkClose::refused(APPROVAL_CHANGED), Refused(LinkError::ApprovalChanged));
    }

    #[test]
    fn the_hold_checks_the_epoch_first_then_the_gate_without_the_cooldown() {
        let asking = owner(Style::Everyday);
        let req = request(PERSONA, vec![]);
        let table = vec![asking.clone()];
        let mut ledger = LinkLedger::new();
        ledger.start_cooldown(PHONE, 1_000);
        let at = |c: Check, ledger: &LinkLedger| check(c, Some(&asking), PHONE, served(0, &table), &req, ledger, 2_000, None);
        assert_eq!(at(Check::Card, &ledger).unwrap_err(), LinkError::ShownRecently);
        assert!(matches!(at(Check::Hold { epoch_current: true }, &ledger), Ok(Gate::Plan(_))));
        assert_eq!(at(Check::Hold { epoch_current: false }, &ledger).unwrap_err(), LinkError::ApprovalChanged);
        // A stale epoch beats a retry and every rule.
        let mut link = planned_slot(&table, &req.label, &check_create(Some(&asking), PHONE, served(0, &table), &req).unwrap().policy).unwrap();
        link.secret = "ab".repeat(32);
        let with_link = vec![asking.clone(), link.clone()];
        ledger.record(0, link.slot_index, credential_fingerprint(&link.secret), PERSONA, PHONE, &req.label, 1_000);
        let retry = |c| check(c, Some(&asking), PHONE, served(0, &with_link), &req, &ledger, 2_000, None);
        assert!(matches!(retry(Check::Hold { epoch_current: true }), Ok(Gate::Retry(_))));
        assert_eq!(retry(Check::Hold { epoch_current: false }).unwrap_err(), LinkError::ApprovalChanged);
        assert_eq!(
            check(Check::Hold { epoch_current: false }, None, PHONE, None, &req, &ledger, 2_000, None).unwrap_err(),
            LinkError::ApprovalChanged
        );
    }

    #[test]
    fn a_link_ask_weighs_its_params_and_the_overhead() {
        use serde_json::json;
        let compact = |p: &[Value]| serde_json::to_string(p).unwrap().len();
        let small = vec![json!({"identity": "33", "label": "x", "policy": {"allowed_methods": ["a", "b"]}})];
        assert_eq!(ask_weight(&small), compact(&small) + ASK_OVERHEAD);
        assert_eq!(ask_weight(&[]), 2 + 256);
        assert_eq!(ASK_OVERHEAD, 256);
        let big = vec![json!({"label": "y".repeat(9_000)})];
        assert!(ask_weight(&big) > 9_000 + ASK_OVERHEAD);
    }

    #[test]
    fn the_gate_runs_rules_then_retry_then_room_then_cooldown() {
        let asking = owner(Style::Everyday);
        let req = request(PERSONA, vec![]);
        let plan = check_create(Some(&asking), PHONE, served(0, &[asking.clone()]), &req).unwrap();
        // The link that took the last slot, its reply lost.
        let mut link = planned_slot(&[asking.clone()], &req.label, &plan.policy).unwrap();
        link.secret = "ab".repeat(32);
        let mut full = vec![asking.clone(), link.clone()];
        for i in 2..16 {
            full.push(base_slot(i, "other"));
        }
        let none = crate::nvs_room::NvsRoom { free_entries: 0, total_entries: 630, reclaimable_entries: 0 };
        let mut ledger = LinkLedger::new();
        ledger.record(0, 1, credential_fingerprint(&link.secret), PERSONA, PHONE, &req.label, 1_000);
        // The retry beats a full table, full NVS and a cooldown.
        ledger.start_cooldown(PHONE, 2_000);
        let retry = before_card(Some(&asking), PHONE, served(0, &full), &req, &ledger, 30_000, Some(none));
        assert_eq!(retry.map(|g| matches!(g, Gate::Retry(s) if s.slot_index == 1)), Ok(true));
        assert!(matches!(gate(Some(&asking), PHONE, served(0, &full), &req, &ledger, 30_000, Some(none)), Ok(Gate::Retry(_))));
        // Rules come first: a cooling stranger hears the rule, not the minute.
        assert_eq!(
            before_card(None, PHONE, served(0, &full), &req, &ledger, 30_000, None).unwrap_err(),
            LinkError::NotOwnerPairing
        );
        let mut wide = req.clone();
        wide.allowed_methods.push("heartwood_list_identities".into());
        assert_eq!(
            before_card(Some(&asking), PHONE, served(0, &full), &wide, &ledger, 30_000, None).unwrap_err(),
            LinkError::WiderThanPhone
        );
        // Another label: room before the cooldown.
        let mut other = req.clone();
        other.label = "mysignet:other.example:0123abcd".into();
        assert_eq!(
            before_card(Some(&asking), PHONE, served(0, &full), &other, &ledger, 30_000, None).unwrap_err(),
            LinkError::NoRoom
        );
        // With room, the cooldown; after it, the card's plan.
        let roomy = vec![asking.clone(), link];
        assert_eq!(
            before_card(Some(&asking), PHONE, served(0, &roomy), &other, &ledger, 30_000, None).unwrap_err(),
            LinkError::ShownRecently
        );
        assert!(matches!(
            before_card(Some(&asking), PHONE, served(0, &roomy), &other, &ledger, 62_000, None),
            Ok(Gate::Plan(_))
        ));
        // The hold's gate ignores the cooldown.
        assert!(matches!(gate(Some(&asking), PHONE, served(0, &roomy), &other, &ledger, 30_000, None), Ok(Gate::Plan(_))));
    }

    #[test]
    fn the_ledger_holds_at_most_a_few_live_links() {
        let mut ledger = LinkLedger::new();
        for i in 0..(MAX_LIVE_LINKS as u8 + 2) {
            ledger.record(0, i, "00".repeat(32), PERSONA, PHONE, &format!("l{i}"), 0);
        }
        assert_eq!(ledger.live_count(0), MAX_LIVE_LINKS);
        // The oldest went first.
        assert!(ledger.live_for_label(PHONE, "l0", 0).is_none());
        assert!(ledger.live_for_label(PHONE, "l5", 0).is_some());
    }

    // --- status and revoke, rows 11, 12, 13 ---

    fn link_slot(index: u8, secret: &str) -> ConnectSlot {
        let mut slot = strict_m1(vec![]);
        slot.slot_index = index;
        slot.label = "mysignet:kithmoot.com:0123abcd".into();
        slot.secret = secret.to_string();
        slot.current_pubkey = None;
        slot.authorized_pubkeys.clear();
        slot.was_bound = false;
        slot
    }

    #[test]
    fn rows_11_and_12_status_and_revoke_by_label_and_by_fingerprint() {
        let secret = "ab".repeat(32);
        let fp = credential_fingerprint(&secret);
        let table = vec![owner(Style::Everyday), link_slot(1, &secret)];
        let served = ServedIdentity { master_slot: 0, real: false, table: &table };
        let mut ledger = LinkLedger::new();
        ledger.record(0, 1, fp.clone(), PERSONA, PHONE, "mysignet:kithmoot.com:0123abcd", 0);
        let by_label = LookupRequest { identity: PERSONA, target: LinkTarget::Label("mysignet:kithmoot.com:0123abcd".into()) };
        let found = find_target(&ledger, &served, PHONE, &by_label, 1_000).unwrap();
        assert_eq!(status_reply(found).unwrap(), serde_json::json!({"exists": true, "bound": false}));
        assert_eq!(plan_revoke(found, true).unwrap(), RevokePlan::Remove { slot_index: 1, fingerprint: fp.clone() });
        // Another client's label reaches nothing, and so does a stale one.
        assert_eq!(find_target(&ledger, &served, SITE, &by_label, 1_000), Err(LinkError::UnknownLink));
        assert_eq!(find_target(&ledger, &served, PHONE, &by_label, 60_000), Err(LinkError::UnknownLink));
        // Another identity under the same label reaches nothing.
        let other = LookupRequest { identity: MASTER1, ..by_label.clone() };
        assert_eq!(find_target(&ledger, &served, PHONE, &other, 1_000), Err(LinkError::UnknownLink));

        // Bound: status says so, and the label alone does not remove it.
        let mut bound = link_slot(1, &secret);
        bound.current_pubkey = Some(SITE.into());
        let bound_table = vec![owner(Style::Everyday), bound];
        let bound_served = ServedIdentity { table: &bound_table, ..served };
        let found = find_target(&ledger, &bound_served, PHONE, &by_label, 1_000).unwrap();
        assert_eq!(status_reply(found).unwrap(), serde_json::json!({"exists": true, "bound": true}));
        assert_eq!(plan_revoke(found, true).unwrap(), RevokePlan::Keep(serde_json::json!({"revoked": false, "bound": true})));

        // Row 12: the fingerprint removes it bound or not; a wrong one is refused.
        let by_fp = LookupRequest { identity: PERSONA, target: LinkTarget::Fingerprint { slot_index: 1, fingerprint: fp.clone() } };
        let found = find_target(&LinkLedger::new(), &bound_served, SITE, &by_fp, 1_000_000).unwrap();
        assert_eq!(plan_revoke(found, false).unwrap(), RevokePlan::Remove { slot_index: 1, fingerprint: fp.clone() });
        let wrong = LookupRequest { identity: PERSONA, target: LinkTarget::Fingerprint { slot_index: 1, fingerprint: "cd".repeat(32) } };
        let found = find_target(&ledger, &served, PHONE, &wrong, 0).unwrap();
        assert_eq!(found, Found::Mismatch);
        assert_eq!(plan_revoke(found, false), Err(LinkError::StaleFingerprint));
        assert_eq!(status_reply(found).unwrap(), serde_json::json!({"exists": false, "bound": false}));
        let gone = LookupRequest { identity: PERSONA, target: LinkTarget::Fingerprint { slot_index: 9, fingerprint: fp.clone() } };
        let found = find_target(&ledger, &served, PHONE, &gone, 0).unwrap();
        assert_eq!(found, Found::Missing);
        assert_eq!(plan_revoke(found, false), Err(LinkError::UnknownLink));
        assert_eq!(revoked_reply(1, &fp)["revoked"], true);

        // An owner pairing, or a family slot, is never a target.
        let owner_fp = credential_fingerprint(&table[0].secret);
        let at_owner = LookupRequest { identity: PERSONA, target: LinkTarget::Fingerprint { slot_index: 0, fingerprint: owner_fp } };
        let found = find_target(&ledger, &served, PHONE, &at_owner, 0).unwrap();
        assert_eq!(plan_revoke(found, false), Err(LinkError::OwnerPairingTarget));
        assert_eq!(status_reply(found), Err(LinkError::OwnerPairingTarget));
        let mut child = link_slot(1, &secret);
        child.guardian_notice_wrap = true;
        assert_eq!(check_target(&child), Err(LinkError::FamilySlot));
    }

    #[test]
    fn row_13_a_link_made_through_the_operator_route_revokes_by_fingerprint() {
        // Its record keeps the slot index and fingerprint; no ledger entry.
        let secret = "ef".repeat(32);
        let table = vec![owner(Style::Everyday), link_slot(4, &secret)];
        let served = ServedIdentity { master_slot: 0, real: false, table: &table };
        let req = LookupRequest {
            identity: PERSONA,
            target: LinkTarget::Fingerprint { slot_index: 4, fingerprint: credential_fingerprint(&secret) },
        };
        let found = find_target(&LinkLedger::new(), &served, PHONE, &req, 0).unwrap();
        assert!(matches!(plan_revoke(found, false), Ok(RevokePlan::Remove { slot_index: 4, .. })));
    }

    #[test]
    fn status_and_revoke_keep_rules_1_to_5() {
        let asking = owner(Style::Everyday);
        let m1 = vec![strict_m1(vec![])];
        assert!(check_phone(Some(&asking), PHONE, &MASTER1, served(1, &m1)).is_ok());
        assert_eq!(check_phone(Some(&m1[0]), PHONE, &MASTER1, served(1, &m1)).unwrap_err(), LinkError::NotOwnerPairing);
        assert_eq!(check_phone(Some(&asking), SITE, &MASTER1, served(1, &m1)).unwrap_err(), LinkError::NotApprovedForIdentity);
    }

    #[test]
    fn every_refusal_has_a_message_and_the_design_strings_hold() {
        use LinkError::*;
        for e in [
            Malformed, RelayOnly, Declined, Timeout, Busy, AnotherLink, ShownRecently, NoRoom, NotOwnerPairing,
            IdentityNotServed, NotApprovedForIdentity, WiderThanPhone, FamilySlot, RealIdentity, ApprovalChanged,
            UnknownLink, StaleFingerprint, OwnerPairingTarget,
        ] {
            assert!(!e.message().is_empty());
            assert!(e.code() < 0);
        }
        assert_eq!(WiderThanPhone.message(), "wider than this phone's access");
        assert_eq!(NotApprovedForIdentity.message(), "not approved for identity");
        assert!(ApprovalChanged.message().starts_with("approval_changed"));
        assert_eq!(Busy.message(), crate::approval_queue::BUSY_ERROR);
        // The approved-but-not-done card reads a stale hold as a pairing change.
        assert_eq!(
            crate::approval_queue::approved_but_not_done(Some(ApprovalChanged.message())),
            Some(("Pairing changed", "Ask again from the app"))
        );
    }
}
