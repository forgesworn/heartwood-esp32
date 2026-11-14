// firmware/src/relay/site_link.rs
//
// Relay glue for site links made by the Heartwood, with a hold (signet-plans
// site links design). Every rule is `heartwood_common::site_link`'s; this
// file reads the slot tables, raises the LINK card on the #64 queue and, at
// the hold, creates the slot. The card's reply is sealed and published by
// `resolve_button_card`'s own loop, like every other card's.

use std::sync::{Mutex, MutexGuard};

use heartwood_common::hex::hex_encode;
use heartwood_common::mgmt;
use heartwood_common::nip46::{self, Nip46Request};
use heartwood_common::site_link::{self as sl, LinkError, LinkLedger, RevokePlan, ServedIdentity};
use serde_json::Value;

use crate::nip46_handler::{AskCard, DeferredAsk};

use super::{SignCtx, Tls, NIP46_KIND};

/// The inherit entries and cooldowns (design 4.2, 4.4). RAM only. A static
/// because the bind that spends an entry runs in `nip46_handler::dispatch`,
/// which has no relay context.
static LINKS: Mutex<LinkLedger> = Mutex::new(LinkLedger::new());

fn links() -> MutexGuard<'static, LinkLedger> {
    LINKS.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

type Refusal = (i32, String);

fn refusal(e: LinkError) -> Refusal {
    (e.code(), e.message().into())
}

/// A slot's first bind: the identity its link grants, if any (design 4.2).
pub(crate) fn take_on_bind(master_slot: u8, slot_index: u8, secret: &str) -> Option<[u8; 32]> {
    links().take_on_bind(master_slot, slot_index, secret, crate::uptime_ms())
}

/// A LINK card closed: anything but the hold cools its phone; a card the
/// slot tables closed was counted when it was marked (design 4.4,
/// [`sl::LinkLedger::card_closed`]).
pub(super) fn card_closed(client_hex: &str, close: sl::LinkClose) {
    links().card_closed(client_hex, close, crate::uptime_ms());
}

/// The named identity as the gate sees it, and the name its card shows. A
/// locked master serves nothing, nor do its personas.
fn served<'c>(ctx: &'c SignCtx, identity: &[u8; 32]) -> Option<(ServedIdentity<'c>, String)> {
    use heartwood_common::owner_pairing::is_real_identity_name;
    let (master_slot, real, served_label) = match ctx.masters.iter().find(|m| m.pubkey == *identity) {
        Some(m) => (m.slot, false, m.label.as_str()),
        None => {
            let p = ctx.personas.iter().find(|p| p.pubkey == *identity)?;
            let real = p.name.as_deref().is_some_and(is_real_identity_name)
                || p.purpose.strip_prefix("nostr:persona:").is_some_and(is_real_identity_name);
            (p.master_slot, real, "")
        }
    };
    ctx.masters.iter().find(|m| m.slot == master_slot && !m.locked)?;
    let label = crate::nip46_handler::identity_label_for(ctx.personas, served_label, identity, None);
    Some((ServedIdentity { master_slot, real, table: ctx.policy_engine.list_slots(master_slot) }, label))
}

/// What a create asks of the loop before the hold.
enum Step {
    /// A copy of the request a waiting LINK card holds: no reply.
    Ignore,
    Reply(Value),
    Queue(DeferredAsk),
}

/// Answer `heartwood_link_create`, `_status` or `_revoke` from the phone's
/// connection (`slot` is its master). Every refusal is answered here, before
/// any card; a create that passes goes on the card queue.
#[allow(clippy::too_many_arguments)]
pub(super) fn handle(
    tls: &mut Tls,
    ctx: &mut SignCtx,
    request: Nip46Request,
    slot: u8,
    target_pk: &[u8; 32],
    client_pubkey: &[u8; 32],
    client_hex: &str,
    conversation_key: &[u8; 32],
    signing_secret: &[u8; 32],
    created_at: u64,
    received_uptime: u64,
) -> Result<(), String> {
    let id = request.id.clone();
    let reply = if request.method == sl::METHOD_CREATE {
        match before_card(ctx, request, slot, client_hex) {
            Ok(Step::Ignore) => return Ok(()),
            Ok(Step::Queue(ask)) => {
                return super::queue_button_ask(
                    tls,
                    ctx,
                    ask,
                    slot,
                    target_pk,
                    client_pubkey,
                    client_hex,
                    conversation_key,
                    signing_secret,
                    created_at,
                    received_uptime,
                    None,
                )
            }
            Ok(Step::Reply(value)) => Ok(value),
            Err(e) => Err(e),
        }
    } else {
        lookup(ctx, &request, slot, client_hex)
    };
    let response = answer(&id, reply);
    let stamp = ctx.reply_clock.stamp(created_at, received_uptime, crate::uptime_s());
    super::sign_and_publish(tls, ctx.secp, signing_secret, conversation_key, client_hex, NIP46_KIND, stamp, response)
}

fn answer(id: &str, reply: Result<Value, Refusal>) -> String {
    match reply {
        Ok(value) => nip46::build_result_response(id, &value.to_string()),
        Err((code, message)) => nip46::build_error_response(id, code, &message),
    }
    .unwrap_or_default()
}

fn nvs_room(ctx: &SignCtx) -> Option<heartwood_common::nvs_room::NvsRoom> {
    crate::nip46_handler::nvs_room(ctx.nvs)
}

/// Rules 1 to 6, the retry, room (rule 7), the cooldown and the one-card
/// rule (design 4.3 to 4.5), in `sl::card_step`'s order; nothing is written.
fn before_card(ctx: &mut SignCtx, request: Nip46Request, slot: u8, client_hex: &str) -> Result<Step, Refusal> {
    let create = sl::parse_create(&request.params).map_err(refusal)?;
    let engine = &*ctx.policy_engine;
    let current = |epoch| engine.approval_is_current(epoch);
    let now = crate::uptime_ms();
    let waiting =
        sl::against_waiting(&mut ctx.button_cards, current, &mut links(), now, client_hex, &request.id, &request.params);
    let step = sl::card_step(waiting, || {
        gate(ctx, &create, slot, client_hex, sl::Check::Card).map(|(verdict, label, from)| (verdict, (label, from)))
    });
    let card = match step.map_err(refusal)? {
        sl::CardStep::Ignore => return Ok(Step::Ignore),
        sl::CardStep::Retry(made) => return Ok(Step::Reply(retry_reply(ctx, &create, made))),
        sl::CardStep::Show(plan, (label, from)) => {
            sl::link_card(&create.label, &label, plan.master_slot, slot, &plan.policy, from)
        }
        // Both are refused: the waiting cards close on the next pass, their
        // phones cooling as they do, and the asker cools now.
        sl::CardStep::RefuseBoth => {
            let refused = sl::refuse_both(&mut ctx.button_cards, &mut links(), client_hex, crate::uptime_ms());
            return Err(refusal(refused));
        }
    };
    if !crate::entropy::rng_ok() {
        return Err((-1, crate::entropy::rng_refusal().into()));
    }
    let resume = crate::nip46_handler::Resume {
        authority_epoch: ctx.policy_engine.approval_epoch(),
        ..Default::default()
    };
    Ok(Step::Queue(DeferredAsk {
        card: AskCard::SiteLink { card, create },
        request,
        event: None,
        identity: None,
        resume,
    }))
}

/// LINK cards the slot tables overtook (an authority change on any master's
/// slots moves the approval epoch) are refused `approval_changed` as soon as
/// the loop sees them, queued or on screen, not only at the hold, and their
/// phones' closes counted then ([`sl::refuse_stale`]).
pub(super) fn refuse_stale(ctx: &mut SignCtx) {
    let engine = &*ctx.policy_engine;
    sl::refuse_stale(&mut ctx.button_cards, |epoch| engine.approval_is_current(epoch), &mut links(), crate::uptime_ms());
}

impl sl::WaitingCard for super::ButtonCard {
    fn held(&self, i: usize) -> Option<sl::HeldLink<'_>> {
        let a = self.asks.get(i).filter(|_| is_link_card(self))?;
        Some(sl::HeldLink {
            client_hex: &self.key.client_hex,
            id: &a.ask.request.id,
            params: &a.ask.request.params,
            epoch: a.ask.resume.authority_epoch,
        })
    }

    fn link_refusal(&self) -> Option<sl::LinkRefusal> {
        match self.refused {
            Some(super::CardRefusal::Link(why)) => Some(why),
            Some(super::CardRefusal::FullAccess(_)) | None => None,
        }
    }

    fn refuse_link(&mut self, why: sl::LinkRefusal) {
        self.refused = Some(super::CardRefusal::Link(why));
    }
}

/// Whether a card is a LINK card.
pub(super) fn is_link_card(card: &super::ButtonCard) -> bool {
    card.asks.first().is_some_and(|a| matches!(a.ask.card, AskCard::SiteLink { .. }))
}

/// `common::site_link::check` against the tables as they are now, shared
/// by the card and the hold: the verdict, the identity's card name and the
/// asking slot's label.
fn gate<'c>(
    ctx: &'c SignCtx,
    create: &sl::CreateRequest,
    asking_master: u8,
    client_hex: &str,
    check: sl::Check,
) -> Result<(sl::Gate<'c>, String, &'c str), LinkError> {
    let asking = ctx.policy_engine.find_slot_by_pubkey(asking_master, client_hex);
    let (found, label) = match served(ctx, &create.identity) {
        Some((found, label)) => (Some(found), label),
        None => (None, String::new()),
    };
    let verdict = sl::check(check, asking, client_hex, found, create, &links(), crate::uptime_ms(), nvs_room(ctx))?;
    Ok((verdict, label, asking.map_or("", |a| a.label.as_str())))
}

/// The same link again, answered as the hold answered it.
fn retry_reply(ctx: &SignCtx, create: &sl::CreateRequest, made: &heartwood_common::policy::ConnectSlot) -> Value {
    let identity = hex_encode(&create.identity);
    let uri = mgmt::bunker_uri(&identity, &ctx.relays, Some(&made.secret));
    sl::create_reply(made, &identity, &uri)
}

/// Status and revoke (design 4.5): rules 1 to 5 for the identity, then the
/// target, which never reaches an owner pairing or a family slot.
fn lookup(ctx: &mut SignCtx, request: &Nip46Request, slot: u8, client_hex: &str) -> Result<Value, Refusal> {
    let lookup = sl::parse_lookup(&request.params).map_err(refusal)?;
    let by_label = matches!(lookup.target, sl::LinkTarget::Label(_));
    let (master, plan) = {
        let asking = ctx.policy_engine.find_slot_by_pubkey(slot, client_hex);
        let found = served(ctx, &lookup.identity).map(|f| f.0);
        let (_, served) = sl::check_phone(asking, client_hex, &lookup.identity, found).map_err(refusal)?;
        let target = sl::find_target(&links(), &served, client_hex, &lookup, crate::uptime_ms()).map_err(refusal)?;
        if request.method == sl::METHOD_STATUS {
            return sl::status_reply(target).map_err(refusal);
        }
        (served.master_slot, sl::plan_revoke(target, by_label).map_err(refusal)?)
    };
    let (slot_index, fingerprint) = match plan {
        RevokePlan::Keep(value) => return Ok(value),
        RevokePlan::Remove { slot_index, fingerprint } => (slot_index, fingerprint),
    };
    let snapshot = ctx.policy_engine.snapshot_slot_state(master);
    ctx.policy_engine.revoke_slot(master, slot_index);
    super::persist_slot_mutation_or_rollback(ctx, master, snapshot, "client revocation").map_err(|e| (-1, e))?;
    links().clear_slot(master, slot_index);
    Ok(sl::revoked_reply(slot_index, &fingerprint))
}

/// The hold on a LINK card: the response `resolve_button_card` seals. The
/// request is checked again against the tables as they are now (design 4.4:
/// an authority change on any master's slots since the card answers
/// `approval_changed`), and the slot is written only here.
pub(super) fn complete(ctx: &mut SignCtx, ask: &DeferredAsk, asking_master: u8, client_hex: &str) -> String {
    let reply = match &ask.card {
        AskCard::SiteLink { create, .. } => make(ctx, create, ask.resume.authority_epoch, asking_master, client_hex),
        _ => Err(refusal(LinkError::Malformed)),
    };
    answer(&ask.request.id, reply)
}

fn make(
    ctx: &mut SignCtx,
    create: &sl::CreateRequest,
    epoch: Option<u32>,
    asking_master: u8,
    client_hex: &str,
) -> Result<Value, Refusal> {
    // One epoch covers every master's table.
    let check = sl::Check::Hold { epoch_current: ctx.policy_engine.approval_is_current(epoch) };
    let plan = match gate(ctx, create, asking_master, client_hex, check).map_err(refusal)?.0 {
        sl::Gate::Retry(made) => return Ok(retry_reply(ctx, create, made)),
        sl::Gate::Plan(plan) => plan,
    };
    if !crate::entropy::rng_ok() {
        return Err((-1, crate::entropy::rng_refusal().into()));
    }
    let mut secret_bytes = [0u8; 32];
    crate::fill_random(&mut secret_bytes);
    let secret = hex_encode(&secret_bytes);
    zeroize::Zeroize::zeroize(&mut secret_bytes);
    let master = plan.master_slot;
    let snapshot = ctx.policy_engine.snapshot_slot_state(master);
    let index = ctx
        .policy_engine
        .create_slot_with_exact_policy(master, create.label.clone(), secret.clone(), plan.policy)
        .ok_or_else(|| refusal(LinkError::NoRoom))?;
    super::persist_slot_mutation_or_rollback(ctx, master, snapshot, "client creation").map_err(|e| (-1, e))?;
    links().record(
        master,
        index,
        mgmt::credential_fingerprint(&secret),
        create.identity,
        client_hex,
        &create.label,
        crate::uptime_ms(),
    );
    let made = ctx
        .policy_engine
        .list_slots(master)
        .iter()
        .find(|s| s.slot_index == index)
        .ok_or_else(|| refusal(LinkError::NoRoom))?;
    let identity = hex_encode(&create.identity);
    let uri = mgmt::bunker_uri(&identity, &ctx.relays, Some(&secret));
    Ok(sl::create_reply(made, &identity, &uri))
}
