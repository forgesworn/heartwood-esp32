// firmware/src/confirm.rs
//
// Non-blocking holds for post-signing confirmation cards (#60).
//
// The first fix for the too-fast SIGNED card was a blocking delay inside
// show_signed() (373831d); it was reverted (2013bc3) because it ran before
// the response was written and pushed the NIP-44 re-encryption past
// heartwoodd's 60-second timeout. This module holds cards *after* the
// handler returns instead: presenting a card starts a hold that the idle
// loops respect, back-to-back confirmations (a NIP-17 seal + wrap) queue
// rather than overwrite, and a button press dismisses the run early.
// Nothing here ever delays a response.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::oled::Display;

/// How long each confirmation card stays up before the next queued card (or
/// the idle screen) may replace it. Enforced by the loop ticks, not by
/// blocking the signing handler.
const HOLD: Duration = Duration::from_secs(3);

/// Cards queued beyond this coalesce by dropping the oldest — the newest
/// are the ones the user has not yet had a chance to see.
const MAX_QUEUED: usize = 4;

/// One completed signing, as shown on the OLED.
pub struct Card {
    pub requester: String,
    pub kind: u64,
    /// Auto-approved by policy (AUTO-SIGNED card) vs button-approved (SIGNED).
    pub auto: bool,
}

struct State {
    /// Deadline of the card currently on screen; `None` when nothing is held.
    hold_until: Option<Instant>,
    queue: VecDeque<Card>,
    /// The idle screen is restored exactly once, after the last hold expires.
    restore_pending: bool,
}

static STATE: Mutex<State> = Mutex::new(State {
    hold_until: None,
    queue: VecDeque::new(),
    restore_pending: false,
});

fn draw(display: &mut Display<'_>, card: &Card) {
    if card.auto {
        crate::oled::show_auto_signed(display, &card.requester, card.kind);
    } else {
        crate::oled::show_signed(display, &card.requester, card.kind);
    }
}

/// Show a confirmation card now, or queue it behind the one already held.
pub fn present(display: &mut Display<'_>, card: Card) {
    let mut st = STATE.lock().unwrap();
    let holding = st.hold_until.map(|t| Instant::now() < t).unwrap_or(false);
    if holding || !st.queue.is_empty() {
        if st.queue.len() >= MAX_QUEUED {
            st.queue.pop_front();
        }
        st.queue.push_back(card);
        return;
    }
    draw(display, &card);
    st.hold_until = Some(Instant::now() + HOLD);
    st.restore_pending = true;
}

/// Idle-loop tick. Draws the next queued card when the current hold expires.
/// Returns true exactly once, when the last card's hold ends — the caller
/// restores its idle screen.
pub fn service(display: &mut Display<'_>) -> bool {
    let mut st = STATE.lock().unwrap();
    let Some(until) = st.hold_until else {
        return false;
    };
    if Instant::now() < until {
        return false;
    }
    if let Some(card) = st.queue.pop_front() {
        draw(display, &card);
        st.hold_until = Some(Instant::now() + HOLD);
        return false;
    }
    st.hold_until = None;
    let restore = st.restore_pending;
    st.restore_pending = false;
    restore
}

/// A button press while cards are held dismisses the whole run early.
/// Returns true when something was dismissed — the caller restores its idle
/// screen instead of paging the carousel.
pub fn dismiss() -> bool {
    let mut st = STATE.lock().unwrap();
    if st.hold_until.is_none() && st.queue.is_empty() {
        return false;
    }
    st.hold_until = None;
    st.queue.clear();
    st.restore_pending = false;
    true
}

/// True while a confirmation is on screen or queued — callers that would
/// redraw the idle screen unconditionally skip it and let `service` restore.
pub fn active() -> bool {
    let st = STATE.lock().unwrap();
    st.hold_until.map(|t| Instant::now() < t).unwrap_or(false) || !st.queue.is_empty()
}
