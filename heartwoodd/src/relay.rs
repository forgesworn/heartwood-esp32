// heartwoodd/src/relay.rs
//
// NIP-46 relay event loop. Subscribes to kind:24133 events p-tagged
// with any of the configured master pubkeys and dispatches each event
// to the backend along with the master identified by its p-tag.
// Both Hard and Soft modes use the same loop -- the SigningBackend
// trait abstracts the signing implementation.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use nostr_sdk::prelude::*;

use crate::backend::{BackendError, SigningBackend};

/// Subscribe to NIP-46 events and dispatch them to the given backend indefinitely.
///
/// Creates a filter for kind:24133 events p-tagged with any of `signing_pubkeys`,
/// subscribes, then enters the notification loop. For each request:
///
///   1. Extracts the addressed master pubkey from the event's p-tag and
///      verifies it is one of the configured masters.
///   2. Calls `backend.handle_encrypted_request` to decrypt, process, re-encrypt,
///      and sign the kind:24133 envelope event (all in one call).
///   3. Publishes the signed event to connected relays.
///
/// Returns when the notification loop ends (relay disconnection, or an internal error).
pub async fn run_event_loop(
    client: &Client,
    backend: &Arc<dyn SigningBackend>,
    signing_pubkeys: &[[u8; 32]],
    master_labels: &HashMap<[u8; 32], String>,
    client_labels: &HashMap<[u8; 32], String>,
) -> Result<()> {
    let nostr_pubkeys: Vec<PublicKey> = signing_pubkeys
        .iter()
        .map(|bytes| {
            PublicKey::from_slice(bytes)
                .expect("signing pubkey is a valid secp256k1 x-only key")
        })
        .collect();

    let accepted: Arc<HashSet<[u8; 32]>> =
        Arc::new(signing_pubkeys.iter().copied().collect());

    let filter = Filter::new()
        .kind(Kind::NostrConnect)
        .pubkeys(nostr_pubkeys)
        .since(Timestamp::now());

    client.subscribe(filter, None).await?;
    log::info!(
        "Subscribed to NIP-46 events for {} master(s) -- waiting for requests...",
        signing_pubkeys.len()
    );

    let backend = Arc::clone(backend);
    let client_clone = client.clone();
    let master_labels = Arc::new(master_labels.clone());
    let client_labels = Arc::new(client_labels.clone());

    client
        .handle_notifications(|notification| {
            let backend = Arc::clone(&backend);
            let client_clone = client_clone.clone();
            let accepted = Arc::clone(&accepted);
            let master_labels = Arc::clone(&master_labels);
            let client_labels = Arc::clone(&client_labels);

            async move {
                let event = match notification {
                    RelayPoolNotification::Event { event, .. } => event,
                    _ => return Ok(false),
                };

                // Only process NIP-46 requests.
                if event.kind != Kind::NostrConnect {
                    return Ok(false);
                }

                // Identify the addressed master from the event's p-tag.
                let master_pubkey_bytes: [u8; 32] = match event
                    .tags
                    .public_keys()
                    .next()
                    .map(|pk| pk.to_bytes())
                {
                    Some(bytes) if accepted.contains(&bytes) => bytes,
                    Some(bytes) => {
                        log::warn!(
                            "NIP-46 request addressed to unknown master {} -- ignoring",
                            PublicKey::from_slice(&bytes)
                                .map(|pk| pk.to_string())
                                .unwrap_or_else(|_| "<invalid>".to_string())
                        );
                        return Ok(false);
                    }
                    None => {
                        log::warn!("NIP-46 request missing p-tag -- ignoring");
                        return Ok(false);
                    }
                };

                let client_pubkey = event.pubkey;
                let client_pubkey_bytes: [u8; 32] = client_pubkey.to_bytes();
                let master_hex = PublicKey::from_slice(&master_pubkey_bytes)
                    .map(|pk| pk.to_string())
                    .unwrap_or_else(|_| "<invalid>".to_string());
                log::info!(
                    "NIP-46 request from {} to master {}",
                    describe_pubkey(&client_labels, &client_pubkey_bytes, &client_pubkey.to_string()),
                    describe_pubkey(&master_labels, &master_pubkey_bytes, &master_hex),
                );

                // Handle the NIP-46 request: decrypt, process, re-encrypt,
                // build and sign the kind:24133 envelope — all in one call.
                let created_at: u64 = Timestamp::now().as_secs();
                let signed_event_json = match backend.handle_encrypted_request(
                    &master_pubkey_bytes,
                    &client_pubkey_bytes,
                    created_at,
                    &event.content,
                ) {
                    Ok(json) => json,
                    Err(BackendError::PendingApproval(id)) => {
                        log::info!("Request queued for approval: {id}");
                        return Ok(false);
                    }
                    Err(e) => {
                        log::error!("Backend error: {e}");
                        return Ok(false);
                    }
                };

                // Parse the pre-signed event and publish it verbatim.
                let signed_event = match Event::from_json(&signed_event_json) {
                    Ok(ev) => ev,
                    Err(e) => {
                        log::error!("Failed to parse signed envelope: {e}");
                        return Ok(false);
                    }
                };

                match client_clone.send_event(&signed_event).await {
                    Ok(output) => log::info!("Response published: {}", output.id()),
                    Err(e) => log::error!("Publish failed: {e}"),
                }

                Ok(false) // keep listening
            }
        })
        .await?;

    Ok(())
}

/// Format a pubkey for logging, prefixing a known slot/master label.
///
/// Falls back to the bare hex pubkey when the key is not in the label map,
/// so requests stay greppable by full pubkey regardless of label coverage.
fn describe_pubkey(labels: &HashMap<[u8; 32], String>, pk: &[u8; 32], hex: &str) -> String {
    match labels.get(pk) {
        Some(label) if !label.is_empty() => format!("\"{label}\" ({hex})"),
        _ => hex.to_string(),
    }
}
