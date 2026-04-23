// heartwoodd/src/relay.rs
//
// NIP-46 relay event loop. Subscribes to kind:24133 events p-tagged
// with any of the configured master pubkeys and dispatches each event
// to the backend along with the master identified by its p-tag.
// Both Hard and Soft modes use the same loop -- the SigningBackend
// trait abstracts the signing implementation.

use std::collections::HashSet;
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

    client
        .handle_notifications(|notification| {
            let backend = Arc::clone(&backend);
            let client_clone = client_clone.clone();
            let accepted = Arc::clone(&accepted);

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
                log::info!(
                    "NIP-46 request from {} to master {}",
                    client_pubkey,
                    PublicKey::from_slice(&master_pubkey_bytes)
                        .map(|pk| pk.to_string())
                        .unwrap_or_else(|_| "<invalid>".to_string())
                );

                let client_pubkey_bytes: [u8; 32] = client_pubkey.to_bytes();

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
