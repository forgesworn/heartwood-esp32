// heartwoodd/src/relay.rs
//
// NIP-46 relay event loop. Subscribes to kind:24133 events p-tagged
// with the signing master pubkey and dispatches them to the backend.
// Both Hard and Soft modes use the same loop -- the SigningBackend
// trait abstracts the signing implementation.

use std::sync::Arc;

use nostr_sdk::prelude::*;

use crate::backend::{BackendError, SigningBackend};

/// Subscribe to NIP-46 events and dispatch them to the given backend indefinitely.
///
/// Creates a filter for kind:24133 events p-tagged with `signing_pubkey`, subscribes,
/// then enters the notification loop. For each request:
///
///   1. Calls `backend.handle_encrypted_request` to decrypt and process the payload.
///   2. Calls `backend.sign_envelope` to build and sign the Nostr response event.
///   3. Publishes the signed event to connected relays.
///
/// Returns when the notification loop ends (relay disconnection, or an internal error).
pub async fn run_event_loop(
    client: &Client,
    backend: &Arc<dyn SigningBackend>,
    signing_pubkey: &[u8; 32],
) -> Result<()> {
    let signing_nostr_pubkey = PublicKey::from_slice(signing_pubkey)
        .expect("signing pubkey is a valid secp256k1 x-only key");

    let filter = Filter::new()
        .kind(Kind::NostrConnect)
        .pubkey(signing_nostr_pubkey)
        .since(Timestamp::now());

    client.subscribe(filter, None).await?;
    log::info!("Subscribed to NIP-46 events -- waiting for requests...");

    let backend = Arc::clone(backend);
    let master_pubkey_bytes: [u8; 32] = *signing_pubkey;
    let client_clone = client.clone();

    client
        .handle_notifications(|notification| {
            let backend = Arc::clone(&backend);
            let client_clone = client_clone.clone();

            async move {
                let event = match notification {
                    RelayPoolNotification::Event { event, .. } => event,
                    _ => return Ok(false),
                };

                // Only process NIP-46 requests.
                if event.kind != Kind::NostrConnect {
                    return Ok(false);
                }

                let client_pubkey = event.pubkey;
                log::info!("NIP-46 request from {}", client_pubkey);

                let client_pubkey_bytes: [u8; 32] = client_pubkey.to_bytes();

                // Step 1: decrypt and process the encrypted request, returning
                // an encrypted response ciphertext.
                let response_ciphertext = match backend.handle_encrypted_request(
                    &master_pubkey_bytes,
                    &client_pubkey_bytes,
                    &event.content,
                ) {
                    Ok(ct) => ct,
                    Err(BackendError::PendingApproval(id)) => {
                        log::info!("Request queued for approval: {id}");
                        return Ok(false);
                    }
                    Err(e) => {
                        log::error!("Backend error handling request: {e}");
                        return Ok(false);
                    }
                };

                // Step 2: build and sign the outer kind:24133 envelope event.
                let created_at: u64 = Timestamp::now().as_secs();
                let signed_event_json = match backend.sign_envelope(
                    &master_pubkey_bytes,
                    &client_pubkey_bytes,
                    created_at,
                    &response_ciphertext,
                ) {
                    Ok(json) => json,
                    Err(e) => {
                        log::error!("Envelope sign error: {e}");
                        return Ok(false);
                    }
                };

                // Step 3: parse the pre-signed event and publish it verbatim.
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
