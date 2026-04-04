// common/src/frame.rs
//
// Serial frame protocol shared between firmware and host tools.
//
// Frame format:
//   [0x48 0x57] [type_u8] [length_u16_be] [payload...] [crc32_4]
//
// CRC32 covers: type byte + length bytes + payload (NOT the magic bytes).

use crate::types::{FRAME_OVERHEAD, FRAME_HEADER_SIZE, MAGIC_BYTES, MAX_PAYLOAD_SIZE};

/// A parsed frame received over the serial link.
#[derive(Debug, PartialEq)]
pub struct Frame {
    pub frame_type: u8,
    pub payload: Vec<u8>,
}

/// Errors that can occur when building or parsing a frame.
#[derive(Debug, PartialEq)]
pub enum FrameError {
    /// Input is shorter than the minimum frame size.
    TooShort,
    /// Magic bytes do not match `[0x48, 0x57]`.
    BadMagic,
    /// Payload length exceeds `MAX_PAYLOAD_SIZE`.
    PayloadTooLarge,
    /// CRC32 checksum does not match.
    BadCrc,
}

/// Build a complete frame from a type byte and payload slice.
///
/// Returns an error if the payload exceeds `MAX_PAYLOAD_SIZE`.
pub fn build_frame(frame_type: u8, payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    if payload.len() > MAX_PAYLOAD_SIZE {
        return Err(FrameError::PayloadTooLarge);
    }

    let length = payload.len() as u16;
    let length_bytes = length.to_be_bytes();

    // CRC covers type + length bytes + payload.
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&[frame_type]);
    hasher.update(&length_bytes);
    hasher.update(payload);
    let crc = hasher.finalize();

    let mut frame = Vec::with_capacity(FRAME_OVERHEAD + payload.len());
    frame.extend_from_slice(&MAGIC_BYTES);
    frame.push(frame_type);
    frame.extend_from_slice(&length_bytes);
    frame.extend_from_slice(payload);
    frame.extend_from_slice(&crc.to_be_bytes());

    Ok(frame)
}

/// Parse and validate a frame from raw bytes.
///
/// Returns the decoded `Frame` on success, or a `FrameError` if the data is
/// malformed, too short, or the checksum fails.
pub fn parse_frame(data: &[u8]) -> Result<Frame, FrameError> {
    if data.len() < FRAME_OVERHEAD {
        return Err(FrameError::TooShort);
    }

    if data[0] != MAGIC_BYTES[0] || data[1] != MAGIC_BYTES[1] {
        return Err(FrameError::BadMagic);
    }

    let frame_type = data[2];
    let length = u16::from_be_bytes([data[3], data[4]]) as usize;

    if length > MAX_PAYLOAD_SIZE {
        return Err(FrameError::PayloadTooLarge);
    }

    // Ensure there is enough data for the declared payload plus the CRC.
    if data.len() < FRAME_HEADER_SIZE + length + 4 {
        return Err(FrameError::TooShort);
    }

    let payload = &data[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + length];
    let crc_bytes = &data[FRAME_HEADER_SIZE + length..FRAME_HEADER_SIZE + length + 4];
    let received_crc = u32::from_be_bytes([crc_bytes[0], crc_bytes[1], crc_bytes[2], crc_bytes[3]]);

    // Recompute CRC over type + length bytes + payload.
    let length_bytes = (length as u16).to_be_bytes();
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&[frame_type]);
    hasher.update(&length_bytes);
    hasher.update(payload);
    let expected_crc = hasher.finalize();

    if received_crc != expected_crc {
        return Err(FrameError::BadCrc);
    }

    Ok(Frame {
        frame_type,
        payload: payload.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        FRAME_TYPE_PROVISION, FRAME_TYPE_NIP46_REQUEST, FRAME_TYPE_NIP46_RESPONSE,
        FRAME_TYPE_ACK, FRAME_TYPE_POLICY_LIST_REQUEST, FRAME_TYPE_POLICY_LIST_RESPONSE,
        FRAME_TYPE_POLICY_REVOKE, FRAME_TYPE_POLICY_UPDATE, MAX_PAYLOAD_SIZE,
    };

    #[test]
    fn roundtrip_provision_frame() {
        let payload = vec![0xAB; 32];
        let bytes = build_frame(FRAME_TYPE_PROVISION, &payload).unwrap();
        let frame = parse_frame(&bytes).unwrap();
        assert_eq!(frame.frame_type, FRAME_TYPE_PROVISION);
        assert_eq!(frame.payload, payload);
    }

    #[test]
    fn roundtrip_nip46_frame() {
        let payload = br#"{"id":"abc","method":"sign_event","params":["{}"]}"#.to_vec();
        let bytes = build_frame(FRAME_TYPE_NIP46_REQUEST, &payload).unwrap();
        let frame = parse_frame(&bytes).unwrap();
        assert_eq!(frame.frame_type, FRAME_TYPE_NIP46_REQUEST);
        assert_eq!(frame.payload, payload);

        // Response direction as well.
        let response_payload = br#"{"id":"abc","result":"sig"}"#.to_vec();
        let bytes = build_frame(FRAME_TYPE_NIP46_RESPONSE, &response_payload).unwrap();
        let frame = parse_frame(&bytes).unwrap();
        assert_eq!(frame.frame_type, FRAME_TYPE_NIP46_RESPONSE);
        assert_eq!(frame.payload, response_payload);
    }

    #[test]
    fn empty_ack_frame() {
        let bytes = build_frame(FRAME_TYPE_ACK, &[]).unwrap();
        // An empty ACK should be exactly FRAME_OVERHEAD bytes.
        assert_eq!(bytes.len(), FRAME_OVERHEAD);
        let frame = parse_frame(&bytes).unwrap();
        assert_eq!(frame.frame_type, FRAME_TYPE_ACK);
        assert!(frame.payload.is_empty());
    }

    #[test]
    fn bad_magic_is_rejected() {
        let mut bytes = build_frame(FRAME_TYPE_ACK, &[]).unwrap();
        bytes[0] = 0xFF; // corrupt first magic byte
        assert_eq!(parse_frame(&bytes), Err(FrameError::BadMagic));
    }

    #[test]
    fn bad_crc_is_rejected() {
        let mut bytes = build_frame(FRAME_TYPE_PROVISION, &[0x01; 16]).unwrap();
        // Flip the last byte of the CRC.
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        assert_eq!(parse_frame(&bytes), Err(FrameError::BadCrc));
    }

    #[test]
    fn too_short_is_rejected() {
        // Fewer bytes than the minimum frame overhead.
        let short = [0x48, 0x57, 0x01, 0x00];
        assert_eq!(parse_frame(&short), Err(FrameError::TooShort));

        // Empty slice.
        assert_eq!(parse_frame(&[]), Err(FrameError::TooShort));
    }

    #[test]
    fn payload_too_large_build() {
        let oversized = vec![0u8; MAX_PAYLOAD_SIZE + 1];
        assert_eq!(
            build_frame(FRAME_TYPE_PROVISION, &oversized),
            Err(FrameError::PayloadTooLarge)
        );
    }

    #[test]
    fn max_payload_roundtrip() {
        let payload = vec![0x5Au8; MAX_PAYLOAD_SIZE];
        let bytes = build_frame(FRAME_TYPE_PROVISION, &payload).unwrap();
        let frame = parse_frame(&bytes).unwrap();
        assert_eq!(frame.frame_type, FRAME_TYPE_PROVISION);
        assert_eq!(frame.payload.len(), MAX_PAYLOAD_SIZE);
        assert_eq!(frame.payload, payload);
    }

    // --- Policy management frame roundtrips ---

    #[test]
    fn roundtrip_policy_list_request() {
        let payload = vec![0x02]; // master_slot = 2
        let bytes = build_frame(FRAME_TYPE_POLICY_LIST_REQUEST, &payload).unwrap();
        let frame = parse_frame(&bytes).unwrap();
        assert_eq!(frame.frame_type, FRAME_TYPE_POLICY_LIST_REQUEST);
        assert_eq!(frame.payload, vec![0x02]);
    }

    #[test]
    fn roundtrip_policy_list_response() {
        // Simulated JSON payload.
        let payload = br#"[{"client_pubkey":"aa","label":"test","auto_approve":true}]"#.to_vec();
        let bytes = build_frame(FRAME_TYPE_POLICY_LIST_RESPONSE, &payload).unwrap();
        let frame = parse_frame(&bytes).unwrap();
        assert_eq!(frame.frame_type, FRAME_TYPE_POLICY_LIST_RESPONSE);
        assert_eq!(frame.payload, payload);
    }

    #[test]
    fn roundtrip_policy_revoke() {
        // 1 byte slot + 64 bytes ASCII hex pubkey.
        let mut payload = vec![0x00]; // slot 0
        payload.extend_from_slice(&[b'a'; 64]);
        let bytes = build_frame(FRAME_TYPE_POLICY_REVOKE, &payload).unwrap();
        let frame = parse_frame(&bytes).unwrap();
        assert_eq!(frame.frame_type, FRAME_TYPE_POLICY_REVOKE);
        assert_eq!(frame.payload.len(), 65);
        assert_eq!(frame.payload[0], 0);
    }

    #[test]
    fn roundtrip_policy_update() {
        // 1 byte slot + JSON payload.
        let mut payload = vec![0x01]; // slot 1
        payload.extend_from_slice(br#"{"client_pubkey":"bb","auto_approve":false}"#);
        let bytes = build_frame(FRAME_TYPE_POLICY_UPDATE, &payload).unwrap();
        let frame = parse_frame(&bytes).unwrap();
        assert_eq!(frame.frame_type, FRAME_TYPE_POLICY_UPDATE);
        assert_eq!(frame.payload[0], 1);
    }
}
