//! Bounded encoder adapter for physical note handover; no display or transport.
//! `qr-compact` is opt-in. Normal firmware keeps the existing encoder.
#[cfg(feature = "qr-compact")]
pub use forgesworn_qr_embedded::{Workspace, MODULE_BYTES as BUFFER_BYTES};
#[cfg(not(feature = "qr-compact"))]
use qrcodegen_no_heap::{QrCode, QrCodeEcc, Version};
#[cfg(not(feature = "qr-compact"))]
use zeroize::Zeroize;

#[cfg(not(feature = "qr-compact"))]
pub const BUFFER_BYTES: usize = Version::new(8).buffer_len();
#[cfg(not(feature = "qr-compact"))]
pub struct Workspace {
    buffer: [u8; BUFFER_BYTES],
}
#[cfg(not(feature = "qr-compact"))]
impl Workspace {
    pub const fn new() -> Self {
        Self {
            buffer: [0; BUFFER_BYTES],
        }
    }
    pub fn clear(&mut self) {
        self.buffer.zeroize();
    }
}
#[cfg(not(feature = "qr-compact"))]
impl Default for Workspace {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(not(feature = "qr-compact"))]
impl Drop for Workspace {
    fn drop(&mut self) {
        self.clear();
    }
}

#[derive(Debug)]
pub struct EncodeError;

pub struct Code<'a> {
    #[cfg(feature = "qr-compact")]
    inner: forgesworn_qr_embedded::Symbol<'a>,
    #[cfg(not(feature = "qr-compact"))]
    inner: QrCode<'a>,
}
impl Code<'_> {
    pub fn size(&self) -> i32 {
        #[cfg(feature = "qr-compact")]
        {
            self.inner.size() as i32
        }
        #[cfg(not(feature = "qr-compact"))]
        {
            self.inner.size()
        }
    }
    pub fn is_dark(&self, x: i32, y: i32) -> bool {
        #[cfg(feature = "qr-compact")]
        {
            self.inner.is_dark(x as usize, y as usize)
        }
        #[cfg(not(feature = "qr-compact"))]
        {
            self.inner.get_module(x, y)
        }
    }
}

/// Raw OLED payload: exactly 32 bytes, level L and version 2, without a marker.
pub fn raw<'a>(
    secret: &[u8; 32],
    scratch: &mut Workspace,
    output: &'a mut [u8; BUFFER_BYTES],
) -> Result<Code<'a>, EncodeError> {
    #[cfg(feature = "qr-compact")]
    let result = forgesworn_qr_embedded::encode_bytes(
        secret,
        &forgesworn_qr_embedded::Options {
            ecc: forgesworn_qr_embedded::Ecc::L,
            version: Some(2),
            ..Default::default()
        },
        scratch,
        output,
    )
    .map_err(|_| EncodeError);
    #[cfg(not(feature = "qr-compact"))]
    let result = {
        scratch.buffer[..32].copy_from_slice(secret);
        QrCode::encode_binary(
            &mut scratch.buffer,
            32,
            output,
            QrCodeEcc::Low,
            Version::new(2),
            Version::new(2),
            None,
            false,
        )
        .map_err(|_| EncodeError)
    };
    result.map(|inner| Code { inner })
}

/// Colour-panel URL: level L, automatic version up to 8, no ECC boosting or ECI.
pub fn text<'a>(
    url: &str,
    scratch: &mut Workspace,
    output: &'a mut [u8; BUFFER_BYTES],
) -> Result<Code<'a>, EncodeError> {
    #[cfg(feature = "qr-compact")]
    let options = forgesworn_qr_embedded::Options {
        ecc: forgesworn_qr_embedded::Ecc::L,
        ..Default::default()
    };
    #[cfg(all(feature = "qr-compact", not(feature = "qr-optimal")))]
    let result = forgesworn_qr_embedded::encode_simple_text(url, &options, scratch, output)
        .map_err(|_| EncodeError);
    #[cfg(feature = "qr-optimal")]
    let result = {
        let mut planner = forgesworn_qr_embedded::TextPlanner::new();
        forgesworn_qr_embedded::encode_text(url, &options, &mut planner, scratch, output)
            .map_err(|_| EncodeError)
    };
    #[cfg(not(feature = "qr-compact"))]
    let result = QrCode::encode_text(
        url,
        &mut scratch.buffer,
        output,
        QrCodeEcc::Low,
        Version::MIN,
        Version::new(8),
        None,
        false,
    )
    .map_err(|_| EncodeError);
    result.map(|inner| Code { inner })
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroize;

    fn with_text(text: &str) -> i32 {
        let mut scratch = Workspace::new();
        let mut output = [0; BUFFER_BYTES];
        let size = {
            let code = super::text(text, &mut scratch, &mut output).unwrap();
            let size = code.size();
            assert!(code.is_dark(0, 0));
            assert!(!code.is_dark(-1, 0));
            assert!(!code.is_dark(size, 0));
            size
        };
        scratch.clear();
        output.zeroize();
        size
    }

    #[test]
    fn raw_secret_stays_in_v2() {
        let mut scratch = Workspace::new();
        let mut output = [0; BUFFER_BYTES];
        {
            let code = raw(&[0xab; 32], &mut scratch, &mut output).unwrap();
            assert_eq!(code.size(), 25);
        }
        scratch.clear();
        output.zeroize();
    }

    #[test]
    fn actual_note_urls_fit_the_colour_panel() {
        let ordinary = heartwood_common::note_wrap::note_url("mint.example/w", &[0xab; 32], 21_000);
        assert_eq!(with_text(&ordinary), 37);
        let host = format!("{}/w", "m".repeat(62));
        let maximum = heartwood_common::note_wrap::note_url(&host, &[0xab; 32], u64::MAX);
        let side = with_text(&maximum);
        assert!(side <= 49);
        assert!(side * 2 + 16 <= 135);
    }

    #[test]
    fn optimal_planning_is_optional_and_can_reduce_numeric_runs() {
        let numeric = format!(
            "https://mint.example/w?k1={}&amount=18446744073709551615",
            "12".repeat(32)
        );
        assert_eq!(
            with_text(&numeric),
            if cfg!(feature = "qr-optimal") { 33 } else { 41 }
        );
    }

    #[test]
    fn rejects_payloads_above_v8_and_allows_explicit_cleanup() {
        let mut scratch = Workspace::new();
        let mut output = [0x55; BUFFER_BYTES];
        assert!(text(&"x".repeat(193), &mut scratch, &mut output).is_err());
        scratch.clear();
        output.zeroize();
        assert!(output.iter().all(|&b| b == 0));
    }

    #[cfg(feature = "qr-compact")]
    #[test]
    fn compact_symbol_drop_and_rejection_wipe_output() {
        let mut scratch = Workspace::new();
        let mut output = [0; BUFFER_BYTES];
        drop(raw(&[0xab; 32], &mut scratch, &mut output).unwrap());
        assert!(output.iter().all(|&b| b == 0));
        output.fill(0x55);
        assert!(text(&"x".repeat(193), &mut scratch, &mut output).is_err());
        assert!(output.iter().all(|&b| b == 0));
        assert_eq!(core::mem::size_of::<Workspace>() + BUFFER_BYTES, 602);
    }
}
