// firmware/src/serial.rs
//
// Board-specific serial transport abstraction. Both Heltec V3 and V4 expose a
// USB-C port to the host, but they wire it very differently:
//
//   - **V4** routes USB-C directly to the ESP32-S3 native USB pins (GPIO19
//     D-, GPIO20 D+), driving the chip's USB-Serial-JTAG peripheral via
//     `UsbSerialDriver`.
//
//   - **V3** routes USB-C through a CP2102 USB-to-UART bridge chip to the
//     ESP32-S3's UART0 (GPIO43 TX / GPIO44 RX), which we drive with
//     `UartDriver`.
//
// `SerialPort` is a thin wrapper that unifies these two at compile time. The
// variant is selected by the `heltec-v3` or `heltec-v4` cargo feature.
// Exactly one feature is always active (enforced by a `compile_error!` guard
// in `main.rs`), so there is no runtime branching and no vtable cost -- the
// compiler strips the inactive backend entirely.
//
// The API surface mirrors what the frame protocol actually uses: a timeout
// read and a blocking write. Both driver types have matching `read` shapes
// but differ on `write` (USB takes a `delay` parameter, UART does not), which
// is why a bare type alias would not work here.

use esp_idf_svc::sys::EspError;

#[cfg(any(feature = "heltec-v4", feature = "c6"))]
use esp_idf_hal::usb_serial::UsbSerialDriver;

#[cfg(any(feature = "heltec-v3", feature = "tdisplay"))]
use esp_idf_hal::uart::UartDriver;

/// Board-specific serial transport to the host.
///
/// Wraps either the native USB-Serial-JTAG peripheral (V4) or UART0 via the
/// on-board CP2102 bridge (V3). Which backend is compiled in is determined by
/// the active cargo feature.
pub struct SerialPort<'a> {
    #[cfg(any(feature = "heltec-v4", feature = "c6"))]
    inner: UsbSerialDriver<'a>,
    #[cfg(any(feature = "heltec-v3", feature = "tdisplay"))]
    inner: UartDriver<'a>,
}

impl<'a> SerialPort<'a> {
    /// Wrap a native `UsbSerialDriver` (Heltec V4).
    #[cfg(any(feature = "heltec-v4", feature = "c6"))]
    pub fn from_usb(inner: UsbSerialDriver<'a>) -> Self {
        Self { inner }
    }

    /// Wrap a native `UartDriver` on UART0 (Heltec V3, CP2102 bridge).
    #[cfg(any(feature = "heltec-v3", feature = "tdisplay"))]
    pub fn from_uart(inner: UartDriver<'a>) -> Self {
        Self { inner }
    }

    /// Read up to `buf.len()` bytes from the host, blocking up to
    /// `timeout_ms` ticks. Note that the two backends signal "nothing
    /// received" differently: the V4 `UsbSerialDriver::read` returns
    /// `Ok(0)` on timeout, while the V3 `UartDriver::read` returns
    /// `Err(EspError::Timeout)`. Callers must handle BOTH. The existing
    /// frame reader uses `match { Ok(n) if n > 0 => ..., _ => retry }`
    /// which covers both cases correctly.
    ///
    /// Both driver types have identical parameter shapes -- `(buf,
    /// timeout) -> Result<usize, EspError>` -- so the delegation is a
    /// straight passthrough.
    pub fn read(&mut self, buf: &mut [u8], timeout_ms: u32) -> Result<usize, EspError> {
        self.inner.read(buf, timeout_ms)
    }

    /// Write `buf`, blocking at most `timeout` (same tick unit as `read`).
    /// Returns `Ok(0)` when the driver accepted nothing within the window.
    ///
    /// Deliberately no unbounded variant: on the native USB-Serial-JTAG
    /// boards the TX buffer only drains while a host is reading, so a
    /// suspended or vanished host leaves it full and a `BLOCK` write parks
    /// the single signing thread forever — with the task watchdog disabled,
    /// that is a wedge only a power-cycle clears. The UART boards drain at
    /// baud rate through the CP2102 regardless of the host, so their plain
    /// blocking write is already bounded in practice (`UartDriver::write`
    /// takes no delay parameter).
    pub fn write_bounded(&mut self, buf: &[u8], timeout: u32) -> Result<usize, EspError> {
        #[cfg(any(feature = "heltec-v4", feature = "c6"))]
        {
            self.inner.write(buf, timeout)
        }
        #[cfg(any(feature = "heltec-v3", feature = "tdisplay"))]
        {
            let _ = timeout;
            self.inner.write(buf)
        }
    }
}
