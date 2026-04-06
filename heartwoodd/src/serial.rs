// heartwoodd/src/serial.rs
//
// Raw POSIX serial wrapper -- thin newtype around a file descriptor.
// Uses termios directly instead of the `serialport` crate to avoid
// DTR toggling on open (which reboots the ESP32-S3 via USB-CDC).

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd};

use nix::sys::termios;

/// Thin wrapper around a raw file descriptor for serial I/O.
/// Uses POSIX termios instead of the `serialport` crate to avoid
/// DTR toggling on open (which reboots the ESP32-S3 via USB-CDC).
pub struct RawSerial {
    pub file: File,
}

impl RawSerial {
    /// Open a serial port with raw POSIX I/O.
    ///
    /// Sets CLOCAL (ignore modem control lines) so DTR is never asserted,
    /// configures raw mode at the given baud rate, and explicitly clears
    /// DTR/RTS via ioctl.
    pub fn open(path: &str, baud: u32) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;

        let raw_fd = file.as_raw_fd();
        let fd = unsafe { BorrowedFd::borrow_raw(raw_fd) };
        let mut cfg = termios::tcgetattr(fd)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        termios::cfmakeraw(&mut cfg);

        // Map baud rate
        let baud_rate = match baud {
            9600 => termios::BaudRate::B9600,
            19200 => termios::BaudRate::B19200,
            38400 => termios::BaudRate::B38400,
            57600 => termios::BaudRate::B57600,
            115200 => termios::BaudRate::B115200,
            230400 => termios::BaudRate::B230400,
            _ => termios::BaudRate::B115200,
        };
        termios::cfsetspeed(&mut cfg, baud_rate)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        // Disable hardware flow control
        cfg.control_flags.remove(termios::ControlFlags::CRTSCTS);
        // Enable receiver, local mode (ignore modem control = no DTR)
        cfg.control_flags.insert(termios::ControlFlags::CREAD);
        cfg.control_flags.insert(termios::ControlFlags::CLOCAL);
        // Disable HUPCL (don't drop DTR on close)
        cfg.control_flags.remove(termios::ControlFlags::HUPCL);

        // VMIN=0, VTIME=1 -- 100ms read timeout (non-blocking with short poll).
        // VMIN=1/VTIME=0 would block until data arrives but breaks the serial
        // drain at startup and the log poller. The 100ms poll is acceptable --
        // the real latency fix was removing the 2s OLED delay in the firmware.
        cfg.control_chars[termios::SpecialCharacterIndices::VMIN as usize] = 0;
        cfg.control_chars[termios::SpecialCharacterIndices::VTIME as usize] = 1;

        termios::tcsetattr(fd, termios::SetArg::TCSANOW, &cfg)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        // Clear DTR and RTS explicitly via ioctl
        unsafe {
            let mut bits: libc::c_int = libc::TIOCM_DTR | libc::TIOCM_RTS;
            libc::ioctl(raw_fd, libc::TIOCMBIC as _, &mut bits);
        }

        Ok(Self { file })
    }
}

impl Read for RawSerial {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buf)
    }
}

impl Write for RawSerial {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}
