//! Bounded USB-only management contract. No secret-bearing or general decrypt
//! operation, no pairing grants, and no automatic retry after an uncertain reply.
use alloc::string::String;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlotReference {
    pub slot: u8,
    pub npub: String,
    pub mode: u8,
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum WrappedCommand {
    Wrap {
        root: SlotReference,
        target: SlotReference,
    },
    Check {
        root: SlotReference,
        record: String,
        expected_npub: String,
    },
    Restore {
        root: SlotReference,
        record: String,
        expected_npub: String,
        destination: u8,
        label: String,
    },
}

impl WrappedCommand {
    pub fn root(&self) -> &SlotReference {
        match self {
            Self::Wrap { root, .. } | Self::Check { root, .. } | Self::Restore { root, .. } => root,
        }
    }
}

pub fn parse_command(bytes: &[u8]) -> Result<WrappedCommand, &'static str> {
    if bytes.len() > 768 {
        return Err("wrapped request too large");
    }
    let command: WrappedCommand =
        serde_json::from_slice(bytes).map_err(|_| "invalid wrapped request")?;
    let root = command.root();
    if root.slot >= 8 || root.mode > 2 || crate::encoding::decode_npub(&root.npub).is_none() {
        return Err("invalid root reference");
    }
    match &command {
        WrappedCommand::Wrap { target, .. } => {
            if target.mode != 0
                || target.slot >= 8
                || crate::encoding::decode_npub(&target.npub).is_none()
                || target.slot == root.slot
                || target.npub == root.npub
            {
                return Err("choose a separate raw-key slot");
            }
        }
        WrappedCommand::Check {
            record,
            expected_npub,
            ..
        }
        | WrappedCommand::Restore {
            record,
            expected_npub,
            ..
        } => {
            if record.len() != crate::wrapped_nsec::RECORD_LEN
                || crate::encoding::decode_npub(expected_npub).is_none()
            {
                return Err("invalid wrapped file or expected npub");
            }
        }
    }
    if let WrappedCommand::Restore {
        destination, label, ..
    } = &command
    {
        if *destination >= 8
            || label.trim().is_empty()
            || label.len() > 32
            || label.chars().any(char::is_control)
        {
            return Err("invalid empty slot or label");
        }
    }
    Ok(command)
}
