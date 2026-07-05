//! Human-friendly names for common Nostr event kinds, so the signer can show
//! "App Data" on a sign-request screen instead of a bare "Kind 30078" that
//! means nothing to the person holding the button. Mirrors Sapwood's kindLabel
//! (sapwood/src/lib/kinds.ts) — keep the two lists in step.

/// A short human name for a Nostr event kind, or `None` when it is not one we
/// recognise (the caller then falls back to showing the number).
pub fn kind_label(kind: u64) -> Option<&'static str> {
    Some(match kind {
        0 => "Profile",
        1 => "Note",
        3 => "Contacts",
        4 => "DM (NIP-04)",
        5 => "Delete",
        6 => "Repost",
        7 => "Reaction",
        1059 => "Gift Wrap",
        1063 => "File Metadata",
        1984 => "Report",
        9734 => "Zap Request",
        9735 => "Zap Receipt",
        10000 => "Mute List",
        10002 => "Relay List",
        13194 => "Wallet Info",
        22242 => "Relay Auth",
        23194 => "Wallet Request",
        23195 => "Wallet Response",
        24133 => "NIP-46",
        27235 => "HTTP Auth",
        30000 => "People List",
        30023 => "Article",
        30078 => "App Data",
        30311 => "Live Event",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_kinds_get_friendly_names() {
        assert_eq!(kind_label(0), Some("Profile"));
        assert_eq!(kind_label(30078), Some("App Data"));
        assert_eq!(kind_label(1), Some("Note"));
    }

    #[test]
    fn unknown_kinds_return_none() {
        assert_eq!(kind_label(999999), None);
    }
}
