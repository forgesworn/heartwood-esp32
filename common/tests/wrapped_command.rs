#![cfg(feature = "wrapped-nsec")]
use heartwood_common::wrapped_command::parse_command;

#[test]
fn bounded_strict_commands_reject_ambiguous_authority() {
    let valid = br#"{"op":"wrap","root":{"slot":0,"npub":"npub1root","mode":1},"target":{"slot":1,"npub":"npub1target","mode":0}}"#;
    let root_npub = heartwood_common::encoding::encode_npub(&[0x11; 32]);
    let target_npub = heartwood_common::encoding::encode_npub(&[0x22; 32]);
    let valid = String::from_utf8(valid.to_vec())
        .unwrap()
        .replace("npub1root", &root_npub)
        .replace("npub1target", &target_npub);
    assert!(parse_command(valid.as_bytes()).is_ok());
    for bad in [
        valid.as_bytes().to_vec().into_iter().chain(b" ".repeat(1024)).collect(),
        br#"{"op":"decrypt","root":{"slot":0,"npub":"npub1root","mode":1}}"#.to_vec(),
        br#"{"op":"wrap","root":{"slot":0,"npub":"npub1root","mode":1,"extra":true},"target":{"slot":1,"npub":"npub1target","mode":0}}"#.to_vec(),
        br#"{"op":"wrap","root":{"slot":0,"npub":"npub1root","mode":1},"target":{"slot":1,"npub":"npub1target","mode":0},"secret":"host-key"}"#.to_vec(),
    ] {
        let bad = String::from_utf8(bad).unwrap()
            .replace("npub1root", &root_npub)
            .replace("npub1target", &target_npub);
        assert!(parse_command(bad.as_bytes()).is_err());
    }
}
