//! Additive fixture parity: nsec-tree/test/fixtures/signet-vault-v1.json.
use heartwood_common::derive::{nsec_to_tree_root, create_tree_root, derive};
#[test]
fn signet_vault_vectors() {
    let secret = nsec_to_tree_root(&[1u8; 32]).unwrap();
    let root = create_tree_root(&secret).unwrap();
    let vectors = [
        ("signet:vault:profiles", 0, "aa98c55baf6bf626ff9396934b3597ca3baa271d10b05ebdf6b83bda0efe0a65", "223236577d0e3f7b1b0d8b424a188f5dda49bdcf6f6bfa06469a65a3f47a80c8"),
        ("signet:vault:profiles", 1, "84abc273187ec53d977b862d459e1a1cf3eddf60a8dc9bddacac3555736bdc59", "0d79736832f6df92ee1b69d4f4e4aed36e7e3559df348d97c0c5496dd2ff0716"),
        ("signet:vault:contacts:owner", 0, "a5388004fa6b2b10f1c4403e9a22eb13aebcd9b04f607d62924a6adcbcc64903", "c13ab922351c243706d79242e671505ad79bfb06c9669c54f00cf4647c15369c"),
        ("signet:vault:contacts:owner", 1, "44c35f5016bc6598e373093da7d6b2315032ee75c01d869380db401dbaaead50", "fdc2ca2862ee9c2d5a2f994671489bee55f0bab9131ce816820893b32d426e4d"),
        ("signet:vault:contacts:dependant-0", 0, "6bc171216cb918b965b32f8836f6384a71e8e006a2ff1ca31a3253e127014564", "bee408e7e92073c159c9971bac83530ab845a12cce7b6890f88459475407ce7a"),
        ("signet:vault:contacts:dependant-0", 1, "700cf9ed6af7d5fa65425cd2a9d6ff598d7745cbe72115a72dc5652b26456269", "d73e342d4d691ed080db5ac7e4faf328f91c6b9f6ba9f420d549d5f7ea028f9a"),
        ("signet:vault:contacts:dependant-1", 0, "0acfaf48210302b74ccf4cbf549ac9baa4a654dfef628a50dba8cb2ea5937d37", "1d6e5eb9e094bac26f9947939b7f0f3cc30acc80525570e00c7006aadf60eb33"),
        ("signet:vault:contacts:dependant-1", 1, "9929537546dfaf3bffa1b9366535ac5154570a3fef9de3e3233b230fe19de653", "c7084d624df94c96dd20c9a38ae22a7b0c308163a2db7d033e399f5f533af60c"),
        ("signet:vault:contacts:bots", 0, "cd7f1bc622298fcb045cca98cdd186dcaf089aae648eb837eaca31a6a960d4d2", "bfac20349045682860d767328d8e897c34ad61c251140b5b15409d3c29aa6aa5"),
        ("signet:vault:contacts:bots", 1, "aed52e8fd5bad0dcbc50bcd9084983141755c7fff10e0c63e3aba2f4adb885e9", "4244c689e2a0cff52dfdfc72a78e9c2767bfbf0f7774a9d30a5c832eeb6079c8"),
        ("signet:vault:credentials", 0, "d4468b61e1296960cc7e4d4df3586fa440fdd536c96af5910be5c59c7fed6bf8", "e2ad51460bab0bc654623e4366cb22d0ba04639f4065dea1c57d9df6cb56a82f"),
        ("signet:vault:credentials", 1, "5e4e22426e67c303042c58c78afca1a4acac9c636b5336f181daa7f11b22603a", "06afa39b59f1d7af8ff8b45b775ea4c08bf16c590ae0f3a96dbd2718fc13fce7"),
        ("signet:vault:settings", 0, "b1dff13164548d08be0ced372a42a076ca6da222e59f74201ba5be5561b2ea82", "f8748ee2e0d9e4ddc82aff23ce1967ba9d0c4ed42f09554115e86c8afe3ca73f"),
        ("signet:vault:settings", 1, "1d44e05181ad0e8a9df729ecbaaa2ce3e084989df5c79d026462cecba28c47d4", "cc82126813d56f6951b03a2650b10efe3e27f3efd24e5e35061df3cb1ea1fef6"),
    ];
    for (purpose, index, private_hex, public_hex) in vectors {
        let child = derive(&root, purpose, index).unwrap();
        let as_hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(as_hex(child.private_key.as_ref()), private_hex, "{purpose}/{index}");
        assert_eq!(as_hex(&child.public_key), public_hex, "{purpose}/{index}");
        assert_eq!(child.index, index);
    }
}
