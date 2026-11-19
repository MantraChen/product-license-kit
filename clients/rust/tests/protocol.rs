use product_license_kit_client::*;
use serde_json::json;

#[test]
fn rejects_ambiguous_json_utf8_and_noncanonical_base64() {
    for input in [
        b"{\"a\":1,\"a\":2}".as_slice(),
        b"{\"nested\":{\"a\":1,\"\\u0061\":1}}",
        b"\xff",
        b"{}true",
    ] {
        assert!(parse_json(input).is_err());
    }
    for value in ["Zg=", "Zh", "+w", "a", ""] {
        assert!(decode_base64url(value).is_err());
    }
    assert_eq!(decode_base64url("Zg").unwrap(), b"f");
}
#[test]
fn refuses_untrusted_endpoints() {
    for url in [
        "http://public.example",
        "https://user:pass@example.com",
        "https://example.com/path",
        "https://example.com?q=1",
        "file:///tmp",
    ] {
        assert!(LicenseClient::new(url).is_err());
    }
    assert!(LicenseClient::new("http://127.0.0.1:10001").is_ok());
}
#[test]
fn challenge_signing_binds_original_bytes_and_full_context() {
    let key = DeviceKey::from_ed25519_seed(&[1u8; 32]).unwrap();
    let account = "00000000-0000-4000-8000-000000000001";
    let id = "00000000-0000-4000-8000-000000000002";
    let fingerprint = Fingerprint {
        schema: "sdk-test-v1".into(),
        digest: "a".repeat(64),
    };
    let challenge=json!(["product-license-kit",1,"enroll",id,account,{"groupId":"desktop","publicKey":key.public_key(),"thumbprint":device_thumbprint(key.public_key()).unwrap(),"fingerprint":fingerprint},base64url(&[0u8;32])]).to_string();
    let signature = key
        .sign_enrollment(&challenge, id, account, "desktop", &fingerprint)
        .unwrap();
    assert_eq!(signature.len(), 86);
    assert!(
        key.sign_enrollment(&challenge, id, account, "other", &fingerprint)
            .is_err()
    );
    assert!(
        key.sign_enrollment(
            &challenge,
            id,
            "00000000-0000-4000-8000-000000000003",
            "desktop",
            &fingerprint
        )
        .is_err()
    );
    assert!(
        key.sign_enrollment(
            &challenge.replace("\"enroll\"", "\"license\""),
            id,
            account,
            "desktop",
            &fingerprint
        )
        .is_err()
    );
    assert!(
        key.sign_enrollment(
            &challenge.replace(
                "\"groupId\":\"desktop\"",
                "\"groupId\":\"desktop\",\"groupId\":\"desktop\""
            ),
            id,
            account,
            "desktop",
            &fingerprint
        )
        .is_err()
    );
}
#[test]
fn hardware_fingerprint_is_product_scoped_and_has_no_shared_fallback() {
    let mut raw = vec![0u8; 34];
    raw[4] = 26;
    raw[8] = 1;
    raw[9] = 24;
    for i in 0..16 {
        raw[16 + i] = (i + 1) as u8;
    }
    let first = fingerprint_from_smbios(&raw, "sample-tool", "sample-v1").unwrap();
    assert_eq!(first.digest.len(), 64);
    assert_ne!(
        first,
        fingerprint_from_smbios(&raw, "sample-addon", "sample-v1").unwrap()
    );
    assert!(fingerprint_from_smbios(&raw[..33], "sample-tool", "sample-v1").is_err());
    raw[16..32].fill(0);
    assert!(fingerprint_from_smbios(&raw, "sample-tool", "sample-v1").is_err());
}
