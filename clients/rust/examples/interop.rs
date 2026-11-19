use base64::{Engine, engine::general_purpose::STANDARD};
use product_license_kit_client::*;
use rsa::pkcs8::DecodePrivateKey;
use serde_json::{Value, json};
use std::fs;

fn text<'a>(value: &'a Value, name: &str) -> &'a str {
    value[name].as_str().expect("FIXTURE_FIELD")
}
fn command_key() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).unwrap();
    base64url(&bytes)
}
fn rejected(result: Result<Value>, code: &str, status: Option<u16>) {
    let error = result.expect_err("ACCEPTED_INVALID_INPUT");
    assert_eq!(error.code, code);
    if let Some(status) = status {
        assert_eq!(error.status, Some(status));
    }
}
fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(args.len(), 3);
    assert_eq!(args[1], "--interop");
    let config = parse_json(&fs::read(&args[2])?)?;
    let client = LicenseClient::new(text(&config, "origin"))?;
    let trusted = text(&config, "publicKey");
    let admin = text(&config, "adminToken");
    let now = config["now"].as_i64().unwrap() / 1000;
    let mut checks = 0;
    #[cfg(windows)]
    let (mut stored, created_protected_key) = {
        let root = std::path::Path::new(text(&config, "storageRoot"));
        let key = windows::load_or_create_key(
            "sdk-interoperability",
            text(&config, "storageAccountId"),
            Some(root),
            false,
        )?;
        assert_eq!(key.public_key(), text(&config, "protectedPublicKey"));
        checks += 1;
        let fingerprint = windows::read_fingerprint("sdk-interoperability", "sdk-hwid-v1")?;
        assert_eq!(fingerprint.digest, text(&config["fingerprint"], "digest"));
        checks += 1;
        let created = windows::load_or_create_key(
            "sdk-interoperability",
            text(&config, "rustStorageAccountId"),
            Some(root),
            true,
        )?;
        checks += 1;
        (Some(key), created.public_key().to_owned())
    };
    #[cfg(not(windows))]
    let (mut stored, created_protected_key): (Option<DeviceKey>, String) = (None, String::new());
    for subject in config["cases"].as_array().unwrap() {
        let key = if subject["algorithm"] == "Ed25519" {
            match stored.take() {
                Some(key) => key,
                None => DeviceKey::generate_ed25519()?,
            }
        } else {
            DeviceKey::from_rsa(rsa::PrivateKey::from_pkcs8_pem(text(
                subject,
                "privateKey",
            ))?)?
        };
        let session = client.request(
            "/v1/auth/register",
            Some(&json!({"ticket":text(subject,"ticket"),"proof":text(subject,"proof")})),
            None,
            None,
        )?;
        let account_id = text(&session, "accountId");
        let access = text(&session, "accessToken");
        let order = client.request(
            "/v1/orders",
            Some(&json!({"offerId":"buy-tool-1"})),
            Some(access),
            Some(&command_key()),
        )?;
        client.request(&format!("/v1/admin/orders/{}/confirm",text(&order,"orderId")),Some(&json!({"method":"manual-bank","reference":command_key(),"amount":5000,"currency":"CNY"})),Some(admin),None)?;
        let fingerprint = Fingerprint {
            schema: "sdk-test-v1".into(),
            digest: "a".repeat(64),
        };
        let enrollment=client.request("/v1/devices/challenges",Some(&json!({"groupId":"desktop","publicKey":key.public_key(),"fingerprint":fingerprint})),Some(access),None)?;
        let signature = key.sign_enrollment(
            text(&enrollment, "message"),
            text(&enrollment, "challengeId"),
            account_id,
            "desktop",
            &fingerprint,
        )?;
        let activate = json!({"challengeId":text(&enrollment,"challengeId"),"signature":signature});
        let activate_key = command_key();
        let binding = client.request(
            "/v1/devices/activate",
            Some(&activate),
            Some(access),
            Some(&activate_key),
        )?;
        assert_eq!(
            binding,
            client.request(
                "/v1/devices/activate",
                Some(&activate),
                Some(access),
                Some(&activate_key)
            )?
        );
        checks += 1;
        let scope = LicenseScope {
            issuer: "test-issuer".into(),
            product_id: "sample-tool".into(),
            edition_id: "tool-1".into(),
            account_id: account_id.into(),
            device_id: text(&binding, "deviceId").into(),
            device_public_key: key.public_key().into(),
            fingerprint,
            channel: "stable".into(),
            generation: binding["generation"].as_i64(),
        };
        let challenge=client.request("/v1/licenses/challenges",Some(&json!({"deviceId":scope.device_id,"editionId":scope.edition_id,"channel":scope.channel})),None,None)?;
        let signature = key.sign_license(
            text(&challenge, "message"),
            text(&challenge, "challengeId"),
            &scope,
        )?;
        let issue = json!({"challengeId":text(&challenge,"challengeId"),"signature":signature});
        let issued = client.request("/v1/licenses/issue", Some(&issue), None, None)?;
        let token = text(&issued, "token");
        verify_license(token, trusted, &scope, now)?;
        checks += 1;
        let invalid = vec![
            LicenseScope {
                issuer: "other".into(),
                ..scope.clone()
            },
            LicenseScope {
                product_id: "other".into(),
                ..scope.clone()
            },
            LicenseScope {
                edition_id: "other".into(),
                ..scope.clone()
            },
            LicenseScope {
                account_id: "other".into(),
                ..scope.clone()
            },
            LicenseScope {
                device_id: "other".into(),
                ..scope.clone()
            },
            LicenseScope {
                channel: "beta".into(),
                ..scope.clone()
            },
            LicenseScope {
                generation: Some(scope.generation.unwrap() + 1),
                ..scope.clone()
            },
            LicenseScope {
                fingerprint: Fingerprint {
                    schema: scope.fingerprint.schema.clone(),
                    digest: "b".repeat(64),
                },
                ..scope.clone()
            },
        ];
        for wrong in invalid {
            assert!(verify_license(token, trusted, &wrong, now).is_err());
            checks += 1;
        }
        assert!(verify_license(token, trusted, &scope, now + 960).is_err());
        checks += 1;
        rejected(
            client.request("/v1/licenses/issue", Some(&issue), None, None),
            "API_REQUEST_FAILED",
            Some(401),
        );
        checks += 1;
        let vectors = client.request(
            "/v1/test/vectors",
            Some(&json!({"token":token})),
            Some(access),
            None,
        )?;
        for vector in vectors.as_array().unwrap() {
            assert!(verify_license(text(vector, "token"), trusted, &scope, now).is_err());
            checks += 1;
        }
        let artifact = STANDARD.decode(text(&config, "artifact"))?;
        let distribution = client.request(
            "/v1/admin/distributions",
            Some(&json!({"accountId":account_id,"editionId":"tool-1","releaseId":"sdk-test"})),
            Some(admin),
            Some(&command_key()),
        )?;
        let distribution_id = text(&distribution, "distributionId");
        let finalized = client.request(
            &format!("/v1/admin/distributions/{distribution_id}/finalize"),
            Some(&json!({"sha256":sha256(&artifact)})),
            Some(admin),
            None,
        )?;
        let manifest = text(&finalized, "manifest");
        verify_distribution(
            manifest,
            trusted,
            &artifact,
            distribution_id,
            "tool-1",
            "sdk-test",
        )?;
        checks += 1;
        assert!(
            verify_distribution(
                manifest,
                trusted,
                &[1],
                distribution_id,
                "tool-1",
                "sdk-test"
            )
            .is_err()
        );
        checks += 1;
        assert!(
            verify_distribution(
                manifest,
                trusted,
                &artifact,
                distribution_id,
                "tool-1",
                "other"
            )
            .is_err()
        );
        checks += 1;
        client.request("/v1/auth/logout", Some(&json!({})), Some(access), None)?;
        rejected(
            client.request("/v1/me", None, Some(access), None),
            "API_REQUEST_FAILED",
            Some(401),
        );
        checks += 1;
    }
    for path in [
        "https://other.example/v1/me",
        "//other.example/v1/me",
        "/v1/../health",
        "/v1/%2e%2e/health",
        "/v1/\\other",
        "/v1/me#fragment",
        "/v1/me\r\n",
    ] {
        rejected(
            client.request(path, None, None, None),
            "INVALID_API_PATH",
            None,
        );
        checks += 1;
    }
    rejected(
        client.request("/v1/test/redirect", None, Some(admin), None),
        "API_REQUEST_FAILED",
        Some(302),
    );
    checks += 1;
    rejected(
        client.request("/v1/test/oversized", None, None, None),
        "RESPONSE_TOO_LARGE",
        None,
    );
    checks += 1;
    rejected(
        client.request("/v1/test/chunked", None, None, None),
        "RESPONSE_TOO_LARGE",
        None,
    );
    checks += 1;
    println!(
        "{}",
        json!({"language":"rust","cases":config["cases"].as_array().unwrap().len(),"checks":checks,"createdProtectedKey":created_protected_key})
    );
    Ok(())
}
