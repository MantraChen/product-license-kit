#![cfg(windows)]
use product_license_kit_client::{windows::*, *};
use std::fs;

#[test]
fn protected_identity_is_stable_isolated_and_never_replaced_after_corruption() {
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).unwrap();
    let root = std::env::temp_dir().join(format!("plk-rust-sdk-{}", base64url(&nonce)));
    let account = "00000000-0000-4000-8000-000000000001";
    let run = || -> Result<()> {
        let first = load_or_create_key("sample-tool", account, Some(&root), true)?;
        assert_eq!(
            first.public_key(),
            load_or_create_key("sample-tool", account, Some(&root), false)?.public_key()
        );
        let other = load_or_create_key("sample-addon", account, Some(&root), true)?;
        assert_ne!(first.public_key(), other.public_key());
        let racers: Vec<_> = (0..8)
            .map(|_| {
                let root = root.clone();
                std::thread::spawn(move || {
                    load_or_create_key("race", account, Some(&root), true)
                        .unwrap()
                        .public_key()
                        .to_owned()
                })
            })
            .collect();
        let keys: Vec<_> = racers
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert!(keys.iter().all(|key| key == &keys[0]));
        let path = root
            .join(sha256(b"sample-tool"))
            .join(account)
            .join("device.key");
        let original = fs::read(&path).unwrap();
        fs::write(&path, [1, 2, 3]).unwrap();
        assert!(load_or_create_key("sample-tool", account, Some(&root), false).is_err());
        assert_eq!(fs::read(&path).unwrap(), [1, 2, 3]);
        fs::write(
            root.join(sha256(b"sample-addon"))
                .join(account)
                .join("device.key"),
            original,
        )
        .unwrap();
        assert!(load_or_create_key("sample-addon", account, Some(&root), false).is_err());
        fs::remove_file(&path).unwrap();
        assert!(load_or_create_key("sample-tool", account, Some(&root), false).is_err());
        assert!(!path.exists());
        Ok(())
    };
    let result = run();
    let exact = fs::canonicalize(&root).unwrap();
    let parent = fs::canonicalize(std::env::temp_dir()).unwrap();
    assert_eq!(exact.parent(), Some(parent.as_path()));
    assert!(
        exact
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("plk-rust-sdk-")
    );
    fs::remove_dir_all(exact).unwrap();
    result.unwrap();
}
