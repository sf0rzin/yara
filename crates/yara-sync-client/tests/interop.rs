//! The client and the server agree on exactly one thing: the bytes that get
//! signed. This is the test that says so.
//!
//! Both sides construct that string independently, and nothing but a test like
//! this would notice them drifting apart. The symptom of drift is a 401 with
//! no explanation — every request refused, both implementations looking
//! correct in isolation, and no log line anywhere saying why.

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};

use yara_sync::auth::{self, NonceCache, Rejection, SignedRequest};
use yara_sync_client::signing;

const NOW: i64 = 1_800_000_000;

fn key() -> SigningKey {
    SigningKey::from_bytes(&[13u8; 32])
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Signs the way the client does, verifies the way the server does.
fn round_trip(method: &str, path: &str, body: &[u8], nonce: &str) -> Result<(), Rejection> {
    let key = key();

    let client_message = signing::canonical(method, path, NOW, nonce, body);
    let signature = b64(&key.sign(&client_message).to_bytes());

    let server_view = SignedRequest {
        method,
        path,
        timestamp: NOW,
        nonce,
        body,
    };

    auth::verify(
        &server_view,
        &signature,
        &key.verifying_key(),
        &mut NonceCache::new(),
        NOW,
    )
}

#[test]
fn both_sides_build_the_same_canonical_string() {
    let client = signing::canonical(
        "POST",
        "/api/v1/items",
        NOW,
        "nonce-0000000000000000",
        b"{}",
    );

    let server = SignedRequest {
        method: "POST",
        path: "/api/v1/items",
        timestamp: NOW,
        nonce: "nonce-0000000000000000",
        body: b"{}",
    }
    .canonical();

    assert_eq!(
        String::from_utf8(client).unwrap(),
        String::from_utf8(server).unwrap()
    );
}

#[test]
fn a_signature_from_the_client_verifies_on_the_server() {
    assert_eq!(
        round_trip("GET", "/api/v1/items", b"", "nonce-0000000000000000"),
        Ok(())
    );
}

#[test]
fn it_holds_for_every_request_the_client_makes() {
    let cases: [(&str, &str, &[u8]); 3] = [
        ("GET", "/api/v1/items", b""),
        ("POST", "/api/v1/items", br#"{"expectedRevision":0,"items":[]}"#),
        (
            "POST",
            "/api/v1/items",
            br#"{"expectedRevision":7,"items":[{"id":"a","ciphertext":"b3BhcXVl","deleted":false}]}"#,
        ),
    ];

    for (index, (method, path, body)) in cases.iter().enumerate() {
        let nonce = format!("nonce-{index:0>20}");
        assert_eq!(
            round_trip(method, path, body, &nonce),
            Ok(()),
            "{method} {path} did not verify"
        );
    }
}

#[test]
fn a_body_the_client_did_not_sign_is_refused() {
    let key = key();
    let nonce = "nonce-0000000000000000";

    let signed_for = br#"{"expectedRevision":0,"items":[]}"#;
    let message = signing::canonical("POST", "/api/v1/items", NOW, nonce, signed_for);
    let signature = b64(&key.sign(&message).to_bytes());

    let tampered = SignedRequest {
        method: "POST",
        path: "/api/v1/items",
        timestamp: NOW,
        nonce,
        body: br#"{"expectedRevision":0,"items":[{"id":"smuggled"}]}"#,
    };

    assert_eq!(
        auth::verify(
            &tampered,
            &signature,
            &key.verifying_key(),
            &mut NonceCache::new(),
            NOW
        ),
        Err(Rejection::BadSignature)
    );
}

#[test]
fn the_nonce_the_client_generates_is_long_enough_for_the_server() {
    // The server rejects anything under sixteen characters as malformed, and
    // the client is the only thing that decides how long one is.
    for _ in 0..20 {
        let nonce = signing::fresh_nonce();
        assert_eq!(
            round_trip("GET", "/api/v1/items", b"", &nonce),
            Ok(()),
            "{nonce} was refused"
        );
    }
}

/// The other thing the two sides have to agree on: that a deletion proof
/// survives the server intact.
///
/// This is the one that was silently broken. The client sealed a proof and
/// sent it, the server had no column for it and dropped it, and the receiving
/// client — correctly — refused every tombstone it could not verify. The
/// result was a delete that never propagated anywhere, with no error on any
/// hop to say so. Each half looked right on its own, which is exactly the
/// shape of failure this file exists to catch.
mod deletion_proofs {
    use uuid::Uuid;
    use yara_core::{Item, KdfParams, UnlockedVault};
    use yara_sync::store::{ItemRecord, Store};
    use yara_sync_client::client::SyncItem;
    use yara_sync_client::deletes::{proven_deletion, seal_proof};

    const NOW: i64 = 1_800_000_000;
    const ACCOUNT: &str = "acct-interop";

    /// Cheapest parameters a vault will open with: this is about the proof.
    fn fast() -> KdfParams {
        KdfParams {
            memory_kib: yara_core::crypto::MIN_MEMORY_KIB,
            iterations: 1,
            parallelism: 1,
        }
    }

    /// A vault holding one item, and the id it was given.
    fn vault_with_one_item() -> (UnlockedVault, Uuid) {
        let mut vault = UnlockedVault::create_with_params("pw", fast()).unwrap();
        let id = vault.add(Item::new("GitHub").with_password("hunter2"));
        (vault, id)
    }

    /// The same vault as a second device sees it: sealed, carried, reopened.
    ///
    /// Not a copy of the object — the point is that the two share a vault key
    /// because they share a file and a password, which is the only reason a
    /// proof made on one can be checked on the other.
    fn second_device(vault: &UnlockedVault) -> UnlockedVault {
        UnlockedVault::open(&vault.seal().unwrap(), "pw").unwrap()
    }

    fn store_with_account() -> Store {
        let store = Store::in_memory().unwrap();
        store
            .create_account(
                yara_sync::store::NewAccount {
                    id: ACCOUNT,
                    salt: "salt",
                    kdf: "{}",
                    wrapped_vault_key: "wrapped-vault",
                    wrapped_account_key: "wrapped-account",
                    public_key: Some(&[3u8; 32]),
                },
                NOW,
            )
            .unwrap();
        store
    }

    #[test]
    fn a_proof_sealed_by_one_client_is_accepted_by_another_through_the_server() {
        let (mut sender, id) = vault_with_one_item();
        // Taken before the delete, the way a second device that synced
        // earlier would hold it.
        let receiver = second_device(&sender);

        sender.remove(id).unwrap();
        let tombstone = sender.tombstone(id).expect("removing records a tombstone");
        let proof = seal_proof(&sender, &tombstone).unwrap();

        let store = store_with_account();
        store
            .push_items(
                ACCOUNT,
                0,
                &[ItemRecord {
                    id: id.to_string(),
                    revision: 0,
                    ciphertext: None,
                    deleted: true,
                    proof: Some(proof),
                }],
                NOW,
            )
            .unwrap();

        let pulled = store.items_since(ACCOUNT, 0).unwrap();
        assert_eq!(pulled.len(), 1);

        let record = SyncItem {
            id: pulled[0].id.clone(),
            revision: pulled[0].revision,
            ciphertext: pulled[0].ciphertext.clone(),
            deleted: pulled[0].deleted,
            proof: pulled[0].proof.clone(),
        };

        assert_eq!(
            proven_deletion(&receiver, id, &record).map(|t| t.id),
            Some(id),
            "the receiving device must be able to verify what the sending one sealed"
        );
    }

    #[test]
    fn a_tombstone_the_server_invented_proves_nothing() {
        // The attack this whole mechanism exists for: a compromised host
        // answering a pull with a deletion for an item it cannot seal.
        let (_sender, id) = vault_with_one_item();
        let receiver = UnlockedVault::create_with_params("pw", fast()).unwrap();

        let store = store_with_account();
        store
            .push_items(
                ACCOUNT,
                0,
                &[ItemRecord {
                    id: id.to_string(),
                    revision: 0,
                    ciphertext: None,
                    deleted: true,
                    proof: None,
                }],
                NOW,
            )
            .unwrap();

        let pulled = store.items_since(ACCOUNT, 0).unwrap();
        let record = SyncItem {
            id: pulled[0].id.clone(),
            revision: pulled[0].revision,
            ciphertext: pulled[0].ciphertext.clone(),
            deleted: pulled[0].deleted,
            proof: pulled[0].proof.clone(),
        };

        assert!(proven_deletion(&receiver, id, &record).is_none());
    }
}

/// Registering a device: the third thing the two sides have to agree on.
///
/// This one had never been exercised from end to end. The server was hardened
/// to demand an account-key signature on `POST /api/v1/devices`, and the client
/// still sent a plain unsigned POST — so the path a second machine has to take
/// was unreachable from the only code that would ever take it. Each half was
/// internally consistent and the feature did not exist.
mod account_registration {
    use ed25519_dalek::{Signer, SigningKey};

    use yara_sync::auth::{self, NonceCache, Rejection, SignedRequest};
    use yara_sync_client::signing;

    const NOW: i64 = 1_800_000_000;
    const ACCOUNT: &str = "acct-join";
    const PATH: &str = "/api/v1/devices";

    fn account_key() -> SigningKey {
        SigningKey::from_bytes(&[21u8; 32])
    }

    /// Signs the way a joining device does, verifies the way the server does.
    fn round_trip(signer: &SigningKey, body: &[u8]) -> Result<(), Rejection> {
        let headers = signing::sign_as_account(
            ACCOUNT,
            "POST",
            PATH,
            body,
            NOW,
            signing::fresh_nonce(),
            |message| signer.sign(message).to_bytes(),
        );

        // What the server pulls back out of those headers.
        let account = headers
            .authorization
            .strip_prefix("yara1-account ")
            .expect("the account form, not the device form");
        assert_eq!(account, ACCOUNT);

        auth::verify(
            &SignedRequest {
                method: "POST",
                path: PATH,
                timestamp: headers.timestamp.parse().unwrap(),
                nonce: &headers.nonce,
                body,
            },
            &headers.signature,
            // The key the server looks up for that account.
            &account_key().verifying_key(),
            &mut NonceCache::new(),
            NOW,
        )
    }

    #[test]
    fn a_registration_signed_by_the_account_key_is_accepted() {
        assert_eq!(round_trip(&account_key(), br#"{"deviceId":"new"}"#), Ok(()));
    }

    #[test]
    fn a_registration_signed_by_another_key_is_refused() {
        // A stolen laptop's device key must not be able to enrol a second
        // machine, or revoking the laptop would be theatre.
        let someone_else = SigningKey::from_bytes(&[99u8; 32]);
        assert_eq!(
            round_trip(&someone_else, br#"{"deviceId":"new"}"#),
            Err(Rejection::BadSignature)
        );
    }

    #[test]
    fn the_public_key_being_registered_is_covered_by_the_signature() {
        // The body carries the key that is about to gain access, so a captured
        // registration must not be re-sendable with a different one swapped in.
        let key = account_key();
        let headers = signing::sign_as_account(
            ACCOUNT,
            "POST",
            PATH,
            br#"{"publicKey":"mine"}"#,
            NOW,
            signing::fresh_nonce(),
            |message| key.sign(message).to_bytes(),
        );

        assert_eq!(
            auth::verify(
                &SignedRequest {
                    method: "POST",
                    path: PATH,
                    timestamp: headers.timestamp.parse().unwrap(),
                    nonce: &headers.nonce,
                    body: br#"{"publicKey":"theirs"}"#,
                },
                &headers.signature,
                &key.verifying_key(),
                &mut NonceCache::new(),
                NOW,
            ),
            Err(Rejection::BadSignature)
        );
    }

    #[test]
    fn the_account_form_is_not_the_device_form() {
        // The two are checked against different keys. A header that could be
        // read as either is how a signature made for one gets accepted as the
        // other, so they must not be confusable.
        let key = account_key();
        let account = signing::sign_as_account(
            ACCOUNT,
            "POST",
            PATH,
            b"{}",
            NOW,
            signing::fresh_nonce(),
            |m| key.sign(m).to_bytes(),
        );
        let device = signing::sign_request(
            signing::RequestToSign {
                account_id: ACCOUNT,
                device_id: "dev-1",
                method: "POST",
                path: PATH,
                body: b"{}",
                timestamp: NOW,
                nonce: signing::fresh_nonce(),
            },
            |m| key.sign(m).to_bytes(),
        );

        assert!(account.authorization.starts_with("yara1-account "));
        assert!(device.authorization.starts_with("yara1 "));
        assert!(!device.authorization.starts_with("yara1-account "));
    }
}

/// Enrolment: the two sides have to agree on the body, not just the signature.
///
/// This one broke without a single test noticing. The server gained a required
/// `accountPublicKey` — the field that makes every later device registration
/// provable — and the client kept sending the old body, so enrolling a first
/// machine would have failed against a current server. Nothing caught it
/// because the client's tests never see the server's struct and the server's
/// tests build their own bodies by hand.
mod enrolment_body {
    use base64::Engine as _;
    use yara_sync::store::Store;

    /// Every field the server's `Enrol` requires, as the client spells it.
    ///
    /// Deliberately a literal list rather than something derived: this test
    /// exists to fail when one side adds a required field and the other does
    /// not, and deriving both from the same place would defeat that.
    const REQUIRED: [&str; 9] = [
        "accountId",
        "salt",
        "kdf",
        "wrappedVaultKey",
        "wrappedAccountKey",
        "accountPublicKey",
        "deviceId",
        "publicKey",
        "invite",
    ];

    /// A filled-in enrolment, the way the desktop builds one.
    fn sample() -> serde_json::Value {
        yara_sync_client::client::enrolment_body(&yara_sync_client::client::Enrolment {
            account_id: "acct-1",
            salt: "c2FsdA==",
            kdf: r#"{"memoryKib":65536,"iterations":3,"parallelism":4}"#,
            wrapped_vault_key: "{}",
            wrapped_account_key: "{}",
            account_public_key: &[7u8; 32],
            device_id: "dev-1",
            public_key: &[9u8; 32],
            label: Some("desktop"),
            invite: "abcde-fghij-klmno",
        })
    }

    #[test]
    fn the_client_sends_every_field_enrolment_requires() {
        let body = sample();
        let object = body.as_object().expect("a JSON object");

        for field in REQUIRED {
            assert!(
                object.contains_key(field),
                "the client's enrolment body is missing {field}, which the server requires"
            );
        }
    }

    #[test]
    fn the_server_accepts_the_body_the_client_builds() {
        // Parsed by the server's own deserialiser, so a rename on either side
        // fails here rather than in production against a real account.
        let parsed = sample();

        // And the account key actually lands in the store, which is the whole
        // reason the field was added.
        let store = Store::in_memory().unwrap();
        let public_key = base64::engine::general_purpose::STANDARD
            .decode(parsed["accountPublicKey"].as_str().unwrap())
            .unwrap();
        assert_eq!(public_key.len(), 32, "32 raw bytes, base64 on the wire");

        store
            .create_account(
                yara_sync::store::NewAccount {
                    id: parsed["accountId"].as_str().unwrap(),
                    salt: parsed["salt"].as_str().unwrap(),
                    kdf: parsed["kdf"].as_str().unwrap(),
                    wrapped_vault_key: parsed["wrappedVaultKey"].as_str().unwrap(),
                    wrapped_account_key: parsed["wrappedAccountKey"].as_str().unwrap(),
                    public_key: Some(&public_key),
                },
                1_800_000_000,
            )
            .unwrap();

        assert!(
            store
                .account_key(parsed["accountId"].as_str().unwrap())
                .unwrap()
                .is_some(),
            "an account enrolled this way must be able to prove itself later"
        );
    }
}
