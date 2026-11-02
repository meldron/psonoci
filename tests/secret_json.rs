mod common;

use common::{API_KEY, Server};
use psonoci::crypto::seal_secret_box_hex;
use serde_json::{Value, json};
use std::process::Command;
use uuid::Uuid;

fn read_json(payload: Value) -> Value {
    let secret_key = "22".repeat(32);
    let nonce = "33".repeat(24);
    let key_nonce = "44".repeat(24);
    let server = Server::start(vec![(
        200,
        json!({
            "data": seal_secret_box_hex(payload.to_string().as_bytes(), &nonce, &secret_key).unwrap(),
            "data_nonce": nonce,
            "secret_key": seal_secret_box_hex(secret_key.as_bytes(), &key_nonce, API_KEY).unwrap(),
            "secret_key_nonce": key_nonce,
            "write_date": "2026-11-02T12:00:00Z"
        }),
    )]);
    let id = Uuid::new_v4();
    let api_key_id = server.config.psono_settings.api_key_id.to_string();
    let mut command = Command::new(env!("CARGO_BIN_EXE_psonoci"));
    // Keep the fixture independent of the caller's config and authentication.
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("PSONO_CI_") {
            command.env_remove(key);
        }
    }
    let output = command
        .env("NO_PROXY", "127.0.0.1")
        .env("no_proxy", "127.0.0.1")
        .args([
            "--api-key-id",
            &api_key_id,
            "--api-secret-key-hex",
            API_KEY,
            "--server-url",
            server.config.psono_settings.server_url.as_str(),
            "secret",
            "get",
            &id.to_string(),
            "json",
        ])
        .output()
        .unwrap();
    let requests = server.finish();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[0].path, "/server/api-key-access/secret/");
    assert_eq!(requests[0].body["secret_id"], id.to_string());
    assert_eq!(requests[0].body["api_key_id"], api_key_id);
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    for internal in ["raw", "write_date", "secret_type"] {
        assert!(
            value.get(internal).is_none(),
            "internal field exposed: {internal}"
        );
    }
    value
}

#[test]
fn ssh_json_includes_both_keys_and_existing_metadata() {
    let private_key =
        "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n-----END OPENSSH PRIVATE KEY-----";
    let public_key = "ssh-ed25519 fixture public-key";
    let value = read_json(json!({
        "ssh_own_key_title": "SSH fixture", "ssh_own_key_notes": "SSH notes",
        "ssh_own_key_private": private_key, "ssh_own_key_public": public_key
    }));
    assert_eq!(value["type"], "ssh_key");
    assert_eq!(value["title"], "SSH fixture");
    assert_eq!(value["notes"], "SSH notes");
    assert_eq!(
        value["ssh_key"],
        json!({"key_private": private_key, "key_public": public_key})
    );
    assert!(value.get("elster_certificate").is_some_and(Value::is_null));
}

#[test]
fn elster_json_includes_certificate_credentials_and_existing_metadata() {
    let value = read_json(json!({
        "elster_certificate_title": "Elster fixture", "elster_certificate_notes": "Certificate notes",
        "elster_certificate_file_content": "RklYVFVSRS1DRVJUSUZJQ0FURQ==",
        "elster_certificate_password": "fixture-password",
        "elster_certificate_retrieval_code": "fixture-retrieval"
    }));
    assert_eq!(value["type"], "elster_certificate");
    assert_eq!(value["title"], "Elster fixture");
    assert_eq!(value["notes"], "Certificate notes");
    assert_eq!(
        value["elster_certificate"],
        json!({
            "file_content": "RklYVFVSRS1DRVJUSUZJQ0FURQ==",
            "password": "fixture-password", "retrieval_code": "fixture-retrieval"
        })
    );
    assert!(value.get("ssh_key").is_some_and(Value::is_null));
    assert!(value.get("password").is_some_and(Value::is_null));
}
