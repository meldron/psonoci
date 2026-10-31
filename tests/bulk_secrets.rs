mod common;

use common::{API_KEY, Server};
use psonoci::api::{
    SecretType, SecretValueType, api_key_get_secrets, api_key_get_secrets_filtered, get_secret,
    set_secret,
};
use psonoci::crypto::seal_secret_box_hex;
use serde_json::{Value, json};
use uuid::Uuid;

fn encrypted(payload: Value) -> Value {
    let secret_key = "22".repeat(32);
    let nonce = "33".repeat(24);
    let key_nonce = "44".repeat(24);
    json!({
        "data": seal_secret_box_hex(payload.to_string().as_bytes(), &nonce, &secret_key).unwrap(),
        "data_nonce": nonce,
        "secret_key": seal_secret_box_hex(secret_key.as_bytes(), &key_nonce, API_KEY).unwrap(),
        "secret_key_nonce": key_nonce,
    })
}

fn inspect(ids: &[Uuid]) -> Value {
    json!({
        "allow_insecure_access":false, "restrict_to_secrets":true, "read":true,"write":true,
        "api_key_secrets": ids.iter().map(|id| json!({"secret_id":id,"write_date":"2026-10-31T12:00:00Z"})).collect::<Vec<_>>()
    })
}

fn env_payload() -> Value {
    json!({"environment_variables_title":"Test", "environment_variables_variables":[{"key":"BULK_FIXTURE", "value":"expected"}]})
}

#[test]
fn mixed_bulk_read_preserves_unsupported_payloads() {
    let env_id = Uuid::new_v4();
    let unknown_id = Uuid::new_v4();
    let original = json!({"passkey_title":"Test", "passkey_private_key":{"kty":"EC","d":"fixture"}, "future":[true,null]});
    let unknown_response = encrypted(original.clone());
    let server = Server::with_handler(3, move |request| {
        if request.path.ends_with("/inspect/") {
            (200, inspect(&[env_id, unknown_id]))
        } else if request.body["secret_id"] == env_id.to_string() {
            (200, encrypted(env_payload()))
        } else {
            assert_eq!(request.body["secret_id"], unknown_id.to_string());
            (200, unknown_response.clone())
        }
    });
    let secrets = api_key_get_secrets(&server.config).unwrap();
    assert_eq!(secrets.len(), 2);
    assert_eq!(secrets[&env_id].secret_type, SecretType::EnvVars);
    assert_eq!(secrets[&unknown_id].secret_type, SecretType::Unknown);
    assert_eq!(
        serde_json::to_value(&secrets[&unknown_id]).unwrap()["raw"],
        original
    );
    assert_eq!(
        serde_json::from_str::<Value>(
            &secrets[&unknown_id]
                .clone()
                .get_value(&SecretValueType::json)
                .unwrap()
        )
        .unwrap(),
        original
    );
    assert!(
        serde_json::to_value(&secrets[&env_id])
            .unwrap()
            .get("raw")
            .is_none()
    );
    let requests = server.finish();
    assert_eq!(requests.len(), 3);
    assert!(requests.iter().all(|r| r.method == "POST"));
}

#[test]
fn filters_ids_before_fetching_excluded_secrets() {
    let selected = Uuid::new_v4();
    let excluded = Uuid::new_v4();
    let server = Server::with_handler(2, move |request| {
        if request.path.ends_with("/inspect/") {
            (200, inspect(&[selected, excluded]))
        } else {
            assert_eq!(request.body["secret_id"], selected.to_string());
            (200, encrypted(env_payload()))
        }
    });
    let secrets = api_key_get_secrets_filtered(&server.config, Some(&[selected])).unwrap();
    assert_eq!(secrets.len(), 1);
    assert!(secrets.contains_key(&selected));
    assert_eq!(server.finish().len(), 2);
}

#[test]
fn empty_filter_fetches_no_secret_payloads() {
    let server = Server::start(vec![(200, inspect(&[Uuid::new_v4()]))]);
    assert!(
        api_key_get_secrets_filtered(&server.config, Some(&[]))
            .unwrap()
            .is_empty()
    );
    assert_eq!(server.finish().len(), 1);
}

#[test]
fn requested_authentication_decryption_and_validation_failures_remain_fatal() {
    for (status, body) in [
        (401, json!({})),
        (403, json!({})),
        (500, json!({})),
        (
            200,
            json!({"data":"bad", "data_nonce":"bad", "secret_key":"bad", "secret_key_nonce":"bad"}),
        ),
        (200, encrypted(json!({"website_password_password":false}))),
        (200, encrypted(json!(["invalid secret array"]))),
    ] {
        let selected = Uuid::new_v4();
        let server = Server::start(vec![(200, inspect(&[selected])), (status, body)]);
        assert!(api_key_get_secrets_filtered(&server.config, Some(&[selected])).is_err());
        assert_eq!(server.finish().len(), 2);
    }
}

#[test]
fn requested_network_failures_remain_fatal() {
    let selected = Uuid::new_v4();
    // Closing the fixture after inspect makes the subsequent secret request fail.
    let server = Server::start(vec![(200, inspect(&[selected]))]);
    assert!(api_key_get_secrets_filtered(&server.config, Some(&[selected])).is_err());
    assert_eq!(server.finish().len(), 1);
}

#[test]
fn opaque_secrets_cannot_be_written() {
    let server = Server::start(vec![(
        200,
        encrypted(json!({"ssh_connection_host":"test.invalid"})),
    )]);
    let id = Uuid::new_v4();
    let (secret, key) = get_secret(&id, &server.config).unwrap();
    assert_eq!(secret.secret_type, SecretType::Unknown);
    assert!(
        set_secret(&id, &server.config, &secret, &key)
            .unwrap_err()
            .to_string()
            .contains("unsupported secret")
    );
    assert_eq!(server.finish().len(), 1);
}

#[cfg(unix)]
fn run_fixture(server: &Server, selected: Option<Uuid>) -> std::process::Output {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_psonoci"));
    command
        .env_remove("PSONO_CI_CONFIG_PACKED")
        .env_remove("PSONO_CI_CONFIG_PATH");
    command.args([
        "--api-key-id",
        &server.config.psono_settings.api_key_id.to_string(),
        "--api-secret-key-hex",
        API_KEY,
        "--server-url",
        server.config.psono_settings.server_url.as_str(),
        "run",
        "--clear-env",
    ]);
    if let Some(id) = selected {
        command.args(["--filter", &id.to_string()]);
    }
    command
        .args(["--", "/bin/sh", "-c", "printf '%s' \"$BULK_FIXTURE\""])
        .output()
        .unwrap()
}

#[cfg(unix)]
#[test]
fn run_command_fetches_only_selected_secrets_and_injects_their_environment() {
    let selected = Uuid::new_v4();
    let excluded = Uuid::new_v4();
    let server = Server::with_handler(2, move |request| {
        if request.path.ends_with("/inspect/") {
            (200, inspect(&[selected, excluded]))
        } else {
            assert_eq!(request.body["secret_id"], selected.to_string());
            (200, encrypted(env_payload()))
        }
    });
    let result = run_fixture(&server, Some(selected));
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(result.stdout, b"expected");
    assert_eq!(server.finish().len(), 2);
}

#[cfg(unix)]
#[test]
fn run_ignores_unknown_secrets_but_stops_before_child_on_requested_errors() {
    for fail in [false, true] {
        let selected = Uuid::new_v4();
        let unknown = Uuid::new_v4();
        let server = Server::with_handler(if fail { 2 } else { 3 }, move |request| {
            if request.path.ends_with("/inspect/") {
                (200, inspect(&[selected, unknown]))
            } else if fail {
                (403, json!({}))
            } else if request.body["secret_id"] == selected.to_string() {
                (200, encrypted(env_payload()))
            } else {
                (200, encrypted(json!({"passkey_title":"Test"})))
            }
        });
        let result = run_fixture(&server, if fail { Some(selected) } else { None });
        if fail {
            assert!(!result.status.success());
            assert!(result.stdout.is_empty());
        } else {
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert_eq!(result.stdout, b"expected");
        }
        assert_eq!(server.finish().len(), if fail { 2 } else { 3 });
    }
}
