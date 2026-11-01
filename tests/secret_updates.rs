mod common;

use common::{API_KEY, Server};
use psonoci::api::{SecretValueType, get_secret, set_secret};
use psonoci::crypto::{open_secret_box, seal_secret_box_hex};
use serde_json::{Value, json};
use uuid::Uuid;

const SECRET_KEY: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn encrypted_secret(write_date: Option<&str>) -> Value {
    let nonce = "33".repeat(24);
    let key_nonce = "44".repeat(24);
    let original = original_payload();
    let mut response = json!({
        "data": seal_secret_box_hex(original.to_string().as_bytes(), &nonce, SECRET_KEY).unwrap(),
        "data_nonce": nonce,
        "secret_key": seal_secret_box_hex(SECRET_KEY.as_bytes(), &key_nonce, API_KEY).unwrap(),
        "secret_key_nonce": key_nonce,
    });
    if let Some(date) = write_date {
        response["write_date"] = json!(date);
    }
    response
}

fn original_payload() -> Value {
    json!({
        "website_password_title": "Test", "website_password_password": "before",
        "website_password_totp_code": "TESTONLY",
        "attachments": [{"file_id": "test-only", "metadata": {"version": 3}}],
        "custom_fields": [{"name": "owner", "value": "test"}],
        "tags": ["fixture"], "future": {"nested": [true, null]}
    })
}

#[test]
fn encrypted_read_edit_write_preserves_payload_and_sends_timestamp() {
    for timestamp in [Some("2026-10-31T12:00:00.123456Z"), None] {
        let server = Server::start(vec![(200, encrypted_secret(timestamp)), (200, json!({}))]);
        let id = Uuid::new_v4();
        let (mut secret, key) = get_secret(&id, &server.config).unwrap();
        // Transport timestamps must not change the supported public JSON format.
        assert!(!secret.as_json().unwrap().contains("write_date"));
        secret
            .set_value(&SecretValueType::password, "after".into())
            .unwrap();
        set_secret(&id, &server.config, &secret, &key).unwrap();
        let requests = server.finish();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].method, "POST");
        assert_eq!(requests[1].method, "PUT");
        assert_eq!(requests[1].path, "/server/api-key-access/secret/");
        let body = &requests[1].body;
        if let Some(timestamp) = timestamp {
            assert_eq!(body["old_write_date"], timestamp);
        } else {
            assert!(body.get("old_write_date").is_none());
        }
        let plaintext = open_secret_box(
            body["data"].as_str().unwrap(),
            body["data_nonce"].as_str().unwrap(),
            SECRET_KEY,
        )
        .unwrap();
        let actual: Value = serde_json::from_slice(&plaintext).unwrap();
        let mut expected = original_payload();
        expected["website_password_password"] = json!("after");
        let date = chrono::DateTime::parse_from_rfc3339(
            actual["password_modification_datetime"].as_str().unwrap(),
        )
        .unwrap();
        assert!(
            (chrono::Utc::now() - date.with_timezone(&chrono::Utc))
                .num_seconds()
                .abs()
                < 5
        );
        expected["password_modification_datetime"] =
            actual["password_modification_datetime"].clone();
        assert_eq!(actual, expected);
    }
}

#[test]
fn stale_write_reports_conflict_without_retry() {
    let timestamp = "2026-10-31T12:00:00Z";
    let server = Server::start(vec![
        (200, encrypted_secret(Some(timestamp))),
        (400, json!({"non_field_errors": ["WRITE_DATE_MISMATCH"]})),
    ]);
    let id = Uuid::new_v4();
    let (mut secret, key) = get_secret(&id, &server.config).unwrap();
    secret
        .set_value(&SecretValueType::password, "after".into())
        .unwrap();
    let error = set_secret(&id, &server.config, &secret, &key).unwrap_err();
    let message = format!("{error:#}");
    assert!(message.contains("WRITE_DATE_MISMATCH"));
    assert!(message.contains("reload it and reapply"));
    let requests = server.finish();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[1].body["old_write_date"], timestamp);
}

#[test]
fn unrelated_errors_remain_failures_without_exposing_response_content() {
    for status in [400, 401, 403, 500] {
        let server = Server::start(vec![(
            status,
            json!({"non_field_errors": ["private-server-detail"]}),
        )]);
        let error = get_secret(&Uuid::new_v4(), &server.config).unwrap_err();
        let message = format!("{error:#}");
        assert!(!message.contains("WRITE_DATE_MISMATCH"));
        assert!(!message.contains("private-server-detail"));
        assert!(message.contains(&status.to_string()));
        assert_eq!(server.finish().len(), 1);
    }
}
