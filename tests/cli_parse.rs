use clap::Parser;
use std::sync::{LazyLock, Mutex};

// Import library crate to access Opt and enums
use psonoci::opt::Opt;

static ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

fn with_cleared_env<T>(f: impl FnOnce() -> T) -> T {
    let _guard = ENV_LOCK.lock().expect("env lock poisoned");

    for k in [
        "PSONO_CI_API_KEY_ID",
        "PSONO_CI_API_SECRET_KEY_HEX",
        "PSONO_CI_SERVER_URL",
        "PSONO_CI_CONFIG_PATH",
        "PSONO_CI_CONFIG_PACKED",
        "PSONO_CI_TIMEOUT",
        "PSONO_CI_MAX_REDIRECTS",
        "PSONO_CI_ADD_DER_ROOT_CERTIFICATE_PATH",
        "PSONO_CI_ADD_PEM_ROOT_CERTIFICATE_PATH",
    ] {
        unsafe { std::env::remove_var(k) };
    }

    f()
}

fn parse_opt(args: impl IntoIterator<Item = impl Into<std::ffi::OsString> + Clone>) -> Opt {
    with_cleared_env(|| Opt::try_parse_from(args).expect("parse failed"))
}

fn parse_opt_error(
    args: impl IntoIterator<Item = impl Into<std::ffi::OsString> + Clone>,
) -> clap::Error {
    with_cleared_env(|| Opt::try_parse_from(args).expect_err("expected parse failure"))
}

fn test_secret_value_type(value_type: &str, snapshot_name: &str) {
    let args = [
        "psonoci",
        "--api-key-id",
        "00000000-0000-0000-0000-000000000000",
        "--api-secret-key-hex",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--server-url",
        "https://psono.pw/server",
        "secret",
        "get",
        "11111111-1111-1111-1111-111111111111",
        value_type,
    ];

    let opt = parse_opt(args);

    insta::assert_json_snapshot!(snapshot_name, &opt);
}

fn parse_secret_value_type(value_type: &str) -> serde_json::Value {
    let args = [
        "psonoci",
        "--api-key-id",
        "00000000-0000-0000-0000-000000000000",
        "--api-secret-key-hex",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--server-url",
        "https://psono.pw/server",
        "secret",
        "get",
        "11111111-1111-1111-1111-111111111111",
        value_type,
    ];

    let opt = parse_opt(args);

    serde_json::to_value(&opt).expect("serialization failed")
}

// Helper function for secret set value type tests to enable IntelliSense support
fn test_secret_set_value_type(value_type: &str, snapshot_name: &str) {
    let args = [
        "psonoci",
        "--api-key-id",
        "00000000-0000-0000-0000-000000000000",
        "--api-secret-key-hex",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--server-url",
        "https://psono.pw/server",
        "secret",
        "set",
        "11111111-1111-1111-1111-111111111111",
        value_type,
        "new-value",
    ];

    let opt = parse_opt(args);

    insta::assert_json_snapshot!(snapshot_name, &opt);
}

fn parse_secret_set_value_type(value_type: &str) -> serde_json::Value {
    let args = [
        "psonoci",
        "--api-key-id",
        "00000000-0000-0000-0000-000000000000",
        "--api-secret-key-hex",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--server-url",
        "https://psono.pw/server",
        "secret",
        "set",
        "11111111-1111-1111-1111-111111111111",
        value_type,
        "new-value",
    ];

    let opt = parse_opt(args);

    serde_json::to_value(&opt).expect("serialization failed")
}

// Simplified macro that generates thin test wrappers calling the helper function
macro_rules! secret_value_type_test {
    ($test_name:ident, $value_type:literal) => {
        #[test]
        fn $test_name() {
            test_secret_value_type($value_type, stringify!($test_name));
        }
    };
}

// Macro for secret set value type tests to generate thin test wrappers calling the helper function
macro_rules! secret_set_value_type_test {
    ($test_name:ident, $value_type:literal) => {
        #[test]
        fn $test_name() {
            test_secret_set_value_type($value_type, stringify!($test_name));
        }
    };
}

secret_value_type_test!(parse_secret_get_password, "password");
secret_value_type_test!(parse_secret_get_username, "username");
secret_value_type_test!(parse_secret_get_notes, "notes");
secret_value_type_test!(parse_secret_get_url, "url");
secret_value_type_test!(parse_secret_get_title, "title");
secret_value_type_test!(parse_secret_get_secret_type, "secret_type");
secret_value_type_test!(parse_secret_get_identity_title, "identity_title");
secret_value_type_test!(parse_secret_get_identity_first_name, "identity_first_name");
secret_value_type_test!(parse_secret_get_identity_last_name, "identity_last_name");
secret_value_type_test!(parse_secret_get_identity_company, "identity_company");
secret_value_type_test!(parse_secret_get_identity_address, "identity_address");
secret_value_type_test!(parse_secret_get_identity_city, "identity_city");
secret_value_type_test!(
    parse_secret_get_identity_postal_code,
    "identity_postal_code"
);
secret_value_type_test!(parse_secret_get_identity_state, "identity_state");
secret_value_type_test!(parse_secret_get_identity_country, "identity_country");
secret_value_type_test!(
    parse_secret_get_identity_phone_number,
    "identity_phone_number"
);
secret_value_type_test!(parse_secret_get_identity_email, "identity_email");
secret_value_type_test!(parse_secret_get_identity_notes, "identity_notes");
secret_value_type_test!(parse_secret_get_env_vars, "env_vars");
secret_value_type_test!(parse_secret_get_totp_period, "totp_period");
secret_value_type_test!(parse_secret_get_totp_algorithm, "totp_algorithm");
secret_value_type_test!(parse_secret_get_totp_digits, "totp_digits");
secret_value_type_test!(parse_secret_get_totp_code, "totp_code");
secret_value_type_test!(parse_secret_get_ssh_key_public, "ssh_key_public");
secret_value_type_test!(parse_secret_get_ssh_key_private, "ssh_key_private");
secret_value_type_test!(parse_secret_get_gpg_key_email, "gpg_key_email");
secret_value_type_test!(parse_secret_get_gpg_key_name, "gpg_key_name");
secret_value_type_test!(parse_secret_get_gpg_key_private, "gpg_key_private");
secret_value_type_test!(parse_secret_get_gpg_key_public, "gpg_key_public");
secret_value_type_test!(parse_secret_get_credit_card_number, "credit_card_number");
secret_value_type_test!(parse_secret_get_credit_card_cvc, "credit_card_cvc");
secret_value_type_test!(parse_secret_get_credit_card_name, "credit_card_name");
secret_value_type_test!(
    parse_secret_get_credit_card_valid_through,
    "credit_card_valid_through"
);
secret_value_type_test!(parse_secret_get_credit_card_pin, "credit_card_pin");
secret_value_type_test!(
    parse_secret_get_elster_certificate_file_content,
    "elster_certificate_file_content"
);
secret_value_type_test!(
    parse_secret_get_elster_certificate_password,
    "elster_certificate_password"
);
secret_value_type_test!(
    parse_secret_get_elster_certificate_retrieval_code,
    "elster_certificate_retrieval_code"
);
secret_value_type_test!(parse_secret_get_json, "json");

#[test]
fn parse_secret_get_accepts_snake_case_and_kebab_case_for_all_multi_word_value_types() {
    for (snake_case, kebab_case) in [
        ("url_filter", "url-filter"),
        ("gpg_key_email", "gpg-key-email"),
        ("gpg_key_name", "gpg-key-name"),
        ("gpg_key_private", "gpg-key-private"),
        ("gpg_key_public", "gpg-key-public"),
        ("secret_type", "secret-type"),
        ("identity_title", "identity-title"),
        ("identity_first_name", "identity-first-name"),
        ("identity_last_name", "identity-last-name"),
        ("identity_company", "identity-company"),
        ("identity_address", "identity-address"),
        ("identity_city", "identity-city"),
        ("identity_postal_code", "identity-postal-code"),
        ("identity_state", "identity-state"),
        ("identity_country", "identity-country"),
        ("identity_phone_number", "identity-phone-number"),
        ("identity_email", "identity-email"),
        ("identity_notes", "identity-notes"),
        ("env_vars", "env-vars"),
        ("ssh_key_public", "ssh-key-public"),
        ("ssh_key_private", "ssh-key-private"),
        ("totp_period", "totp-period"),
        ("totp_algorithm", "totp-algorithm"),
        ("totp_digits", "totp-digits"),
        ("totp_code", "totp-code"),
        ("credit_card_number", "credit-card-number"),
        ("credit_card_cvc", "credit-card-cvc"),
        ("credit_card_name", "credit-card-name"),
        ("credit_card_valid_through", "credit-card-valid-through"),
        ("credit_card_pin", "credit-card-pin"),
        (
            "elster_certificate_file_content",
            "elster-certificate-file-content",
        ),
        ("elster_certificate_password", "elster-certificate-password"),
        (
            "elster_certificate_retrieval_code",
            "elster-certificate-retrieval-code",
        ),
    ] {
        let snake_case_opt = parse_secret_value_type(snake_case);
        let kebab_case_opt = parse_secret_value_type(kebab_case);

        assert_eq!(
            snake_case_opt, kebab_case_opt,
            "snake_case and kebab-case should parse identically for {snake_case}"
        );
    }
}

// Secret set tests for all value types to ensure comprehensive coverage
secret_set_value_type_test!(parse_secret_set_json, "json");
secret_set_value_type_test!(parse_secret_set_notes, "notes");
secret_set_value_type_test!(parse_secret_set_password, "password");
secret_set_value_type_test!(parse_secret_set_title, "title");
secret_set_value_type_test!(parse_secret_set_url, "url");
secret_set_value_type_test!(parse_secret_set_url_filter, "url_filter");
secret_set_value_type_test!(parse_secret_set_username, "username");
secret_set_value_type_test!(parse_secret_set_gpg_key_email, "gpg_key_email");
secret_set_value_type_test!(parse_secret_set_gpg_key_name, "gpg_key_name");
secret_set_value_type_test!(parse_secret_set_gpg_key_private, "gpg_key_private");
secret_set_value_type_test!(parse_secret_set_gpg_key_public, "gpg_key_public");
secret_set_value_type_test!(parse_secret_set_secret_type, "secret_type");
secret_set_value_type_test!(parse_secret_set_identity_title, "identity_title");
secret_set_value_type_test!(parse_secret_set_identity_first_name, "identity_first_name");
secret_set_value_type_test!(parse_secret_set_identity_last_name, "identity_last_name");
secret_set_value_type_test!(parse_secret_set_identity_company, "identity_company");
secret_set_value_type_test!(parse_secret_set_identity_address, "identity_address");
secret_set_value_type_test!(parse_secret_set_identity_city, "identity_city");
secret_set_value_type_test!(
    parse_secret_set_identity_postal_code,
    "identity_postal_code"
);
secret_set_value_type_test!(parse_secret_set_identity_state, "identity_state");
secret_set_value_type_test!(parse_secret_set_identity_country, "identity_country");
secret_set_value_type_test!(
    parse_secret_set_identity_phone_number,
    "identity_phone_number"
);
secret_set_value_type_test!(parse_secret_set_identity_email, "identity_email");
secret_set_value_type_test!(parse_secret_set_identity_notes, "identity_notes");
secret_set_value_type_test!(parse_secret_set_env_vars, "env_vars");
secret_set_value_type_test!(parse_secret_set_ssh_key_public, "ssh_key_public");
secret_set_value_type_test!(parse_secret_set_ssh_key_private, "ssh_key_private");
secret_set_value_type_test!(parse_secret_set_totp_period, "totp_period");
secret_set_value_type_test!(parse_secret_set_totp_algorithm, "totp_algorithm");
secret_set_value_type_test!(parse_secret_set_totp_digits, "totp_digits");
secret_set_value_type_test!(parse_secret_set_totp_code, "totp_code");
secret_set_value_type_test!(parse_secret_set_credit_card_number, "credit_card_number");
secret_set_value_type_test!(parse_secret_set_credit_card_cvc, "credit_card_cvc");
secret_set_value_type_test!(parse_secret_set_credit_card_name, "credit_card_name");
secret_set_value_type_test!(
    parse_secret_set_credit_card_valid_through,
    "credit_card_valid_through"
);
secret_set_value_type_test!(parse_secret_set_credit_card_pin, "credit_card_pin");
secret_set_value_type_test!(
    parse_secret_set_elster_certificate_file_content,
    "elster_certificate_file_content"
);
secret_set_value_type_test!(
    parse_secret_set_elster_certificate_password,
    "elster_certificate_password"
);
secret_set_value_type_test!(
    parse_secret_set_elster_certificate_retrieval_code,
    "elster_certificate_retrieval_code"
);

#[test]
fn parse_secret_set_accepts_legacy_snake_case() {
    let args = [
        "psonoci",
        "--api-key-id",
        "00000000-0000-0000-0000-000000000000",
        "--api-secret-key-hex",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--server-url",
        "https://psono.pw/server",
        "secret",
        "set",
        "11111111-1111-1111-1111-111111111111",
        // legacy snake_case should be accepted via alias
        "url_filter",
        "new-value",
    ];

    let opt = parse_opt(args);

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_secret_set_kebab_case() {
    let args = [
        "psonoci",
        "--api-key-id",
        "00000000-0000-0000-0000-000000000000",
        "--api-secret-key-hex",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--server-url",
        "https://psono.pw/server",
        "secret",
        "set",
        "11111111-1111-1111-1111-111111111111",
        // canonical kebab-case
        "url-filter",
        "new-value",
    ];

    let opt = parse_opt(args);

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_secret_set_accepts_snake_case_and_kebab_case_for_all_multi_word_value_types() {
    for (snake_case, kebab_case) in [
        ("url_filter", "url-filter"),
        ("gpg_key_email", "gpg-key-email"),
        ("gpg_key_name", "gpg-key-name"),
        ("gpg_key_private", "gpg-key-private"),
        ("gpg_key_public", "gpg-key-public"),
        ("secret_type", "secret-type"),
        ("identity_title", "identity-title"),
        ("identity_first_name", "identity-first-name"),
        ("identity_last_name", "identity-last-name"),
        ("identity_company", "identity-company"),
        ("identity_address", "identity-address"),
        ("identity_city", "identity-city"),
        ("identity_postal_code", "identity-postal-code"),
        ("identity_state", "identity-state"),
        ("identity_country", "identity-country"),
        ("identity_phone_number", "identity-phone-number"),
        ("identity_email", "identity-email"),
        ("identity_notes", "identity-notes"),
        ("env_vars", "env-vars"),
        ("ssh_key_public", "ssh-key-public"),
        ("ssh_key_private", "ssh-key-private"),
        ("totp_period", "totp-period"),
        ("totp_algorithm", "totp-algorithm"),
        ("totp_digits", "totp-digits"),
        ("totp_code", "totp-code"),
        ("credit_card_number", "credit-card-number"),
        ("credit_card_cvc", "credit-card-cvc"),
        ("credit_card_name", "credit-card-name"),
        ("credit_card_valid_through", "credit-card-valid-through"),
        ("credit_card_pin", "credit-card-pin"),
        (
            "elster_certificate_file_content",
            "elster-certificate-file-content",
        ),
        ("elster_certificate_password", "elster-certificate-password"),
        (
            "elster_certificate_retrieval_code",
            "elster-certificate-retrieval-code",
        ),
    ] {
        let snake_case_opt = parse_secret_set_value_type(snake_case);
        let kebab_case_opt = parse_secret_set_value_type(kebab_case);

        assert_eq!(
            snake_case_opt, kebab_case_opt,
            "snake_case and kebab-case should parse identically for {snake_case}"
        );
    }
}

#[test]
fn parse_api_key_info() {
    let args = [
        "psonoci",
        "--api-key-id",
        "00000000-0000-0000-0000-000000000000",
        "--api-secret-key-hex",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--server-url",
        "https://psono.pw/server",
        "api-key",
        "info",
    ];

    let opt = parse_opt(args);

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_api_key_secrets() {
    let args = [
        "psonoci",
        "--api-key-id",
        "00000000-0000-0000-0000-000000000000",
        "--api-secret-key-hex",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--server-url",
        "https://psono.pw/server",
        "api-key",
        "secrets",
    ];

    let opt = parse_opt(args);

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_config_commands_save_no_overwrite() {
    let args = [
        "psonoci",
        "--api-key-id",
        "00000000-0000-0000-0000-000000000000",
        "--api-secret-key-hex",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--server-url",
        "https://psono.pw/server",
        "config",
        "save",
        "/path/to/config.toml",
    ];

    let opt = parse_opt(args);

    insta::assert_json_snapshot!(&opt);
}

// Individual tests for config commands to ensure deterministic snapshot naming
#[test]
fn parse_config_commands_pack() {
    let args = [
        "psonoci",
        "--api-key-id",
        "00000000-0000-0000-0000-000000000000",
        "--api-secret-key-hex",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--server-url",
        "https://psono.pw/server",
        "config",
        "pack",
    ];

    let opt = parse_opt(args);

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_config_save() {
    let args = [
        "psonoci",
        "--api-key-id",
        "00000000-0000-0000-0000-000000000000",
        "--api-secret-key-hex",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--server-url",
        "https://psono.pw/server",
        "config",
        "save",
        "--overwrite",
        "/path/to/config.toml",
    ];

    let opt = parse_opt(args);

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_config_show() {
    let args = [
        "psonoci",
        "--api-key-id",
        "00000000-0000-0000-0000-000000000000",
        "--api-secret-key-hex",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--server-url",
        "https://psono.pw/server",
        "config",
        "show",
    ];

    let opt = parse_opt(args);

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_run() {
    let args = [
        "psonoci",
        "--api-key-id",
        "00000000-0000-0000-0000-000000000000",
        "--api-secret-key-hex",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--server-url",
        "https://psono.pw/server",
        "run",
        "--clear-env",
        "--filter",
        "11111111-1111-1111-1111-111111111111",
        "--",
        "echo",
        "hello",
    ];

    let opt = parse_opt(args);

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_env_vars_get_or_create() {
    let args = [
        "psonoci",
        "--api-key-id",
        "00000000-0000-0000-0000-000000000000",
        "--api-secret-key-hex",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--server-url",
        "https://psono.pw/server",
        "env-vars",
        "get-or-create",
        "11111111-1111-1111-1111-111111111111",
        "MY_VAR",
        "--password-length",
        "16",
    ];

    let opt = parse_opt(args);

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_env_vars_update_or_create() {
    let args = [
        "psonoci",
        "--api-key-id",
        "00000000-0000-0000-0000-000000000000",
        "--api-secret-key-hex",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--server-url",
        "https://psono.pw/server",
        "env-vars",
        "update-or-create",
        "11111111-1111-1111-1111-111111111111",
        "MY_VAR",
        "new_value",
    ];

    let opt = parse_opt(args);

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_totp_get_token() {
    let args = [
        "psonoci",
        "--api-key-id",
        "00000000-0000-0000-0000-000000000000",
        "--api-secret-key-hex",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--server-url",
        "https://psono.pw/server",
        "totp",
        "get-token",
        "11111111-1111-1111-1111-111111111111",
    ];

    let opt = parse_opt(args);

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_totp_validate_token() {
    let args = [
        "psonoci",
        "--api-key-id",
        "00000000-0000-0000-0000-000000000000",
        "--api-secret-key-hex",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--server-url",
        "https://psono.pw/server",
        "totp",
        "validate-token",
        "11111111-1111-1111-1111-111111111111",
        "123456",
    ];

    let opt = parse_opt(args);

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_totp_get_url() {
    let args = [
        "psonoci",
        "--api-key-id",
        "00000000-0000-0000-0000-000000000000",
        "--api-secret-key-hex",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--server-url",
        "https://psono.pw/server",
        "totp",
        "get-url",
        "11111111-1111-1111-1111-111111111111",
        "--issuer",
        "MyApp",
        "--account-name",
        "user@example.com",
    ];

    let opt = parse_opt(args);

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_ssh_add() {
    let args = [
        "psonoci",
        "--api-key-id",
        "00000000-0000-0000-0000-000000000000",
        "--api-secret-key-hex",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--server-url",
        "https://psono.pw/server",
        "ssh",
        "add",
        "11111111-1111-1111-1111-111111111111",
        "--key-lifetime",
        "3600",
    ];

    let opt = parse_opt(args);

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_gpg_sign() {
    let args = [
        "psonoci",
        "--api-key-id",
        "00000000-0000-0000-0000-000000000000",
        "--api-secret-key-hex",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--server-url",
        "https://psono.pw/server",
        "gpg",
        "sign",
        "11111111-1111-1111-1111-111111111111",
        "--armor",
        "-o",
        "/path/to/output",
    ];

    let opt = parse_opt(args);

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_gpg_verify() {
    let args = [
        "psonoci",
        "--api-key-id",
        "00000000-0000-0000-0000-000000000000",
        "--api-secret-key-hex",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--server-url",
        "https://psono.pw/server",
        "gpg",
        "verify",
        "11111111-1111-1111-1111-111111111111",
        "-s",
        "/path/to/sig",
        "--verbose",
    ];

    let opt = parse_opt(args);

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_license() {
    let args = [
        "psonoci",
        "--api-key-id",
        "00000000-0000-0000-0000-000000000000",
        "--api-secret-key-hex",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--server-url",
        "https://psono.pw/server",
        "license",
    ];

    let opt = parse_opt(args);

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_secret_get() {
    let args = [
        "psonoci",
        "--api-key-id",
        "00000000-0000-0000-0000-000000000000",
        "--api-secret-key-hex",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--server-url",
        "https://psono.pw/server",
        "secret",
        "get",
        "11111111-1111-1111-1111-111111111111",
        "json",
    ];

    let opt = parse_opt(args);

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_secret_get_fails_without_globals() {
    let args = [
        "psonoci",
        "secret",
        "get",
        "11111111-1111-1111-1111-111111111111",
        "json",
    ];

    let error = parse_opt_error(args);
    insta::assert_snapshot!(error.to_string());
}

#[test]
fn parse_fails_invalid_subcommand() {
    let args = [
        "psonoci",
        "--api-key-id",
        "00000000-0000-0000-0000-000000000000",
        "--api-secret-key-hex",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--server-url",
        "https://psono.pw/server",
        "invalid-command",
    ];

    let error = parse_opt_error(args);
    insta::assert_snapshot!(error.to_string());
}

#[test]
fn parse_fails_missing_required_argument() {
    let args = [
        "psonoci",
        "--api-key-id",
        "00000000-0000-0000-0000-000000000000",
        "--api-secret-key-hex",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--server-url",
        "https://psono.pw/server",
        "secret",
        "get",
        // Missing secret_id argument
    ];

    let error = parse_opt_error(args);
    insta::assert_snapshot!(error.to_string());
}

#[test]
fn parse_fails_invalid_value_type() {
    let args = [
        "psonoci",
        "--api-key-id",
        "00000000-0000-0000-0000-000000000000",
        "--api-secret-key-hex",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--server-url",
        "https://psono.pw/server",
        "secret",
        "get",
        "11111111-1111-1111-1111-111111111111",
        "invalid-type",
    ];

    let error = parse_opt_error(args);
    insta::assert_snapshot!(error.to_string());
}

#[test]
fn parse_fails_invalid_api_key_format() {
    let args = [
        "psonoci",
        "--api-key-id",
        "invalid-uuid-format",
        "--api-secret-key-hex",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--server-url",
        "https://psono.pw/server",
        "api-key",
        "info",
    ];

    let error = parse_opt_error(args);
    insta::assert_snapshot!(error.to_string());
}

#[test]
fn parse_fails_missing_server_url() {
    let args = [
        "psonoci",
        "--api-key-id",
        "00000000-0000-0000-0000-000000000000",
        "--api-secret-key-hex",
        "0000000000000000000000000000000000000000000000000000000000000000",
        // Missing --server-url
        "api-key",
        "info",
    ];

    let error = parse_opt_error(args);
    insta::assert_snapshot!(error.to_string());
}

#[test]
fn parse_fails_invalid_hex_key() {
    let args = [
        "psonoci",
        "--api-key-id",
        "00000000-0000-0000-0000-000000000000",
        "--api-secret-key-hex",
        "invalid-hex-format",
        "--server-url",
        "https://psono.pw/server",
        "api-key",
        "info",
    ];

    let error = parse_opt_error(args);
    insta::assert_snapshot!(error.to_string());
}

#[test]
fn parse_fails_conflicting_arguments() {
    let args = [
        "psonoci",
        "--api-key-id",
        "00000000-0000-0000-0000-000000000000",
        "--api-secret-key-hex",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--server-url",
        "https://psono.pw/server",
        "config",
        "save",
        "--overwrite",
        "/path/to/config.toml",
        "--overwrite", // Duplicate flag
    ];

    let error = parse_opt_error(args);
    insta::assert_snapshot!(error.to_string());
}
