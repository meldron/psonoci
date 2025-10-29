use clap::Parser;

// Import library crate to access Opt and enums
use psonoci::opt::Opt;

fn clear_env() {
    // Ensure clap env readers don't influence parsing
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
        std::env::remove_var(k);
    }
}

fn test_secret_value_type(value_type: &str, snapshot_name: &str) {
    clear_env();

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

    let opt = Opt::try_parse_from(args).expect("parse failed");

    insta::assert_json_snapshot!(snapshot_name, &opt);
}

// Helper function for secret set value type tests to enable IntelliSense support
fn test_secret_set_value_type(value_type: &str, snapshot_name: &str) {
    clear_env();

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

    let opt = Opt::try_parse_from(args).expect("parse failed");

    insta::assert_json_snapshot!(snapshot_name, &opt);
}

// Simplified macro that generates thin test wrappers calling the helper function
macro_rules! secret_value_type_test {
    ($test_name:ident, $value_type:expr) => {
        #[test]
        fn $test_name() {
            test_secret_value_type($value_type, stringify!($test_name));
        }
    };
}

// Macro for secret set value type tests to generate thin test wrappers calling the helper function
macro_rules! secret_set_value_type_test {
    ($test_name:ident, $value_type:expr) => {
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
secret_set_value_type_test!(parse_secret_set_credit_card_valid_through, "credit_card_valid_through");
secret_set_value_type_test!(parse_secret_set_credit_card_pin, "credit_card_pin");
secret_set_value_type_test!(parse_secret_set_elster_certificate_file_content, "elster_certificate_file_content");
secret_set_value_type_test!(parse_secret_set_elster_certificate_password, "elster_certificate_password");
secret_set_value_type_test!(parse_secret_set_elster_certificate_retrieval_code, "elster_certificate_retrieval_code");

#[test]
fn parse_secret_set_accepts_legacy_snake_case() {
    clear_env();

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

    let opt = Opt::try_parse_from(args).expect("parse failed");

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_secret_set_kebab_case() {
    clear_env();

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

    let opt = Opt::try_parse_from(args).expect("parse failed");

    insta::assert_json_snapshot!(&opt);
}

// Individual tests for API key commands to ensure deterministic snapshot naming
#[test]
fn parse_api_key_commands_info() {
    clear_env();

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

    let opt = Opt::try_parse_from(args).expect("parse failed");

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_api_key_commands_secrets() {
    clear_env();

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

    let opt = Opt::try_parse_from(args).expect("parse failed");

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_api_key_info() {
    clear_env();

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

    let opt = Opt::try_parse_from(args).expect("parse failed");

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_api_key_secrets() {
    clear_env();

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

    let opt = Opt::try_parse_from(args).expect("parse failed");

    insta::assert_json_snapshot!(&opt);
}

// Individual tests for config commands to ensure deterministic snapshot naming
#[test]
fn parse_config_commands_pack() {
    clear_env();

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

    let opt = Opt::try_parse_from(args).expect("parse failed");

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_config_commands_save_with_overwrite() {
    clear_env();

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

    let opt = Opt::try_parse_from(args).expect("parse failed");

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_config_commands_save_no_overwrite() {
    clear_env();

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

    let opt = Opt::try_parse_from(args).expect("parse failed");

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_config_commands_show() {
    clear_env();

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

    let opt = Opt::try_parse_from(args).expect("parse failed");

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_config_pack() {
    clear_env();

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

    let opt = Opt::try_parse_from(args).expect("parse failed");

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_config_save() {
    clear_env();

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

    let opt = Opt::try_parse_from(args).expect("parse failed");

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_config_show() {
    clear_env();

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

    let opt = Opt::try_parse_from(args).expect("parse failed");

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_run() {
    clear_env();

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

    let opt = Opt::try_parse_from(args).expect("parse failed");

    insta::assert_json_snapshot!(&opt);
}

// Individual tests for env-vars commands to ensure deterministic snapshot naming
#[test]
fn parse_env_vars_commands_get_or_create_with_options() {
    clear_env();

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
        "--danger-password-allowed-chars",
        "ABC123",
        "--password-length",
        "12",
    ];

    let opt = Opt::try_parse_from(args).expect("parse failed");

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_env_vars_commands_update_or_create_with_options() {
    clear_env();

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
        "--danger-password-allowed-chars",
        "xyz789",
        "--password-length",
        "8",
        "new_value",
    ];

    let opt = Opt::try_parse_from(args).expect("parse failed");

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_env_vars_commands_get_or_create_minimal() {
    clear_env();

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
    ];

    let opt = Opt::try_parse_from(args).expect("parse failed");

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_env_vars_commands_update_or_create_minimal() {
    clear_env();

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

    let opt = Opt::try_parse_from(args).expect("parse failed");

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_env_vars_get_or_create() {
    clear_env();

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

    let opt = Opt::try_parse_from(args).expect("parse failed");

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_env_vars_update_or_create() {
    clear_env();

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

    let opt = Opt::try_parse_from(args).expect("parse failed");

    insta::assert_json_snapshot!(&opt);
}

// Parameterized tests for TOTP commands
// Individual tests for TOTP commands to ensure deterministic snapshot naming
#[test]
fn parse_totp_commands_get_token() {
    clear_env();

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

    let opt = Opt::try_parse_from(args).expect("parse failed");

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_totp_commands_validate_token() {
    clear_env();

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

    let opt = Opt::try_parse_from(args).expect("parse failed");

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_totp_commands_get_url() {
    clear_env();

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

    let opt = Opt::try_parse_from(args).expect("parse failed");

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_totp_get_token() {
    clear_env();

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

    let opt = Opt::try_parse_from(args).expect("parse failed");

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_totp_validate_token() {
    clear_env();

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

    let opt = Opt::try_parse_from(args).expect("parse failed");

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_totp_get_url() {
    clear_env();

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

    let opt = Opt::try_parse_from(args).expect("parse failed");

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_ssh_add() {
    clear_env();

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

    let opt = Opt::try_parse_from(args).expect("parse failed");

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_gpg_sign() {
    clear_env();

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

    let opt = Opt::try_parse_from(args).expect("parse failed");

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_gpg_verify() {
    clear_env();

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

    let opt = Opt::try_parse_from(args).expect("parse failed");

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_license() {
    clear_env();

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

    let opt = Opt::try_parse_from(args).expect("parse failed");

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_secret_get() {
    clear_env();

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

    let opt = Opt::try_parse_from(args).expect("parse failed");

    insta::assert_json_snapshot!(&opt);
}

#[test]
fn parse_secret_get_fails_without_globals() {
    clear_env();

    let args = [
        "psonoci",
        "secret",
        "get",
        "11111111-1111-1111-1111-111111111111",
        "json",
    ];

    Opt::try_parse_from(args).expect_err("should fail without global options");
}
