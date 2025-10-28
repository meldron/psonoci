use clap::{Parser, ValueEnum};
use serde::Serialize;
use uuid::Uuid;

// Import the library crate to access Opt and enums
use psonoci::api::SecretValueType;
use psonoci::opt::{ApiKeyCommand, Command, Opt, SecretCommand};

#[derive(Serialize)]
struct CommandView {
    command: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    subcommand: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    secret_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    secret_value_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    secret_new_value: Option<String>,
}

fn svt_kebab(s: &SecretValueType) -> String {
    s.to_possible_value()
        .map(|pv| pv.get_name().to_string())
        .unwrap_or_else(|| s.as_str().to_string())
}

impl From<&Command> for CommandView {
    fn from(c: &Command) -> Self {
        match c {
            Command::Secret { command } => match command {
                SecretCommand::Get {
                    secret_id,
                    secret_value_type,
                } => CommandView {
                    command: "secret",
                    subcommand: Some("get"),
                    secret_id: Some(secret_id.to_string()),
                    secret_value_type: Some(svt_kebab(secret_value_type)),
                    secret_new_value: None,
                },
                SecretCommand::Set {
                    secret_id,
                    secret_value_type,
                    secret_new_value,
                } => CommandView {
                    command: "secret",
                    subcommand: Some("set"),
                    secret_id: Some(secret_id.to_string()),
                    secret_value_type: Some(svt_kebab(secret_value_type)),
                    secret_new_value: Some(secret_new_value.clone()),
                },
            },
            Command::ApiKey { command } => match command {
                ApiKeyCommand::Info => CommandView {
                    command: "api-key",
                    subcommand: Some("info"),
                    secret_id: None,
                    secret_value_type: None,
                    secret_new_value: None,
                },
                ApiKeyCommand::Secrets => CommandView {
                    command: "api-key",
                    subcommand: Some("secrets"),
                    secret_id: None,
                    secret_value_type: None,
                    secret_new_value: None,
                },
            },
            Command::Config { .. } => CommandView {
                command: "config",
                subcommand: None,
                secret_id: None,
                secret_value_type: None,
                secret_new_value: None,
            },
            Command::Run { .. } => CommandView {
                command: "run",
                subcommand: None,
                secret_id: None,
                secret_value_type: None,
                secret_new_value: None,
            },
            Command::EnvVars { .. } => CommandView {
                command: "env-vars",
                subcommand: None,
                secret_id: None,
                secret_value_type: None,
                secret_new_value: None,
            },
            Command::Totp { .. } => CommandView {
                command: "totp",
                subcommand: None,
                secret_id: None,
                secret_value_type: None,
                secret_new_value: None,
            },
            #[cfg(unix)]
            Command::Ssh { .. } => CommandView {
                command: "ssh",
                subcommand: None,
                secret_id: None,
                secret_value_type: None,
                secret_new_value: None,
            },
            Command::Gpg { .. } => CommandView {
                command: "gpg",
                subcommand: None,
                secret_id: None,
                secret_value_type: None,
                secret_new_value: None,
            },
            Command::License => CommandView {
                command: "license",
                subcommand: None,
                secret_id: None,
                secret_value_type: None,
                secret_new_value: None,
            },
        }
    }
}

#[derive(Serialize)]
struct OptView<'a> {
    command: CommandView,
    api_key_id: Option<String>,
    api_secret_key_hex: Option<&'a str>,
    server_url: Option<String>,
}

impl<'a> From<&'a Opt> for OptView<'a> {
    fn from(o: &'a Opt) -> Self {
        let ps = &o.raw_config.psono_settings;
        Self {
            command: CommandView::from(&o.command),
            api_key_id: ps.api_key_id.as_ref().map(Uuid::to_string),
            api_secret_key_hex: ps.api_secret_key_hex.as_deref(),
            server_url: ps.server_url.as_ref().map(|u| u.to_string()),
        }
    }
}

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

    insta::assert_json_snapshot!(OptView::from(&opt));
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

    insta::assert_json_snapshot!(OptView::from(&opt));
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

    insta::assert_json_snapshot!(OptView::from(&opt));
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

    insta::assert_json_snapshot!(OptView::from(&opt));
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

    insta::assert_json_snapshot!(OptView::from(&opt));
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

    insta::assert_json_snapshot!(OptView::from(&opt));
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

    insta::assert_json_snapshot!(OptView::from(&opt));
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

    insta::assert_json_snapshot!(OptView::from(&opt));
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

    insta::assert_json_snapshot!(OptView::from(&opt));
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

    insta::assert_json_snapshot!(OptView::from(&opt));
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

    insta::assert_json_snapshot!(OptView::from(&opt));
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

    insta::assert_json_snapshot!(OptView::from(&opt));
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

    insta::assert_json_snapshot!(OptView::from(&opt));
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

    insta::assert_json_snapshot!(OptView::from(&opt));
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

    insta::assert_json_snapshot!(OptView::from(&opt));
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

    insta::assert_json_snapshot!(OptView::from(&opt));
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

    insta::assert_json_snapshot!(OptView::from(&opt));
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

    insta::assert_json_snapshot!(OptView::from(&opt));
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
