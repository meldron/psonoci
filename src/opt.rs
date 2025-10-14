use std::ffi::OsString;
use std::fmt::Display;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

use crate::api::{parse_url, SecretValueType};
use crate::config::{Config, ConfigLoader, HttpOptions, PsonoSettings};
use crate::crypto::parse_secret_key;

#[derive(Parser, Debug)]
#[command(
    name = "psonoci",
    about = "Psono CI Client (https://github.com/meldron/psonoci)",
    author = "Bernd Kaiser",
    version,
    help_template = "{name} {version}\n{author-with-newline}{about-with-newline}\n{usage-heading} {usage}\n\n{all-args}"
)]
pub struct Opt {
    #[clap(subcommand)]
    pub command: Command,
    #[clap(flatten)]
    pub raw_config: RawConfig,
}

#[derive(Parser, Debug)]
pub struct RawConfig {
    // psono server options
    #[clap(flatten)]
    pub psono_settings: RawPsonoSettings,
    #[clap(flatten)]
    pub http_options: HttpOptions,

    #[clap(
        long,
        name = "config_packed",
        env = "PSONO_CI_CONFIG_PACKED",
        help = "psonci config as packed string"
    )]
    pub config_packed: Option<String>,

    #[clap(
        short = 'c',
        long,
        name = "config_path",
        env = "PSONO_CI_CONFIG_PATH",
        help = "psonoci config path"
    )]
    pub config_path: Option<PathBuf>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ConfigSource {
    Args,
    File(String),
    Pack,
}

impl Display for ConfigSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ConfigSource::Args => "command line args".to_string(),
            ConfigSource::File(fp) => format!("--config-path '{}'", fp),
            ConfigSource::Pack => "--config-packed".to_string(),
        };

        write!(f, "{}", s)
    }
}

impl RawConfig {
    pub fn into_config(self) -> Result<(ConfigSource, Config)> {
        let psono_settings: PsonoSettings;

        if let Some(config_packed) = self.config_packed {
            return Ok((
                ConfigSource::Pack,
                ConfigLoader::from_str(
                    &config_packed,
                    crate::config::ConfigSaveFormat::MessagePackBase58,
                )?,
            ));
        } else if let Some(config_path) = self.config_path {
            let path_str = config_path.as_path().display().to_string();
            return Ok((
                ConfigSource::File(path_str),
                ConfigLoader::load(&config_path, crate::config::ConfigSaveFormat::Toml)
                    .context("loading config failed")?,
            ));
        } else {
            psono_settings = PsonoSettings {
                api_key_id: self.psono_settings.api_key_id.expect("api_key_id not set"),
                api_secret_key_hex: self
                    .psono_settings
                    .api_secret_key_hex
                    .expect("api_secret_key_hex not set"),
                server_url: self.psono_settings.server_url.expect("server_url not set"),
            }
        }

        Ok((
            ConfigSource::Args,
            Config {
                psono_settings,
                http_options: self.http_options,
            },
        ))
    }
}

#[derive(Parser, Debug)]
pub struct RawPsonoSettings {
    #[clap(
        long,
        env = "PSONO_CI_API_KEY_ID",
        help = "Api key as uuid",
        required_unless_present_any = ["config_packed", "config_path"]
    )]
    pub api_key_id: Option<Uuid>,
    #[clap(
        long,
        env = "PSONO_CI_API_SECRET_KEY_HEX",
        value_parser = parse_secret_key,
        help = "Api secret key as 64 byte hex string",
        required_unless_present_any = ["config_packed", "config_path"]
    )]
    pub api_secret_key_hex: Option<String>,
    #[clap(
        long,
        env = "PSONO_CI_SERVER_URL",
        value_parser = parse_url,
        help = "Url of the psono backend server",
        required_unless_present_any = ["config_packed", "config_path"]
    )]
    pub server_url: Option<Url>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    #[clap(about = "Psono secret commands (/api-key-access/secret/)")]
    Secret {
        #[clap(subcommand)]
        command: SecretCommand,
    },
    #[clap(about = "Psono api-key inspect (/api-key-access/inspect/)")]
    ApiKey {
        #[clap(subcommand)]
        command: ApiKeyCommand,
    },
    #[clap(about = "Config commands (create, save, pack,...)")]
    Config {
        #[clap(subcommand)]
        command: ConfigCommand,
    },
    #[clap(about = "Spawns processes with environment vars from the api-keys secrets")]
    Run {
        #[clap(flatten)]
        run: RunCommand,
    },
    #[clap(about = "Convenience commands on environment variable secrets")]
    EnvVars {
        #[clap(subcommand)]
        command: EnvVarsCommand,
    },
    #[clap(about = "TOTP commands")]
    Totp {
        #[clap(subcommand)]
        command: TotpCommand,
    },
    #[clap(about = "SSH commands")]
    #[cfg(unix)]
    Ssh {
        #[clap(subcommand)]
        command: SshCommand,
    },
    #[clap(about = "GPG commands")]
    Gpg {
        #[clap(subcommand)]
        command: GpgCommand,
    },
    #[clap(about = "Prints psonoci's license")]
    License,
}

#[derive(Subcommand, Debug)]
pub enum SecretCommand {
    #[clap(about = "Get a psono secret")]
    Get {
        #[clap(required = true, help = "The secret's uuid")]
        secret_id: Uuid,
        #[clap(
            required = true,
            value_enum,
            ignore_case = true,
            help = "Which secret value-type to return ('json' returns all value-types in a json object)"
        )]
        secret_value_type: SecretValueType,
    },
    #[clap(about = "Set a psono secret")]
    Set {
        #[clap(required = true, help = "The secret's uuid")]
        secret_id: Uuid,
        #[clap(
            required = true,
            value_enum,
            ignore_case = true,
            help = "Which secret value-type to set ('json' not yet supported)"
        )]
        secret_value_type: SecretValueType,
        #[clap(required = true, help = "The new value to set for type")]
        secret_new_value: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum ApiKeyCommand {
    #[clap(about = "Prints the meta info of a api-key and lists all its secret ids")]
    Info,
    #[clap(about = "Prints all secrets of an api-key as JSON")]
    Secrets,
}

#[derive(Subcommand, Debug)]
pub enum ConfigCommand {
    #[clap(
        about = "Pack psonoci config into base58 encoded MessagePack string which can be used by --config-packed"
    )]
    Pack,
    #[clap(about = "Save psonoci config into a toml file which can be loaded with --config-path")]
    Save {
        #[clap(
            short,
            long,
            help = "Only if overwrite is set, psonoci will replace a config"
        )]
        overwrite: bool,
        #[clap(required = true, help = "Output path")]
        path: PathBuf,
    },
    #[clap(about = "Displays the current config in toml format")]
    Show,
}

#[derive(Parser, Debug)]
pub struct RunCommand {
    #[clap(
        short,
        long,
        help = "Spawn process only with the env vars from the psono datastore"
    )]
    pub clear_env: bool,
    #[clap(
        short = 'f',
        long,
        name = "secret_uuid",
        help = "Only include env vars from secrets explicitly supplied"
    )]
    pub filter: Option<Vec<Uuid>>,
    #[clap(
        help = "The command you want to run. It's recommended to prefix it with '--' so additional flags won't be interpreted by psonoci"
    )]
    pub command_values: Vec<OsString>,
}

#[derive(Parser, Debug)]
pub struct PasswordCreationSettings {
    #[clap(
        short = 'n',
        long,
        name = "num_chars",
        default_value = "21",
        help = "If a password needs to be created use l chars (unicode graphemes).\nImportant: if you are using unicode chars/graphemes with more than one byte per char, the password byte length will be bigger than the num of chars"
    )]
    pub password_length: usize,
    #[clap(
        short = 'a',
        long,
        name = "allowed_password_chars",
        help = "By default psono uses alphanumeric chars ([a-zA-Z0-9]) for the created passwords.\nThis option overwrites the default charset.\nIMPORTANT: Make sure to supply enough chars, otherwise the password will be insecure."
    )]
    pub danger_password_allowed_chars: Option<String>,
}

impl Default for PasswordCreationSettings {
    fn default() -> Self {
        Self {
            password_length: 21,
            danger_password_allowed_chars: None,
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum EnvVarsCommand {
    #[clap(
        about = "Get or create env var for a specific secret. Will always get the first secret the first secret with the specified name in the env var list"
    )]
    GetOrCreate {
        #[clap(
            required = true,
            help = "The uuid of the secret containing the env var"
        )]
        secret_id: Uuid,
        #[clap(required = true, help = "The name of the env var")]
        env_var_name: String,
        #[clap(flatten)]
        password_creation_settings: PasswordCreationSettings,
    },
    #[clap(
        about = "Update or create env var for a specific secret and then returns the value. Will always update the first secret with the specified name in the env var list. If no new value is supplied, a random value will be created"
    )]
    UpdateOrCreate {
        #[clap(
            required = true,
            help = "The uuid of the secret containing the env var"
        )]
        secret_id: Uuid,
        #[clap(required = true, help = "The name of the env var")]
        env_var_name: String,
        #[clap(
            help = "The value of the env var. If no value is provided, a random one will be created"
        )]
        env_var_value: Option<String>,
        #[clap(flatten)]
        password_creation_settings: PasswordCreationSettings,
    },
}

#[derive(Subcommand, Debug)]
pub enum TotpCommand {
    #[clap(about = "Get the current token for a TOTP secret")]
    GetToken {
        #[clap(
            required = true,
            help = "The uuid of the secret containing the totp data"
        )]
        secret_id: Uuid,
    },
    #[clap(about = "Check if a token is currently valid for a TOTP Secret")]
    ValidateToken {
        #[clap(
            required = true,
            help = "The uuid of the secret containing the totp data"
        )]
        secret_id: Uuid,
        #[clap(required = true, help = "The token to validate")]
        token: String,
    },
    #[clap(about = "Get the otpauth url for a TOTP secret")]
    GetUrl {
        #[clap(
            required = true,
            help = "The uuid of the secret containing the totp data"
        )]
        secret_id: Uuid,
        #[clap(long, help = "TOTP issuer for URL")]
        issuer: Option<String>,
        #[clap(long, help = "TOTP account name for URL")]
        account_name: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum SshCommand {
    Add(SshAddCommand),
}

#[derive(Parser, Debug)]
pub struct SshAddCommand {
    #[clap(
        required = true,
        help = "The uuid of the secret containing the ssh key"
    )]
    pub secret_id: Uuid,

    #[clap(
        long,
        help = "Path of the SSH_AUTH_SOCK (overwrites $SSH_AUTH_SOCK)"
    )]
    pub ssh_auth_sock_path: Option<PathBuf>,

    #[clap(long, help = "Optional passphrase which was used to encrypt the key")]
    pub key_passphrase: Option<String>,

    #[clap(
        long,
        help = "This constraint requests that the agent limit the key's lifetime by deleting it after the specified duration (in seconds) has elapsed from the time the key was added to the agent"
    )]
    pub key_lifetime: Option<u32>,

    #[clap(
        long,
        help = "This constraint requests that the agent require explicit user confirmation for each private key operation using the key"
    )]
    pub key_confirmation: bool,
}

#[derive(Subcommand, Debug)]
pub enum GpgCommand {
    Sign(GpgSignCommand),
    Verify(GpgVerifyCommand),
}

#[derive(Parser, Debug)]
pub struct GpgSignCommand {
    #[clap(
        required = true,
        help = "The uuid of the secret containing the gpg private key"
    )]
    pub secret_id: Uuid,

    #[clap(
        help = "Input file path. If no path is given, reads from stdin"
    )]
    pub input_file: Option<PathBuf>,

    #[clap(
        short = 'o',
        long,
        name = "output path",
        help = "Output file path. If no path is given, writes to stdout"
    )]
    pub output: Option<PathBuf>,

    #[clap(short = 'a', long, help = "Armor the gpg signature")]
    pub armor: bool,
}

#[derive(Parser, Debug)]
pub struct GpgVerifyCommand {
    #[clap(
        required = true,
        help = "The uuid of the secret containing the gpg private key"
    )]
    pub secret_id: Uuid,

    #[clap(
        help = "Input file path. If no path is given, reads from stdin"
    )]
    pub input_file: Option<PathBuf>,

    #[clap(
        short = 's',
        long,
        name = "signature path",
        help = "Signature file path"
    )]
    pub signature: PathBuf,

    #[clap(short = 'q', long, help = "Do not print verification error")]
    pub quiet: bool,

    #[clap(short = 'v', long, help = "Print success message")]
    pub verbose: bool,
}
