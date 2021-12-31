use std::ffi::OsString;
use std::fmt::Display;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use structopt::StructOpt;
use url::Url;
use uuid::Uuid;

use crate::api::{parse_url, SecretValueType};
use crate::config::{Config, ConfigLoader, HttpOptions, PsonoSettings};
use crate::crypto::parse_secret_key;

#[derive(StructOpt, Debug)]
#[structopt(name = "psonoci", about = "Psono ci client", author = "Bernd Kaiser")]
pub struct Opt {
    #[structopt(subcommand)]
    pub command: Command,
    #[structopt(flatten)]
    pub raw_config: RawConfig,
}

#[derive(StructOpt, Debug)]
pub struct RawConfig {
    // psono server options
    #[structopt(flatten)]
    pub psono_settings: RawPsonoSettings,
    #[structopt(flatten)]
    pub http_options: HttpOptions,

    #[structopt(
        long,
        name = "config_packed",
        env = "PSONO_CI_CONFIG_PACKED",
        help = "psonci config as packed string"
    )]
    pub config_packed: Option<String>,

    #[structopt(
        short = "c",
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
            ConfigSource::Args => format!("command line args"),
            ConfigSource::File(fp) => format!("--config-path '{}'", fp),
            ConfigSource::Pack => format!("--config-packed"),
        };

        write!(f, "{}", s)
    }
}

impl RawConfig {
    pub fn as_config(self) -> Result<(ConfigSource, Config)> {
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
                ConfigLoader::load(&config_path, crate::config::ConfigSaveFormat::TOML)
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

#[derive(StructOpt, Debug)]
pub struct RawPsonoSettings {
    #[structopt(
        long,
        env = "PSONO_CI_API_KEY_ID",
        help = "Api key as uuid",
        required_unless_one(&["config_packed", "config_path"])
    )]
    pub api_key_id: Option<Uuid>,
    #[structopt(
        long,
        env = "PSONO_CI_API_SECRET_KEY_HEX",
        parse(try_from_str = parse_secret_key),
        help = "Api secret key as 64 byte hex string",
        required_unless_one(&["config_packed", "config_path"])
    )]
    pub api_secret_key_hex: Option<String>,
    #[structopt(
        long,
        env = "PSONO_CI_SERVER_URL",
        parse(try_from_str = parse_url),
        help = "Url of the psono backend server",
        required_unless_one(&["config_packed", "config_path"])
    )]
    pub server_url: Option<Url>,
}

#[derive(StructOpt, Debug)]
pub enum Command {
    #[structopt(about = "Psono secret commands (/api-key-access/secret/)")]
    Secret(SecretCommand),
    #[structopt(about = "Psono api-key inspect (/api-key-access/inspect/)")]
    ApiKey(ApiKeyCommand),
    #[structopt(about = "Config commands (create, save, pack,...)")]
    Config(ConfigCommand),
    #[structopt(about = "Spawns processes with environment vars from the api-keys secrets")]
    Run(RunCommand),
    #[structopt(about = "Convenience commands on environment variable secrets")]
    EnvVars(EnvVarsCommand),
    #[structopt(about = "Prints psonoci's license")]
    License,
}

#[derive(StructOpt, Debug)]
pub enum SecretCommand {
    #[structopt(about = "Get a psono secret")]
    Get {
        #[structopt(required = true, help = "The secret's uuid")]
        secret_id: Uuid,
        #[structopt(required = true, possible_values = &SecretValueType::variants(), case_insensitive = true, help = "Which secret value-type to return ('json' returns all value-types in a json object)")]
        secret_value_type: SecretValueType,
    },
    #[structopt(about = "Set a psono secret")]
    Set {
        #[structopt(required = true, help = "The secret's uuid")]
        secret_id: Uuid,
        #[structopt(required = true, possible_values = &SecretValueType::variants(), case_insensitive = true, help = "Which secret value-type to set ('json' not yet supported)")]
        secret_value_type: SecretValueType,
        #[structopt(required = true, help = "The new value to set for type")]
        secret_new_value: String,
    },
}

#[derive(StructOpt, Debug)]
pub enum ApiKeyCommand {
    #[structopt(about = "Prints the meta info of a api-key and lists all its secret ids")]
    Info,
    #[structopt(about = "Prints all secrets of an api-key as JSON")]
    Secrets,
}

#[derive(StructOpt, Debug)]
pub enum ConfigCommand {
    #[structopt(
        about = "Pack psonoci config into base58 encoded MessagePack string which can be used by --config-packed"
    )]
    Pack,
    #[structopt(
        about = "Save psonoci config into a toml file which can be loaded with --config-path"
    )]
    Save {
        #[structopt(
            short,
            long,
            help = "Only if overwrite is set, psonoci will replace a config"
        )]
        overwrite: bool,
        #[structopt(required = true, parse(from_os_str), help = "Output path")]
        path: PathBuf,
    },
    #[structopt(about = "Displays the current config in toml format")]
    Show,
}

#[derive(StructOpt, Debug)]
pub struct RunCommand {
    #[structopt(
        short,
        long,
        help = "Spawn process only with the env vars from the psono datastore"
    )]
    pub clear_env: bool,
    #[structopt(
        short = "f",
        long,
        name = "secret_uuid",
        help = "Only include env vars from secrets explicitly supplied"
    )]
    pub filter: Option<Vec<Uuid>>,
    #[structopt(
        parse(from_os_str),
        help = "The command you want to run. It's recommended to prefix it with '--' so additional flags won't be interpreted by psonoci"
    )]
    pub command_values: Vec<OsString>,
}

#[derive(StructOpt, Debug)]
pub struct PasswordCreationSettings {
    #[structopt(
        short = "n",
        long,
        name = "num_chars",
        default_value = "21",
        help = "If a password needs to be created use l chars (unicode graphemes).\nImportant: if you are using unicode chars/graphemes with more than one byte per char, the password byte length will be bigger than the num of chars"
    )]
    pub password_length: usize,
    #[structopt(
        short = "a",
        long,
        name = "allowed_password_chars",
        help = "By default psono uses alphanumeric chars ([a-zA-Z0-9]) for the created passwords.\nThis option overwrites the default charset.\nIMPORTANT: Make sure to supply enough chars, otherwise the password will be insecure."
    )]
    pub danger_password_allowed_chars: Option<String>,
}

#[derive(StructOpt, Debug)]
pub enum EnvVarsCommand {
    #[structopt(
        about = "Get or create env var for a specific secret. Will always get the first secret the first secret with the specified name in the env var list"
    )]
    GetOrCreate {
        #[structopt(
            required = true,
            help = "The uuid of the secret containing the env var"
        )]
        secret_id: Uuid,
        #[structopt(required = true, help = "The name of the env var")]
        env_var_name: String,
        #[structopt(flatten)]
        password_creation_settings: PasswordCreationSettings,
    },
    #[structopt(
        about = "Update or create env var for a specific secret. Will always update the first secret with the specified name in the env var list"
    )]
    UpdateOrCreate {
        #[structopt(
            required = true,
            help = "The uuid of the secret containing the env var"
        )]
        secret_id: Uuid,
        #[structopt(required = true, help = "The name of the env var")]
        env_var_name: String,
        #[structopt(required = true, help = "The value of the env var")]
        env_var_value: String,
    },
}
