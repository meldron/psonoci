use std::fmt::Display;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use structopt::StructOpt;
use url::Url;
use uuid::Uuid;

use crate::api::{parse_url, SecretValue};
use crate::config::{Config, ConfigLoader, HttpOptions, PsonoSettings};
use crate::crypto::parse_secret_key;

#[derive(StructOpt, Debug)]
#[structopt(name = "psonoci", about = "Psono ci client")]
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
    #[structopt(about = "psonoci config commands (create, save, pack,...)")]
    Config(ConfigCommand),
}

#[derive(StructOpt, Debug)]
pub enum SecretCommand {
    #[structopt(about = "Get a psono secret by its uuid")]
    Get {
        #[structopt(required = true, help = "The secret's uuid")]
        secret_id: Uuid,
        #[structopt(required = true, possible_values = &SecretValue::variants(), case_insensitive = true, help = "Which secret value-type to return ('json' returns all value-types in a json object)")]
        secret_value: SecretValue,
    },
}

#[derive(StructOpt, Debug)]
pub enum ApiKeyCommand {
    Info,
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
        #[structopt(short, long)]
        overwrite: bool,
        #[structopt(required = true, parse(from_os_str), help = "Output path")]
        path: PathBuf,
    },
    Show,
}
