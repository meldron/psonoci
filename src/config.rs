use std::fs;
use std::io::Cursor;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use const_format::concatcp;
use rmp_serde::Deserializer as MessagePackDeserializer;
use rmp_serde::Serializer as MessagePackSerializer;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use structopt::StructOpt;
use url::Url;
use uuid::Uuid;

use crate::crypto::parse_secret_key;

static CONFIG_LOADER_BASE58_ERROR: &str = "decoding base58 failed";

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "version")]
pub enum ConfigLoader {
    #[serde(rename = "1")]
    V1(ConfigV1),
}

static CONFIG_DESERIALIZING_MESSAGE_PACK_FAILED: &str = "deserializing message pack failed";

pub fn deserialize_message_pack<O: DeserializeOwned>(raw: &[u8]) -> Result<O> {
    let cursor = Cursor::new(raw);
    let mut d = MessagePackDeserializer::new(cursor);
    Deserialize::deserialize(&mut d).context(CONFIG_DESERIALIZING_MESSAGE_PACK_FAILED)
}

static CONFIG_SERIALIZING_MESSAGE_PACK_FAILED: &str = "serializing to message pack failed";

pub fn serialize_message_pack<I: Serialize>(input: I) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut s = MessagePackSerializer::new(&mut buf);
    input
        .serialize(&mut s)
        .context(CONFIG_SERIALIZING_MESSAGE_PACK_FAILED)?;

    Ok(buf)
}

impl ConfigLoader {
    pub fn from_str(s: &str, format: ConfigSaveFormat) -> Result<Config> {
        let cl: ConfigLoader = match format {
            ConfigSaveFormat::Toml => toml::from_str(s)?,
            // ConfigSaveFormat::JSON => {
            //     todo!()
            // }
            ConfigSaveFormat::MessagePackBase58 => {
                let raw: Vec<u8> = bs58::decode(s)
                    .into_vec()
                    .context(CONFIG_LOADER_BASE58_ERROR)?;
                deserialize_message_pack(&raw)?
            }
        };

        match cl {
            ConfigLoader::V1(config_v1) => Ok(config_v1),
        }
    }

    pub fn load(path: &PathBuf, format: ConfigSaveFormat) -> Result<Config> {
        let raw = fs::read_to_string(path)?;

        ConfigLoader::from_str(&raw, format)
    }
}

#[derive(StructOpt, Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ConfigV1 {
    // psono server options
    #[structopt(flatten)]
    pub psono_settings: PsonoSettings,
    #[structopt(flatten)]
    #[serde(default)]
    pub http_options: HttpOptions,
}

pub type Config = ConfigV1;

pub enum ConfigSaveFormat {
    Toml,
    // JSON,
    MessagePackBase58,
}

impl ConfigV1 {
    pub fn to_string(&self, format: ConfigSaveFormat) -> Result<String> {
        let config_loader = ConfigLoader::V1(self.clone());

        let serialized = match format {
            ConfigSaveFormat::Toml => {
                toml::to_string(&config_loader).context("serializing to toml failed")?
            }
            // ConfigSaveFormat::JSON => {
            //     serde_json::to_string(&config_loader).context("serializing to json failed")?
            // }
            ConfigSaveFormat::MessagePackBase58 => {
                let buf = serialize_message_pack(config_loader)
                    .context("serializing to messagepack failed")?;
                bs58::encode(&buf).into_string()
            }
        };

        Ok(serialized)
    }

    pub fn save(&self, path: &PathBuf, format: ConfigSaveFormat, overwrite: bool) -> Result<()> {
        if path.is_dir() {
            return Err(anyhow!("toml path is a directory"));
        }

        if path.exists() && !overwrite {
            return Err(anyhow!(
                "toml output path already exists and overwrite is not set"
            ));
        }

        let serialized = self.to_string(format)?;

        fs::write(path, serialized).context("writing serialized toml to file failed")?;

        Ok(())
    }
}

pub const DEFAULT_TIMEOUT: usize = 60;
pub const DEFAULT_MAX_REDIRECTS: usize = 0;

fn default_timeout() -> usize {
    DEFAULT_TIMEOUT
}

fn default_as_false() -> bool {
    false
}

#[derive(StructOpt, Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct HttpOptions {
    #[structopt(
        long,
        env = "PSONO_CI_TIMEOUT",
        default_value = concatcp!(DEFAULT_TIMEOUT),
        help = "Connection timeout in seconds"
    )]
    #[serde(default = "default_timeout")]
    pub timeout: usize,
    #[structopt(
        long,
        env = "PSONO_CI_MAX_REDIRECTS",
        default_value = concatcp!(DEFAULT_MAX_REDIRECTS),
        help = "Maximum numbers of redirects"
    )]
    pub max_redirects: usize,

    // TLS options and flags
    #[structopt(
        long,
        help = "Use native TLS implementation (for linux musl builds a vendored openssl is used)"
    )]
    #[serde(default = "default_as_false")]
    pub use_native_tls: bool,
    #[structopt(
        long,
        help = "DANGER: completely disables all TLS (common name and certificate) verification. You should not use this. A better approach is just using plain http so there's no false sense of security (Psono secrets are still authenticated)"
    )]
    #[serde(default = "default_as_false")]
    pub danger_disable_tls_verification: bool,
    #[structopt(
        long,
        env = "PSONO_CI_ADD_DER_ROOT_CERTIFICATE_PATH",
        parse(from_os_str),
        help = "Path to a DER encoded root certificate which should be added to the trust store"
    )]
    pub der_root_certificate_path: Option<PathBuf>,
    #[structopt(
        long,
        env = "PSONO_CI_ADD_PEM_ROOT_CERTIFICATE_PATH",
        parse(from_os_str),
        help = "Path to a pem encoded root certificate which should be added to the trust store"
    )]
    pub pem_root_certificate_path: Option<PathBuf>,
}

impl Default for HttpOptions {
    fn default() -> Self {
        HttpOptions {
            danger_disable_tls_verification: false,
            der_root_certificate_path: None,
            max_redirects: DEFAULT_MAX_REDIRECTS,
            pem_root_certificate_path: None,
            timeout: DEFAULT_TIMEOUT,
            use_native_tls: false,
        }
    }
}

#[derive(StructOpt, Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct PsonoSettings {
    pub api_key_id: Uuid,
    #[serde(deserialize_with = "deserialize_secret_key")]
    pub api_secret_key_hex: String,
    pub server_url: Url,
}

fn deserialize_secret_key<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let buf = String::deserialize(deserializer)?;

    parse_secret_key(&buf).map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    fn debug_config_v1() -> ConfigV1 {
        ConfigV1 {
            psono_settings: PsonoSettings {
                api_key_id: Uuid::from_str("0e1ed23d-cac8-4a04-868b-275bf43b81cd")
                    .expect("api_key_id error"),
                api_secret_key_hex:
                    "acf25040d90e3c73abf1c395e7262bc3b5f9b1e35b96c74dcf72faba4663e98b".to_string(),
                server_url: Url::from_str("https://www.psono.pw/server").expect("serer_url error"),
            },
            http_options: HttpOptions {
                timeout: 60,
                max_redirects: 0,
                use_native_tls: false,
                danger_disable_tls_verification: false,
                der_root_certificate_path: None,
                pem_root_certificate_path: None,
            },
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn parse_config_v1_with_config_loader_from_base58_message_pack__success() {
        let input_debug_config_v1 = "XLZ6owS4rtdgFxsBmWbpxeNhScHsMHJZAaXDrrcTxQK7f1vyomg4jiRW6yoAt1qUzE1qdNzGtMw64hi2kG6qXc4aTHrpikZkYiJLAGe5L1HWfo8deWx761CZapVpkqRT5tZM2jAJjLpbdD74A5XaJoNQq4dGX5LhBpUB8Pi7";
        let target_config = debug_config_v1();

        let config_loader_result =
            ConfigLoader::from_str(input_debug_config_v1, ConfigSaveFormat::MessagePackBase58);
        assert!(config_loader_result.is_ok());

        let config_loader_result = config_loader_result.unwrap();

        assert_eq!(config_loader_result, target_config);
    }

    #[test]
    #[allow(non_snake_case)]
    fn parse_config_v1_with_config_loader_from_base58_message_pack__base58_illegal_char_error() {
        // I is an illegal base58 char
        let input_debug_config_v1 = "IXLZ6owS4rtdgFxsBmWbpxeNhScHsMHJZAaXDrrcTxQK7f1vyomg4jiRW6yoAt1qUzE1qdNzGtMw64hi2kG6qXc4aTHrpikZkYiJLAGe5L1HWfo8deWx761CZapVpkqRT5tZM2jAJjLpbdD74A5XaJoNQq4dGX5LhBpUB8Pi7";

        let config_loader_result =
            ConfigLoader::from_str(input_debug_config_v1, ConfigSaveFormat::MessagePackBase58);
        assert!(config_loader_result.is_err());

        let config_loader_error = config_loader_result.unwrap_err();

        assert_eq!(config_loader_error.to_string(), CONFIG_LOADER_BASE58_ERROR);
    }

    #[test]
    #[allow(non_snake_case)]
    fn parse_config_v1_with_config_loader_from_base58_message_pack__message_pack_deserialize_error()
    {
        // random data encoded as base58 string
        let input_debug_config_v1 =
            "2HUhVoziURdMHEhHpwF5DAx7mdToMn5V2a8DzCNKmCAjVTEAxTzfHKJwPz2RCzEqEUfYR";

        let config_loader_result =
            ConfigLoader::from_str(input_debug_config_v1, ConfigSaveFormat::MessagePackBase58);
        assert!(config_loader_result.is_err());

        let config_loader_error = config_loader_result.unwrap_err();

        println!("{}", config_loader_error);
        assert_eq!(
            config_loader_error.to_string(),
            CONFIG_DESERIALIZING_MESSAGE_PACK_FAILED
        );
    }
}

// impl PsonoSettings {
//     pub fn as_base64(&self) -> Result<String> {
//         let key_raw = hex::decode(&self.api_secret_key_hex)?;

//         let id: &[u8] = self.api_key_id.as_bytes();
//         let key: &[u8] = key_raw.as_slice();
//         let url: &[u8] = self.server_url.as_str().as_bytes();

//         let mut joined: Vec<u8> = Vec::with_capacity(id.len() + key.len() + url.len());
//         joined.extend_from_slice(id);
//         joined.extend_from_slice(key);
//         joined.extend_from_slice(url);

//         let encoded = base64::encode_config(joined, base64::STANDARD_NO_PAD);

//         Ok(encoded)
//     }

//     pub fn from_base64(b: &str) -> Result<Self> {
//         let raw = base64::decode_config(b, base64::STANDARD_NO_PAD).context("decode base64")?;

//         let id_raw = &raw[0..16];
//         let api_key_id = Uuid::from_slice(id_raw)?;

//         let key_raw = &raw[16..(16 + 32)];
//         let api_secret_key_hex = hex::encode(key_raw);

//         let url_raw = &raw[(16 + 32)..];
//         let url_str = std::str::from_utf8(&url_raw).context("url is not valid utf-8")?;
//         let server_url = Url::from_str(url_str).context("url is not a valid url")?;

//         Ok(Self {
//             api_key_id,
//             api_secret_key_hex,
//             server_url,
//         })
//     }
// }
