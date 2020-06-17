use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use attohttpc::Method;
use clap::arg_enum;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::json;
use structopt::StructOpt;
use url::Url;
use uuid::Uuid;

use crate::crypto::{open_secret_box, parse_secret_key};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SecretType {
    Website,
    Application,
    Note,
    GPGKey,
    Bookmark,
}

impl SecretType {
    pub fn as_str(&self) -> &str {
        match self {
            &SecretType::Website => "website",
            &SecretType::Application => "application",
            &SecretType::Note => "note",
            &SecretType::GPGKey => "gpg_key",
            &SecretType::Bookmark => "bookmark",
        }
    }
}

arg_enum! {
    #[derive(Debug)]
    #[allow(non_camel_case_types)]
pub enum SecretValue {
    json,
    notes,
    password,
    title,
    url,
    url_filter,
    username,
    gpg_key_email,
    gpg_key_name,
    gpg_key_private,
    gpg_key_public,
}
}

impl SecretValue {
    pub fn as_str(&self) -> &str {
        match self {
            &SecretValue::json => "json",
            &SecretValue::notes => "notes",
            &SecretValue::password => "password",
            &SecretValue::title => "title",
            &SecretValue::url => "url",
            &SecretValue::url_filter => "url_filter",
            &SecretValue::username => "username",
            &SecretValue::gpg_key_email => "gpg_key_email",
            &SecretValue::gpg_key_name => "gpg_key_name",
            &SecretValue::gpg_key_private => "gpg_key_private",
            &SecretValue::gpg_key_public => "gpg_key_public",
        }
    }
}

fn parse_url(src: &str) -> Result<Url> {
    let url = Url::parse(src)?;

    // validate url
    match url.scheme() {
        "http" => {}
        "https" => {}
        _ => {
            return Err(anyhow!(
                "Url has unsupported scheme (only http & https schemes are supported)"
            ))
        }
    };
    url.host().ok_or(anyhow!("Url has invalid host)"))?;
    url.port_or_known_default()
        .ok_or(anyhow!("Url is missing a port"))?;

    Ok(url)
}

#[derive(StructOpt, Debug)]
pub struct ApiSettings {
    #[structopt(long, env = "PSONO_CI_API_KEY_ID", help = "Api key as uuid")]
    pub api_key_id: Uuid,
    #[structopt(
        long,
        env = "PSONO_CI_API_SECRET_KEY_HEX",
        parse(try_from_str = parse_secret_key),
        help = "Api secret key as 64 byte hex string"
    )]
    pub api_secret_key_hex: String,
    #[structopt(
        long,
        env = "PSONO_CI_SERVER_URL",
        parse(try_from_str = parse_url),
        help = "Url of the psono backend server"
    )]
    pub server_url: Url,
    #[structopt(
        long,
        env = "PSONO_CI_TIMEOUT",
        default_value = "60",
        help = "Connection timeout in seconds"
    )]
    pub timeout: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Endpoint {
    ApiKeyAccessSecret,
}

impl Endpoint {
    pub fn as_str(&self) -> &str {
        match self {
            &Endpoint::ApiKeyAccessSecret => "/api-key-access/secret/",
        }
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GenericSecret {
    // website password
    pub website_password_url_filter: Option<String>,
    pub website_password_notes: Option<String>,
    pub website_password_password: Option<String>,
    pub website_password_username: Option<String>,
    pub website_password_url: Option<String>,
    pub website_password_title: Option<String>,

    // application password
    pub application_password_notes: Option<String>,
    pub application_password_password: Option<String>,
    pub application_password_username: Option<String>,
    pub application_password_title: Option<String>,

    // bookmark
    pub bookmark_url_filter: Option<String>,
    pub bookmark_notes: Option<String>,
    pub bookmark_url: Option<String>,
    pub bookmark_title: Option<String>,

    // mail gpg key
    pub mail_gpg_own_key_private: Option<String>,
    pub mail_gpg_own_key_public: Option<String>,
    pub mail_gpg_own_key_name: Option<String>,
    pub mail_gpg_own_key_email: Option<String>,
    pub mail_gpg_own_key_title: Option<String>,

    // notes
    pub note_notes: Option<String>,
    pub note_title: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Secret {
    pub url_filter: Option<String>,
    pub notes: Option<String>,
    pub password: Option<String>,
    pub username: Option<String>,
    pub url: Option<String>,
    pub title: Option<String>,
    pub secret_type: SecretType,

    pub gpg_key_private: Option<String>,
    pub gpg_key_public: Option<String>,
    pub gpg_key_name: Option<String>,
    pub gpg_key_email: Option<String>,
}

impl Secret {
    pub fn as_json(&self) -> Option<String> {
        let value_raw = json!({
            "title": &self.title,
            "username": &self.username,
            "password": &self.password,
            "notes": &self.notes,
            "url": &self.url,
            "url_filter": &self.url_filter,
            "gpg_key_email": &self.gpg_key_email,
            "gpg_key_name": &self.gpg_key_name,
            "gpg_key_private": &self.gpg_key_private,
            "gpg_key_public": &self.gpg_key_public,
            "type": &self.secret_type.as_str(),
        });

        serde_json::to_string(&value_raw).ok()
    }

    pub fn get_value(self, value: &SecretValue) -> Option<String> {
        match value {
            SecretValue::json => self.as_json(),
            SecretValue::notes => self.notes,
            SecretValue::password => self.password,
            SecretValue::title => self.title,
            SecretValue::url => self.url,
            SecretValue::url_filter => self.url_filter,
            SecretValue::username => self.username,
            SecretValue::gpg_key_email => self.gpg_key_email,
            SecretValue::gpg_key_name => self.gpg_key_name,
            SecretValue::gpg_key_private => self.gpg_key_private,
            SecretValue::gpg_key_public => self.gpg_key_public,
        }
    }

    pub fn from_generic_secret(s: GenericSecret) -> Result<Self> {
        if s.application_password_notes.is_some()
            || s.application_password_password.is_some()
            || s.application_password_username.is_some()
            || s.application_password_title.is_some()
        {
            return Ok(Secret {
                gpg_key_email: None,
                gpg_key_name: None,
                gpg_key_private: None,
                gpg_key_public: None,
                notes: s.application_password_notes,
                password: s.application_password_password,
                secret_type: SecretType::Application,
                title: s.application_password_title,
                url: None,
                url_filter: None,
                username: s.application_password_username,
            });
        }

        if s.website_password_notes.is_some()
            || s.website_password_password.is_some()
            || s.website_password_title.is_some()
            || s.website_password_url.is_some()
            || s.website_password_url_filter.is_some()
            || s.website_password_username.is_some()
        {
            return Ok(Secret {
                gpg_key_email: None,
                gpg_key_name: None,
                gpg_key_private: None,
                gpg_key_public: None,
                notes: s.website_password_notes,
                password: s.website_password_password,
                secret_type: SecretType::Website,
                title: s.website_password_title,
                url: s.website_password_url,
                url_filter: s.website_password_url_filter,
                username: s.website_password_username,
            });
        }

        if s.bookmark_url_filter.is_some()
            || s.bookmark_notes.is_some()
            || s.bookmark_url.is_some()
            || s.bookmark_title.is_some()
        {
            return Ok(Secret {
                gpg_key_email: None,
                gpg_key_name: None,
                gpg_key_private: None,
                gpg_key_public: None,
                notes: s.bookmark_notes,
                password: None,
                secret_type: SecretType::Bookmark,
                title: s.bookmark_title,
                url: s.bookmark_url,
                url_filter: s.bookmark_url_filter,
                username: None,
            });
        }

        if s.note_notes.is_some() || s.note_title.is_some() {
            return Ok(Secret {
                gpg_key_email: None,
                gpg_key_name: None,
                gpg_key_private: None,
                gpg_key_public: None,
                notes: s.note_notes,
                password: None,
                secret_type: SecretType::Note,
                title: s.note_title,
                url: None,
                url_filter: None,
                username: None,
            });
        }

        if s.mail_gpg_own_key_private.is_some()
            || s.mail_gpg_own_key_public.is_some()
            || s.mail_gpg_own_key_name.is_some()
            || s.mail_gpg_own_key_email.is_some()
            || s.mail_gpg_own_key_title.is_some()
        {
            return Ok(Secret {
                gpg_key_email: s.mail_gpg_own_key_email,
                gpg_key_name: s.mail_gpg_own_key_name,
                gpg_key_private: s.mail_gpg_own_key_private,
                gpg_key_public: s.mail_gpg_own_key_public,
                notes: None,
                password: None,
                secret_type: SecretType::GPGKey,
                title: s.mail_gpg_own_key_title,
                url: None,
                url_filter: None,
                username: None,
            });
        }

        Err(anyhow!("unsupported secret type"))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Request<T> {
    pub method: Method,
    pub endpoint: Endpoint,
    pub body: T,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecretRequestBody {
    pub api_key_id: String,
    pub secret_id: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecretResponse {
    pub data: String,
    pub data_nonce: String,
    pub secret_key: String,
    pub secret_key_nonce: String,
}

impl SecretResponse {
    pub fn open(&self, api_key_secret_key_hex: &str) -> Result<Secret> {
        let encryption_key_raw = open_secret_box(
            &self.secret_key,
            &self.secret_key_nonce,
            api_key_secret_key_hex,
        )
        .context("decrypting secret key failed")?
        .to_owned();

        let encryption_key = std::str::from_utf8(&encryption_key_raw)
            .context("decrypted secret key is not valid utf-8")?;

        let secret_raw = open_secret_box(&self.data, &self.data_nonce, &encryption_key)
            .context("decrypting secret failed")?;

        let generic_secret: GenericSecret = serde_json::from_slice(&secret_raw)
            .context("parsing generic secret from json failed")?;

        let secret = Secret::from_generic_secret(generic_secret)
            .context("transforming generic secret into specific secret failed")?;

        Ok(secret)
    }
}

pub fn call<T, U>(settings: &ApiSettings, request: Request<T>) -> Result<U>
where
    T: Serialize,
    U: DeserializeOwned,
{
    let url = format!(
        "{}/{}",
        settings.server_url,
        request.endpoint.as_str().to_owned()
    );
    let url_parsed = Url::parse(&url).context("url parsing error")?;

    let response = attohttpc::post(url_parsed)
        .header("user-agent", "psonoci")
        .timeout(Duration::from_secs(settings.timeout))
        .json(&request.body)
        .context("call body json serialization failed")?
        .send()
        .context("http(s) request failed")?;

    if !response.is_success() {
        return Err(anyhow!("{}", response.status()));
    }

    let body_raw = response.bytes().context("read response body failed")?;

    let body: U = serde_json::from_slice(body_raw.as_ref())
        .context("response body json deserialization failed")?;

    Ok(body)
}

pub fn get_secret(secret_id: &Uuid, settings: &ApiSettings) -> Result<Secret> {
    let body = SecretRequestBody {
        api_key_id: settings
            .api_key_id
            .to_hyphenated()
            .to_string()
            .to_lowercase(),
        secret_id: secret_id.to_hyphenated().to_string().to_lowercase(),
    };

    let request = Request {
        method: Method::POST,
        endpoint: Endpoint::ApiKeyAccessSecret,
        body,
    };

    let secret_response: SecretResponse =
        call(settings, request).context("get secret api call failed")?;

    let secret = secret_response
        .open(&settings.api_secret_key_hex)
        .context("get secret decryption failed")?;

    Ok(secret)
}
