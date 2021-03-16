use std::collections::HashMap;
use std::fmt::Debug;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
// use attohttpc::Method;
use clap::arg_enum;
use rayon::prelude::*;
use reqwest::blocking::{Client, ClientBuilder};
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE, USER_AGENT};
use reqwest::redirect::Policy;
use reqwest::Certificate;
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::json;
use url::Url;
use uuid::Uuid;

use crate::config::{Config, HttpOptions};
use crate::crypto::{create_nonce_hex, open_secret_box, seal_secret_box_hex};

static USER_AGENT_NAME: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

static CERTIFICATE_ERROR_DECODE: &str = "could not decode certificate";
static CERTIFICATE_ERROR_OPEN: &str = "could not open certificate";
static CERTIFICATE_ERROR_READ: &str = "could not read certificate";

static SECRET_KEY_SET_WITH_JSON_NOT_YET_SUPPORTED: &str = "setting with JSON is not yet supported";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SecretType {
    Website,
    Application,
    Note,
    GPGKey,
    Bookmark,
    EnvVars,
}

impl SecretType {
    pub fn as_str(&self) -> &str {
        match self {
            SecretType::Website => "website",
            SecretType::Application => "application",
            SecretType::Note => "note",
            SecretType::GPGKey => "gpg_key",
            SecretType::Bookmark => "bookmark",
            SecretType::EnvVars => "env_vars",
        }
    }
}

arg_enum! {
    #[derive(Debug)]
    #[allow(non_camel_case_types)]
pub enum SecretValueType {
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
    secret_type,
    env_vars,
}
}

impl SecretValueType {
    pub fn as_str(&self) -> &str {
        match self {
            SecretValueType::json => "json",
            SecretValueType::notes => "notes",
            SecretValueType::password => "password",
            SecretValueType::title => "title",
            SecretValueType::url => "url",
            SecretValueType::url_filter => "url_filter",
            SecretValueType::username => "username",
            SecretValueType::gpg_key_email => "gpg_key_email",
            SecretValueType::gpg_key_name => "gpg_key_name",
            SecretValueType::gpg_key_private => "gpg_key_private",
            SecretValueType::gpg_key_public => "gpg_key_public",
            SecretValueType::secret_type => "type",
            SecretValueType::env_vars => "env_vars",
        }
    }
}

const PARSE_URL_ERROR_INVALID_SCHEME: &str =
    "Url has unsupported scheme (only http & https schemes are supported)";

pub fn parse_url(src: &str) -> Result<Url> {
    let url = Url::parse(src)?;

    // validate url
    match url.scheme() {
        "http" => {}
        "https" => {}
        _ => return Err(anyhow!(PARSE_URL_ERROR_INVALID_SCHEME)),
    };
    url.host().ok_or_else(|| anyhow!("Url has invalid host)"))?;
    url.port_or_known_default()
        .ok_or_else(|| anyhow!("Url is missing a port"))?;

    Ok(url)
}

enum CertificateEncoding {
    DER,
    PEM,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Endpoint {
    ApiKeyAccessSecret,
    ApiKeyInspect,
}

impl Endpoint {
    pub fn as_str(&self) -> &str {
        match self {
            Endpoint::ApiKeyAccessSecret => "/api-key-access/secret/",
            Endpoint::ApiKeyInspect => "/api-key-access/inspect/",
        }
    }
}

pub trait DataTransform<T, U>: Sized
where
    T: DeserializeOwned,
{
    fn transform(s: T) -> Result<U>;
}

#[derive(Debug, Clone, PartialEq)]
pub struct Route<T> {
    pub method: Method,
    pub endpoint: Endpoint,
    pub body: T,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EncryptedResponse {
    pub data: String,
    pub data_nonce: String,
    pub secret_key: String,
    pub secret_key_nonce: String,
}

impl EncryptedResponse {
    pub fn open<I, O>(&self, api_key_secret_key_hex: &str) -> Result<(O, String)>
    where
        I: DeserializeOwned + Debug,
        O: DataTransform<I, O> + Debug,
    {
        let encryption_key_raw = open_secret_box(
            &self.secret_key,
            &self.secret_key_nonce,
            api_key_secret_key_hex,
        )
        .context("decrypting secret key failed")?;

        let encryption_key = std::str::from_utf8(&encryption_key_raw)
            .context("decrypted secret key is not valid utf-8")?;

        let encrypted_raw = open_secret_box(&self.data, &self.data_nonce, &encryption_key)
            .context("decrypting secret failed")?;

        let input: I = serde_json::from_slice(&encrypted_raw)
            .context("parsing generic response from json failed")?;

        let output = O::transform(input).context("transforming input into output failed")?;

        Ok((output, encryption_key.to_owned()))
    }
}

fn load_root_certificate(encoding: CertificateEncoding, path: &PathBuf) -> Result<Certificate> {
    let mut buf = Vec::new();
    File::open(path)
        .context(CERTIFICATE_ERROR_OPEN)?
        .read_to_end(&mut buf)
        .context(CERTIFICATE_ERROR_READ)?;

    let cert_result = match encoding {
        CertificateEncoding::DER => Certificate::from_der(&buf),
        CertificateEncoding::PEM => Certificate::from_pem(&buf),
    };

    let cert = cert_result.context(CERTIFICATE_ERROR_DECODE)?;

    Ok(cert)
}

pub fn make_request(
    http_options: &HttpOptions,
    url: Url,
    method: Method,
    json_body: Option<String>,
) -> Result<Vec<u8>> {
    let redirect_policy: Policy = match http_options.max_redirects {
        0 => Policy::none(),
        _ => Policy::limited(http_options.max_redirects as usize),
    };

    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static(USER_AGENT_NAME));

    let mut client_builder: ClientBuilder = Client::builder()
        .redirect(redirect_policy)
        .timeout(Duration::from_secs(http_options.timeout as u64));

    if http_options.der_root_certificate_path.is_some() {
        let cert_der_path = http_options.der_root_certificate_path.as_ref().unwrap();
        let cert_der = load_root_certificate(CertificateEncoding::DER, cert_der_path)
            .context("adding DER root certificate failed")?;
        client_builder = client_builder.add_root_certificate(cert_der);
    }

    if http_options.pem_root_certificate_path.is_some() {
        let cert_pem_path = http_options.pem_root_certificate_path.as_ref().unwrap();
        let cert_pem = load_root_certificate(CertificateEncoding::PEM, cert_pem_path)
            .context("adding PEM root certificate failed")?;
        client_builder = client_builder.add_root_certificate(cert_pem);
    }

    // we always use native-tls for making dangerous calls
    // because right now rust-tls cannot handle all of them
    if http_options.use_native_tls || http_options.danger_disable_tls_verification {
        client_builder = client_builder
            .use_native_tls()
            .danger_accept_invalid_certs(http_options.danger_disable_tls_verification)
            .danger_accept_invalid_hostnames(http_options.danger_disable_tls_verification);
    } else {
        client_builder = client_builder.use_rustls_tls();
    }

    let client = client_builder
        .build()
        .context("building reqwest client failed")?;

    let mut request_builder = client.request(method, url);

    if let Some(body) = json_body {
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        request_builder = request_builder.body(body);
    }

    let response = request_builder
        .headers(headers)
        .send()
        .context("request failed")?;

    let status = response.status();

    if !status.is_success() {
        let reason = status.canonical_reason().unwrap_or("unknown").to_owned();
        return Err(anyhow!("{}: {}", response.status(), reason));
    }

    let body_raw = response.bytes().context("read response body failed")?;

    let vec = body_raw.to_vec();

    Ok(vec)
}

fn call_route<T>(server_url: &Url, http_options: &HttpOptions, route: Route<T>) -> Result<Vec<u8>>
where
    T: Serialize,
{
    let url = format!("{}/{}", server_url, route.endpoint.as_str());
    let url_parsed = Url::parse(&url).context("url parsing error")?;

    let body = serde_json::to_string(&route.body)?;

    let response_raw: Vec<u8> = make_request(http_options, url_parsed, route.method, Some(body))
        .context("make request failed")?;

    Ok(response_raw)
}

fn call_route_deserialize_response<T, U>(
    server_url: &Url,
    http_options: &HttpOptions,
    route: Route<T>,
) -> Result<U>
where
    T: Serialize,
    U: DeserializeOwned,
{
    let response_raw: Vec<u8> = call_route(server_url, http_options, route)?;
    let body: U = serde_json::from_slice(response_raw.as_ref())
        .context("response body json deserialization failed")?;

    Ok(body)
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GetSecretRequestBody {
    pub api_key_id: String,
    pub secret_id: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SetSecretRequestBody {
    pub api_key_id: String,
    pub secret_id: String,
    pub data: String,
    pub data_nonce: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnvironmentVariable {
    pub key: String,
    pub value: String,
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

    // environment variables
    pub environment_variables_title: Option<String>,
    pub environment_variables_notes: Option<String>,
    pub environment_variables_variables: Option<Vec<EnvironmentVariable>>,
}

impl GenericSecret {
    pub fn new() -> Self {
        GenericSecret {
            application_password_notes: None,
            application_password_password: None,
            application_password_title: None,
            application_password_username: None,
            bookmark_notes: None,
            bookmark_title: None,
            bookmark_url: None,
            bookmark_url_filter: None,
            mail_gpg_own_key_email: None,
            mail_gpg_own_key_name: None,
            mail_gpg_own_key_private: None,
            mail_gpg_own_key_public: None,
            mail_gpg_own_key_title: None,
            note_notes: None,
            note_title: None,
            website_password_notes: None,
            website_password_password: None,
            website_password_title: None,
            website_password_url: None,
            website_password_url_filter: None,
            website_password_username: None,
            environment_variables_notes: None,
            environment_variables_title: None,
            environment_variables_variables: None,
        }
    }
}

// pub trait PsonoSecret: Sized {
//     fn from_generic_secret(s: &GenericSecret) -> Result<Self>;

//     fn as_json_string(&self) -> Result<String>;

//     fn get_secret_value(&self, value: SecretValueType) -> Result<String>;
// }

// #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
// pub struct WebsiteSecret {
//     pub url_filter: String,
//     pub notes: String,
//     pub password: String,
//     pub username: String,
//     pub url: String,
//     pub title: String,
// }

// impl PsonoSecret for WebsiteSecret {
//     fn from_generic_secret(s: &GenericSecret) -> Result<Self> {
//         if s.website_password_notes.is_some()
//             || s.website_password_password.is_some()
//             || s.website_password_title.is_some()
//             || s.website_password_url.is_some()
//             || s.website_password_url_filter.is_some()
//             || s.website_password_username.is_some()
//         {
//             return Ok(WebsiteSecret {
//                 notes: s.website_password_notes.clone().unwrap(),
//                 password: s.website_password_password.clone().unwrap(),
//                 title: s.website_password_title.clone().unwrap(),
//                 url: s.website_password_url.clone().unwrap(),
//                 url_filter: s.website_password_url_filter.clone().unwrap(),
//                 username: s.website_password_username.clone().unwrap(),
//             });
//         } else {
//             return Err(anyhow!("not a website secret"));
//         }
//     }

//     fn as_json_string(&self) -> Result<String> {
//         serde_json::to_string(&self).map_err(|e| anyhow!(e))
//     }

//     fn get_secret_value(&self, value: SecretValueType) -> Result<String> {
//         // match value {
//         //     SecretValueType::json => Ok(self.as_json_string()?),
//         //     SecretValueType::notes => Ok(self.notes.clone()),
//         //     SecretValueType::password => {}
//         //     SecretValueType::title => {}
//         //     SecretValueType::url => {}
//         //     SecretValueType::url_filter => {}
//         //     SecretValueType::username => {}
//         //     SecretValueType::secret_type => {}
//         //     _ => Err(anyhow!(
//         //         "{} is not available in a {:?} secret",
//         //         value,
//         //         SecretValueTypeType::Website
//         //     )),
//         // }
//         todo!()
//     }
// }

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

    pub env_vars: Option<Vec<EnvironmentVariable>>,
}

impl Secret {
    pub fn as_generic_secret(&self) -> GenericSecret {
        let mut gs = GenericSecret::new();

        match self.secret_type {
            SecretType::Website => {
                gs.website_password_notes = self.notes.clone();
                gs.website_password_password = self.password.clone();
                gs.website_password_title = self.title.clone();
                gs.website_password_url = self.url.clone();
                gs.website_password_url_filter = self.url_filter.clone();
                gs.website_password_username = self.username.clone();
            }
            SecretType::Application => {
                gs.application_password_notes = self.notes.clone();
                gs.application_password_password = self.password.clone();
                gs.application_password_title = self.title.clone();
                gs.application_password_username = self.username.clone();
            }
            SecretType::Note => {
                gs.note_notes = self.notes.clone();
                gs.note_title = self.title.clone();
            }
            SecretType::GPGKey => {
                gs.mail_gpg_own_key_email = self.gpg_key_email.clone();
                gs.mail_gpg_own_key_name = self.gpg_key_name.clone();
                gs.mail_gpg_own_key_private = self.gpg_key_private.clone();
                gs.mail_gpg_own_key_public = self.gpg_key_public.clone();
                gs.mail_gpg_own_key_title = self.title.clone();
            }
            SecretType::Bookmark => {
                gs.bookmark_notes = self.notes.clone();
                gs.bookmark_title = self.title.clone();
                gs.bookmark_url = self.url.clone();
                gs.bookmark_url_filter = self.url_filter.clone();
            }
            SecretType::EnvVars => {
                gs.environment_variables_notes = self.notes.clone();
                gs.environment_variables_title = self.title.clone();
                gs.environment_variables_variables = self.env_vars.clone();
            }
        }

        gs
    }

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
            "env_vars": &self.env_vars,
            "type": &self.secret_type.as_str(),
        });

        serde_json::to_string(&value_raw).ok()
    }

    pub fn get_value(self, value: &SecretValueType) -> Option<String> {
        match value {
            SecretValueType::json => self.as_json(),
            SecretValueType::notes => self.notes,
            SecretValueType::password => self.password,
            SecretValueType::title => self.title,
            SecretValueType::url => self.url,
            SecretValueType::url_filter => self.url_filter,
            SecretValueType::username => self.username,
            SecretValueType::gpg_key_email => self.gpg_key_email,
            SecretValueType::gpg_key_name => self.gpg_key_name,
            SecretValueType::gpg_key_private => self.gpg_key_private,
            SecretValueType::gpg_key_public => self.gpg_key_public,
            SecretValueType::secret_type => Some(self.secret_type.as_str().to_owned()),
            SecretValueType::env_vars => self
                .env_vars
                .map(|v| serde_json::to_string(&v).ok())
                .flatten(),
        }
    }

    pub fn set_value(&mut self, secret_value_type: &SecretValueType, value: String) -> Result<()> {
        match (&self.secret_type, secret_value_type) {
            // WEBSITE
            (SecretType::Website, SecretValueType::json) => {
                return Err(anyhow!(SECRET_KEY_SET_WITH_JSON_NOT_YET_SUPPORTED))
            }
            (SecretType::Website, SecretValueType::notes) => self.notes = Some(value),
            (SecretType::Website, SecretValueType::password) => self.password = Some(value),
            (SecretType::Website, SecretValueType::title) => self.title = Some(value),
            (SecretType::Website, SecretValueType::url) => self.url = Some(value),
            (SecretType::Website, SecretValueType::url_filter) => self.url_filter = Some(value),
            (SecretType::Website, SecretValueType::username) => self.username = Some(value),
            // APPLICATION
            (SecretType::Application, SecretValueType::json) => {
                return Err(anyhow!(SECRET_KEY_SET_WITH_JSON_NOT_YET_SUPPORTED))
            }
            (SecretType::Application, SecretValueType::notes) => self.notes = Some(value),
            (SecretType::Application, SecretValueType::password) => self.password = Some(value),
            (SecretType::Application, SecretValueType::title) => self.title = Some(value),
            (SecretType::Application, SecretValueType::username) => self.username = Some(value),
            // NOTE
            (SecretType::Note, SecretValueType::json) => {
                return Err(anyhow!(SECRET_KEY_SET_WITH_JSON_NOT_YET_SUPPORTED))
            }
            (SecretType::Note, SecretValueType::notes) => self.notes = Some(value),
            (SecretType::Note, SecretValueType::title) => self.title = Some(value),
            // GPGKey
            (SecretType::GPGKey, SecretValueType::json) => {
                return Err(anyhow!(SECRET_KEY_SET_WITH_JSON_NOT_YET_SUPPORTED))
            }
            (SecretType::GPGKey, SecretValueType::title) => self.title = Some(value),
            (SecretType::GPGKey, SecretValueType::gpg_key_email) => {
                self.gpg_key_email = Some(value)
            }
            (SecretType::GPGKey, SecretValueType::gpg_key_name) => self.gpg_key_name = Some(value),
            (SecretType::GPGKey, SecretValueType::gpg_key_private) => {
                self.gpg_key_private = Some(value)
            }
            (SecretType::GPGKey, SecretValueType::gpg_key_public) => {
                self.gpg_key_public = Some(value)
            }
            // Bookmark
            (SecretType::Bookmark, SecretValueType::json) => {
                return Err(anyhow!(SECRET_KEY_SET_WITH_JSON_NOT_YET_SUPPORTED))
            }
            (SecretType::Bookmark, SecretValueType::notes) => self.notes = Some(value),
            (SecretType::Bookmark, SecretValueType::title) => self.title = Some(value),
            (SecretType::Bookmark, SecretValueType::url) => self.url = Some(value),
            (SecretType::Bookmark, SecretValueType::url_filter) => self.url_filter = Some(value),
            // EnvVars
            // TODO add env var settings
            (SecretType::EnvVars, SecretValueType::json) => {
                return Err(anyhow!(SECRET_KEY_SET_WITH_JSON_NOT_YET_SUPPORTED))
            }
            (SecretType::EnvVars, SecretValueType::title) => self.title = Some(value),
            (SecretType::EnvVars, SecretValueType::notes) => self.notes = Some(value),
            (SecretType::EnvVars, SecretValueType::env_vars) => {
                let env_vars: Vec<EnvironmentVariable> = serde_json::from_str(&value)
                    .context("env_vars could not be decoded from json")?;
                self.env_vars = Some(env_vars);
            }
            (_, _) => {
                return Err(anyhow!(
                    "cannot set {:?} for {:?}",
                    secret_value_type,
                    self.secret_type
                ))
            }
        }

        Ok(())
    }
}

impl DataTransform<GenericSecret, Secret> for Secret {
    fn transform(s: GenericSecret) -> Result<Self> {
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
                env_vars: None,
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
                env_vars: None,
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
                env_vars: None,
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
                env_vars: None,
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
                env_vars: None,
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

        if s.environment_variables_notes.is_some()
            || s.environment_variables_title.is_some()
            || s.environment_variables_variables.is_some()
        {
            return Ok(Secret {
                env_vars: s.environment_variables_variables,
                gpg_key_email: None,
                gpg_key_name: None,
                gpg_key_private: None,
                gpg_key_public: None,
                notes: s.environment_variables_notes,
                password: None,
                secret_type: SecretType::EnvVars,
                title: s.environment_variables_title,
                url: None,
                url_filter: None,
                username: None,
            });
        }

        Err(anyhow!("unsupported secret type"))
    }
}

pub fn get_secret(secret_id: &Uuid, config: &Config) -> Result<(Secret, String)> {
    let body = GetSecretRequestBody {
        api_key_id: config
            .psono_settings
            .api_key_id
            .to_hyphenated()
            .to_string()
            .to_lowercase(),
        secret_id: secret_id.to_hyphenated().to_string().to_lowercase(),
    };

    let request = Route {
        method: Method::POST,
        endpoint: Endpoint::ApiKeyAccessSecret,
        body,
    };

    let psono_response: EncryptedResponse = call_route_deserialize_response(
        &config.psono_settings.server_url,
        &config.http_options,
        request,
    )
    .context("get secret api call failed")?;

    let (secret, secret_key_hex) = psono_response
        .open::<GenericSecret, Secret>(&config.psono_settings.api_secret_key_hex)
        .context("get secret decryption failed")?;

    Ok((secret, secret_key_hex))
}

pub fn set_secret(
    secret_id: &Uuid,
    config: &Config,
    secret: &Secret,
    secret_key_hex: &str,
) -> Result<()> {
    let nonce_hex = create_nonce_hex();
    let generic_secret = secret.as_generic_secret();
    let plaintext = serde_json::to_string(&generic_secret).context("serializing secret failed")?;

    let secret_encrypted_hex =
        seal_secret_box_hex(plaintext.as_bytes(), &nonce_hex, secret_key_hex)
            .context("encrypting secret failed")?;

    let body = SetSecretRequestBody {
        api_key_id: config
            .psono_settings
            .api_key_id
            .to_hyphenated()
            .to_string()
            .to_lowercase(),
        secret_id: secret_id.to_hyphenated().to_string().to_lowercase(),
        data: secret_encrypted_hex,
        data_nonce: nonce_hex,
    };

    let request = Route {
        method: Method::PUT,
        endpoint: Endpoint::ApiKeyAccessSecret,
        body,
    };

    call_route(
        &config.psono_settings.server_url,
        &config.http_options,
        request,
    )
    .context("set secret api call failed")?;

    Ok(())
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InspectApiKeyRequest {
    pub api_key_id: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeySecret {
    #[serde(rename = "secret_id")]
    pub secret_id: Uuid,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InspectApiKeyResponse {
    pub allow_insecure_access: bool,
    pub restrict_to_secrets: bool,
    pub read: bool,
    pub write: bool,
    pub api_key_secrets: Vec<ApiKeySecret>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApiKeyInfo {
    pub allow_insecure_access: bool,
    pub restrict_to_secrets: bool,
    pub read: bool,
    pub write: bool,
    pub num_api_key_secrets: usize,
    pub api_key_secrets: Vec<Uuid>,
}

impl ApiKeyInfo {
    pub fn from_inspect_api_key_response(r: InspectApiKeyResponse) -> Self {
        let api_key_secrets: Vec<Uuid> =
            r.api_key_secrets.into_iter().map(|s| s.secret_id).collect();
        let num_api_key_secrets = api_key_secrets.len();

        Self {
            allow_insecure_access: r.allow_insecure_access,
            api_key_secrets,
            num_api_key_secrets,
            read: r.read,
            restrict_to_secrets: r.restrict_to_secrets,
            write: r.write,
        }
    }
}

pub fn api_key_info(config: &Config) -> Result<ApiKeyInfo> {
    let body = InspectApiKeyRequest {
        api_key_id: config
            .psono_settings
            .api_key_id
            .to_hyphenated()
            .to_string()
            .to_lowercase(),
    };

    let request = Route {
        method: Method::POST,
        endpoint: Endpoint::ApiKeyInspect,
        body,
    };

    let response: InspectApiKeyResponse = call_route_deserialize_response(
        &config.psono_settings.server_url,
        &config.http_options,
        request,
    )
    .context("inspect api call failed")?;

    let api_key_info = ApiKeyInfo::from_inspect_api_key_response(response);

    Ok(api_key_info)
}

pub fn api_key_get_secrets(config: &Config) -> Result<HashMap<Uuid, Secret>> {
    let api_key_info = api_key_info(&config).context("inspect api key call failed")?;

    api_key_info
        .api_key_secrets
        .into_par_iter()
        .map(|id| {
            Ok((
                id,
                get_secret(&id, &config)
                    .context(format!("get secret for {} failed", &id))?
                    .0,
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use lazy_static::lazy_static;

    use super::*;
    use crate::config::PsonoSettings;

    static BAD_SSL_UNTRUSTED_ROOT_URL: &str = "https://untrusted-root.badssl.com/";
    static BAD_SSL_EXPIRED_URL: &str = "https://expired.badssl.com/";

    lazy_static! {
        static ref BAD_SSL_UNTRUSTED_CA_PEM_CERT_PATHS: Vec<&'static str> =
            vec!["test_files", "untrusted-root.badssl.com_ca.pem"];
    }

    pub fn debug_psono_settings() -> PsonoSettings {
        PsonoSettings {
            api_key_id: Uuid::parse_str("d65eda03-2362-498e-b9d6-8b34025572ab")
                .expect("debug uuid parsing failed"),
            api_secret_key_hex: "dc6e4d49390041e6ac6e96493aac300fa7327f9d6d71b58cd161ea17da164fbf"
                .to_string(),
            server_url: Url::parse("https://psono.pw/server").expect("debug url parsing failed"),
        }
    }

    pub fn debug_http_options() -> HttpOptions {
        HttpOptions {
            danger_disable_tls_verification: false,
            der_root_certificate_path: None,
            max_redirects: 0,
            pem_root_certificate_path: None,
            timeout: 60,
            use_native_tls: false,
        }
    }

    pub fn get_bad_ssl_cert_path() -> PathBuf {
        let mut cert_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

        BAD_SSL_UNTRUSTED_CA_PEM_CERT_PATHS
            .iter()
            .for_each(|p| cert_path.push(*p));

        cert_path
    }

    #[allow(dead_code)]
    pub fn debug_api_settings() -> Config {
        Config {
            psono_settings: debug_psono_settings(),
            http_options: debug_http_options(),
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn parse_url__valid__url() {
        let result = parse_url("https://psono.pw/server");

        assert!(result.is_ok());

        let url = result.unwrap();

        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("psono.pw"));
        assert_eq!(url.port(), None);
        assert_eq!(url.path(), "/server");
    }

    #[test]
    #[allow(non_snake_case)]
    fn parse_url__invalid_scheme() {
        let result = parse_url("ftp://psono.pw/server");

        assert!(result.is_err());

        assert_eq!(
            result.unwrap_err().to_string().as_str(),
            PARSE_URL_ERROR_INVALID_SCHEME
        );
    }

    #[test]
    #[allow(non_snake_case)]
    fn parse_url__invalid_port() {
        let result = parse_url("https://psono.pw:66000/server");

        assert!(result.is_err());

        assert_eq!(
            result.unwrap_err().to_string(),
            url::ParseError::InvalidPort.to_string()
        );
    }

    #[test]
    #[allow(non_snake_case)]
    fn load_root_certificate__pem_success() {
        let cert_path = get_bad_ssl_cert_path();

        let result = load_root_certificate(CertificateEncoding::PEM, &cert_path);

        assert!(result.is_ok())
    }

    #[test]
    #[allow(non_snake_case)]
    fn load_root_certificate__request_der_supply_pem() {
        let cert_path = get_bad_ssl_cert_path();

        let result = load_root_certificate(CertificateEncoding::DER, &cert_path);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            CERTIFICATE_ERROR_DECODE.to_string()
        );
    }

    #[test]
    #[allow(non_snake_case)]
    fn make_request__untrusted_root_with_supplied_ca__success() {
        let cert_path = get_bad_ssl_cert_path();

        let url = Url::parse(BAD_SSL_UNTRUSTED_ROOT_URL).expect("parsing url failed");
        let mut options = debug_http_options();

        options.pem_root_certificate_path = Some(cert_path);

        let result = make_request(&options, url, Method::GET, None);

        assert!(result.is_ok())
    }

    #[test]
    #[allow(non_snake_case)]
    fn make_request__untrusted_root__failure() {
        let url = Url::parse(BAD_SSL_UNTRUSTED_ROOT_URL).expect("parsing url failed");
        let options = debug_http_options();

        let result = make_request(&options, url, Method::GET, None);

        assert!(result.is_err())
    }

    #[test]
    #[allow(non_snake_case)]
    fn make_request__expired__failure() {
        let url = Url::parse(BAD_SSL_EXPIRED_URL).expect("parsing url failed");
        let options = debug_http_options();

        let result = make_request(&options, url, Method::GET, None);

        assert!(result.is_err())
    }

    #[test]
    #[allow(non_snake_case)]
    fn make_request__expired_with_danger_accept_invalid_certs__success() {
        let url = Url::parse(BAD_SSL_EXPIRED_URL).expect("parsing url failed");
        let mut options = debug_http_options();

        options.danger_disable_tls_verification = true;

        let result = make_request(&options, url, Method::GET, None);

        assert!(result.is_ok())
    }

    #[test]
    #[allow(non_snake_case)]
    fn generic_secret_to_env_vars_secret() {
        let gs: GenericSecret = GenericSecret {
            website_password_url_filter: None,
            website_password_notes: None,
            website_password_password: None,
            website_password_username: None,
            website_password_url: None,
            website_password_title: None,
            application_password_notes: None,
            application_password_password: None,
            application_password_username: None,
            application_password_title: None,
            bookmark_url_filter: None,
            bookmark_notes: None,
            bookmark_url: None,
            bookmark_title: None,
            mail_gpg_own_key_private: None,
            mail_gpg_own_key_public: None,
            mail_gpg_own_key_name: None,
            mail_gpg_own_key_email: None,
            mail_gpg_own_key_title: None,
            note_notes: None,
            note_title: None,
            environment_variables_title: Some("PROD".to_string()),
            environment_variables_notes: Some("my first note".to_string()),
            environment_variables_variables: Some(vec![
                EnvironmentVariable {
                    key: "USERNAME".to_string(),
                    value: "tester".to_string(),
                },
                EnvironmentVariable {
                    key: "Password".to_string(),
                    value: "PASSWORD".to_string(),
                },
            ]),
        };

        let result = Secret::transform(gs);
        assert!(result.is_ok());

        let s = result.unwrap();
        assert_eq!(s.title, Some("PROD".to_string()));
        assert_eq!(s.notes, Some("my first note".to_string()));
        assert_eq!(
            s.env_vars,
            Some(vec![
                EnvironmentVariable {
                    key: "USERNAME".to_string(),
                    value: "tester".to_string(),
                },
                EnvironmentVariable {
                    key: "Password".to_string(),
                    value: "PASSWORD".to_string(),
                },
            ])
        );
    }
}
