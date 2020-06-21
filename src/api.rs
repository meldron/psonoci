use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
// use attohttpc::Method;
use clap::arg_enum;
use reqwest::blocking::{Client, ClientBuilder};
use reqwest::redirect::Policy;
use reqwest::Certificate;
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::json;
use structopt::StructOpt;
use url::Url;
use uuid::Uuid;

use crate::crypto::{open_secret_box, parse_secret_key};

static USER_AGENT_NAME: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

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
    secret_type,
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
            &SecretValue::secret_type => "type",
        }
    }
}

const PARSE_URL_ERROR_INVALID_SCHEME: &str =
    "Url has unsupported scheme (only http & https schemes are supported)";

fn parse_url(src: &str) -> Result<Url> {
    let url = Url::parse(src)?;

    // validate url
    match url.scheme() {
        "http" => {}
        "https" => {}
        _ => return Err(anyhow!(PARSE_URL_ERROR_INVALID_SCHEME)),
    };
    url.host().ok_or(anyhow!("Url has invalid host)"))?;
    url.port_or_known_default()
        .ok_or(anyhow!("Url is missing a port"))?;

    Ok(url)
}

enum CertificateEncoding {
    DER,
    PEM,
}

#[derive(StructOpt, Debug)]
pub struct ApiSettings {
    // psono server options
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

    // http(s) request options
    #[structopt(
        long,
        env = "PSONO_CI_TIMEOUT",
        default_value = "60",
        help = "Connection timeout in seconds"
    )]
    pub timeout: u64,
    #[structopt(
        long,
        env = "PSONO_CI_MAX_REDIRECTS",
        default_value = "0",
        help = "Maximum numbers of redirects"
    )]
    pub max_redirects: u8,

    // TLS options and flags
    #[structopt(
        long,
        help = "Use native TLS implementation (on linux a vendored openssl version is used)"
    )]
    pub use_native_tls: bool,
    #[structopt(long, help = "Controls the use of hostname verification.")]
    pub danger_accept_invalid_hostnames: bool,
    #[structopt(long, help = "Controls the use of certificate verification.")]
    pub danger_accept_invalid_certs: bool,
    #[structopt(
        long,
        parse(from_os_str),
        help = "Path to a DER encoded root certificate which should be added to the trust store"
    )]
    pub add_der_root_certificate: Option<PathBuf>,
    #[structopt(
        long,
        parse(from_os_str),
        help = "Path to a pem encoded root certificate which should be added to the trust store"
    )]
    pub add_pem_root_certificate: Option<PathBuf>,
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
            SecretValue::secret_type => Some(self.secret_type.as_str().to_owned()),
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
pub struct Route<T> {
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

fn load_root_certificate(encoding: CertificateEncoding, path: &PathBuf) -> Result<Certificate> {
    let mut buf = Vec::new();
    File::open(path)
        .context("could not open certificate")?
        .read_to_end(&mut buf)
        .context("could not read certificate")?;

    let cert_result = match encoding {
        CertificateEncoding::DER => Certificate::from_der(&buf),
        CertificateEncoding::PEM => Certificate::from_pem(&buf),
    };

    let cert = cert_result.context("could not decode certificate")?;

    Ok(cert)
}

pub fn call<T, U>(settings: &ApiSettings, route: Route<T>) -> Result<U>
where
    T: Serialize,
    U: DeserializeOwned,
{
    let url = format!("{}/{}", settings.server_url, route.endpoint.as_str());
    let url_parsed = Url::parse(&url).context("url parsing error")?;

    let redirect_policy: Policy = match settings.max_redirects {
        0 => Policy::none(),
        _ => Policy::limited(settings.max_redirects as usize),
    };

    let mut client_builder: ClientBuilder = Client::builder()
        .user_agent(USER_AGENT_NAME)
        .redirect(redirect_policy)
        .timeout(Duration::from_secs(settings.timeout));

    if settings.add_der_root_certificate.is_some() {
        let cert_der_path = settings.add_der_root_certificate.as_ref().unwrap();
        let cert_der = load_root_certificate(CertificateEncoding::DER, cert_der_path)
            .context("adding DER root certificate failed")?;
        client_builder = client_builder.add_root_certificate(cert_der);
    }

    if settings.add_pem_root_certificate.is_some() {
        let cert_pem_path = settings.add_pem_root_certificate.as_ref().unwrap();
        let cert_pem = load_root_certificate(CertificateEncoding::PEM, cert_pem_path)
            .context("adding PEM root certificate failed")?;
        client_builder = client_builder.add_root_certificate(cert_pem);
    }

    // we always use native-tls for making dangerous calls
    // because right now rust-tls cannot handle all of them
    if settings.use_native_tls
        || settings.danger_accept_invalid_certs
        || settings.danger_accept_invalid_hostnames
    {
        client_builder = client_builder
            .use_native_tls()
            .danger_accept_invalid_certs(settings.danger_accept_invalid_certs)
            .danger_accept_invalid_hostnames(settings.danger_accept_invalid_hostnames);
    } else {
        client_builder = client_builder.use_rustls_tls();
    }

    let client = client_builder
        .build()
        .context("building reqwest client failed")?;

    let response = client
        .request(route.method, url_parsed)
        .json(&route.body)
        .send()
        .context("request failed")?;

    let status = response.status();

    if !status.is_success() {
        let reason = status.canonical_reason().unwrap_or("unknown").to_owned();
        return Err(anyhow!("{}: {}", response.status(), reason));
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

    let request = Route {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
