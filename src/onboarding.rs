use std::io::{self, Write};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use crypto_box::aead::{Aead, OsRng};
use crypto_box::{PublicKey, SalsaBox, SecretKey};
use reqwest::Certificate;
use reqwest::blocking::{Client, ClientBuilder};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue, USER_AGENT};
use reqwest::redirect::Policy;
use serde::Deserialize;
use serde_json::{Value, json};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::config::{Config, ConfigSaveFormat, HttpOptions, PsonoSettings};
use crate::crypto::{create_nonce_hex, open_secret_box, seal_secret_box_hex};
use crate::opt::ConfigSource;
use crate::sensitive::SensitiveString;

static USER_AGENT_NAME: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Deserialize)]
struct DeviceInitResponse {
    id: String,
    server_public_key: String,
    web_client_url: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    boxed_payload: String,
    nonce: String,
}

#[derive(Debug, Deserialize)]
struct DecryptedPayload {
    token: String,
    session_secret_key: String,
    encrypted_credentials: String,
    encrypted_credentials_nonce: String,
}

#[derive(Debug, Deserialize)]
struct UserCredentials {
    user_private_key: String,
    user_secret_key: String,
    user_sauce: String,
}

#[derive(Debug, Deserialize)]
struct EncryptedApiEnvelope {
    data: SessionEncryptedValue,
}

#[derive(Debug, Deserialize)]
struct PlainApiEnvelope<T> {
    data: T,
}

#[derive(Debug, Deserialize, serde::Serialize)]
struct SessionEncryptedValue {
    text: String,
    nonce: String,
}

#[derive(Debug, Deserialize)]
struct ApiKeyListResponse {
    api_keys: Vec<ApiKeyListItem>,
}

#[derive(Debug, Deserialize, Clone)]
struct ApiKeyListItem {
    id: Uuid,
    title: String,
    restrict_to_secrets: bool,
    allow_insecure_access: bool,
    read: bool,
    write: bool,
    active: bool,
}

#[derive(Debug, Deserialize)]
struct ApiKeyDetailResponse {
    id: Uuid,
    secret_key: String,
    secret_key_nonce: String,
}

struct UserSession {
    token: SensitiveString,
    session_secret_key: SensitiveString,
    _user_private_key: SensitiveString,
    user_secret_key: SensitiveString,
    _user_sauce: SensitiveString,
    device_fingerprint: String,
    server_url: Url,
}

pub fn run_onboard_command(
    _config_source: ConfigSource,
    server_url: Url,
    http_options: HttpOptions,
    path: Option<PathBuf>,
    overwrite: bool,
) -> Result<()> {
    let onboarding_config = onboard(server_url, http_options)?;

    if let Some(path) = path {
        onboarding_config
            .save(&path, ConfigSaveFormat::Toml, overwrite)
            .context("saving onboarded config failed")?;
    } else {
        println!();
        println!(
            "{}",
            onboarding_config
                .to_string(ConfigSaveFormat::Toml)
                .context("serializing onboarded config failed")?
        );
    }

    Ok(())
}

fn onboard(server_url: Url, http_options: HttpOptions) -> Result<Config> {
    let client = build_http_client(&http_options)?;
    let device_fingerprint = Uuid::new_v4().to_string();
    let device_description = format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

    let (temp_secret_key, temp_public_key) = generate_device_keypair();
    let device_init = initiate_device_flow(
        &client,
        &server_url,
        &device_description,
        &device_fingerprint,
        &temp_public_key,
    )?;
    let salsa_box = compute_shared_secret(&device_init.server_public_key, &temp_secret_key)?;

    let secret_box_key = generate_secret_box_key();
    let approval_url = build_approval_url(
        &device_init.web_client_url,
        &device_init.id,
        &secret_box_key,
    );
    eprintln!(
        "Open this URL in your browser to approve the device:\n{}",
        approval_url
    );

    let payload = poll_for_token(&client, &server_url, &device_init.id, &salsa_box)?;
    let credentials = decrypt_user_credentials(
        &payload.encrypted_credentials,
        &payload.encrypted_credentials_nonce,
        &secret_box_key,
    )?;

    let session = UserSession {
        token: SensitiveString::from(payload.token),
        session_secret_key: SensitiveString::from(payload.session_secret_key),
        _user_private_key: SensitiveString::from(credentials.user_private_key),
        user_secret_key: SensitiveString::from(credentials.user_secret_key),
        _user_sauce: SensitiveString::from(credentials.user_sauce),
        device_fingerprint,
        server_url: server_url.clone(),
    };

    let api_keys = read_api_keys(&client, &session)?;
    if api_keys.is_empty() {
        bail!("No API keys found for the authenticated user");
    }

    let selected_key = select_api_key(&api_keys)?;
    let api_secret_key_hex = read_api_key_secret_key(&client, &session, &selected_key.id)?;

    Ok(build_bootstrap_config(
        server_url,
        http_options,
        selected_key.id,
        SensitiveString::from(api_secret_key_hex),
    ))
}

fn build_bootstrap_config(
    server_url: Url,
    http_options: HttpOptions,
    api_key_id: Uuid,
    api_secret_key_hex: SensitiveString,
) -> Config {
    Config {
        psono_settings: PsonoSettings {
            api_key_id,
            api_secret_key_hex,
            server_url,
        },
        http_options,
    }
}

fn build_http_client(http_options: &HttpOptions) -> Result<Client> {
    let redirect_policy = match http_options.max_redirects {
        0 => Policy::default(),
        _ => Policy::limited(http_options.max_redirects),
    };

    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static(USER_AGENT_NAME));
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));

    let mut client_builder = ClientBuilder::new()
        .redirect(redirect_policy)
        .timeout(Duration::from_secs(http_options.timeout as u64))
        .default_headers(headers);

    if let Some(cert_der_path) = &http_options.der_root_certificate_path {
        let cert_der = std::fs::read(cert_der_path).context("could not read certificate")?;
        let cert = Certificate::from_der(&cert_der).context("could not decode certificate")?;
        client_builder = client_builder.add_root_certificate(cert);
    }

    if let Some(cert_pem_path) = &http_options.pem_root_certificate_path {
        let cert_pem = std::fs::read(cert_pem_path).context("could not read certificate")?;
        let cert = Certificate::from_pem(&cert_pem).context("could not decode certificate")?;
        client_builder = client_builder.add_root_certificate(cert);
    }

    if http_options.use_native_tls || http_options.danger_disable_tls_verification {
        client_builder = client_builder
            .use_native_tls()
            .danger_accept_invalid_certs(http_options.danger_disable_tls_verification)
            .danger_accept_invalid_hostnames(http_options.danger_disable_tls_verification);
    } else {
        client_builder = client_builder.use_rustls_tls();
    }

    client_builder
        .build()
        .context("building reqwest client failed")
}

fn initiate_device_flow(
    client: &Client,
    server_url: &Url,
    device_description: &str,
    device_fingerprint: &str,
    temp_public_key: &PublicKey,
) -> Result<DeviceInitResponse> {
    let url = endpoint_url(server_url, "/device-code/")?;
    let response = client
        .post(url)
        .json(&json!({
            "device_description": device_description,
            "device_fingerprint": device_fingerprint,
            "device_date": chrono::Utc::now(),
            "user_public_key": hex::encode(temp_public_key.as_bytes()),
        }))
        .send()
        .context("device init request failed")?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().unwrap_or_default();
        bail!("device init failed with {}: {}", status, body);
    }

    response
        .json::<DeviceInitResponse>()
        .context("decoding device init response failed")
}

fn poll_for_token(
    client: &Client,
    server_url: &Url,
    device_code_id: &str,
    salsa_box: &SalsaBox,
) -> Result<DecryptedPayload> {
    let url = endpoint_url(
        server_url,
        &format!("/device-code/{}/token/", device_code_id),
    )?;

    loop {
        let response = client
            .post(url.clone())
            .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
            .json(&json!({}))
            .send()
            .context("device token polling request failed")?;

        let status = response.status();
        if status.is_success() {
            let token_response = response
                .json::<TokenResponse>()
                .context("decoding token response failed")?;
            return decrypt_token_payload(&token_response, salsa_box);
        }

        if status.as_u16() == 202 {
            thread::sleep(Duration::from_secs(3));
            continue;
        }

        let body = response.text().unwrap_or_default();
        if status.as_u16() == 400 && body.contains("DEVICE_CODE_NOT_CLAIMED") {
            thread::sleep(Duration::from_secs(3));
            continue;
        }

        bail!("device token polling failed with {}: {}", status, body);
    }
}

fn read_api_keys(client: &Client, session: &UserSession) -> Result<Vec<ApiKeyListItem>> {
    let response: ApiKeyListResponse =
        authenticated_request(client, session, reqwest::Method::GET, "/api-key/", None)?;
    Ok(response.api_keys)
}

fn read_api_key_secret_key(
    client: &Client,
    session: &UserSession,
    api_key_id: &Uuid,
) -> Result<String> {
    let response: ApiKeyDetailResponse = authenticated_request(
        client,
        session,
        reqwest::Method::GET,
        &format!("/api-key/{}/", api_key_id),
        None,
    )?;

    if response.id != *api_key_id {
        bail!("selected api key response returned a mismatched id");
    }

    open_secret_box(
        &response.secret_key,
        &response.secret_key_nonce,
        session.user_secret_key.expose_secret(),
    )
    .context("decrypting selected api key secret key failed")
    .and_then(|raw| {
        String::from_utf8(raw).context("selected api key secret key is not valid utf-8")
    })
}

fn authenticated_request<T: for<'de> Deserialize<'de>>(
    client: &Client,
    session: &UserSession,
    method: reqwest::Method,
    endpoint: &str,
    body: Option<Value>,
) -> Result<T> {
    let url = endpoint_url(&session.server_url, endpoint)?;
    let mut request = client
        .request(method, url)
        .header(
            AUTHORIZATION,
            format!("Token {}", session.token.expose_secret()),
        )
        .header(
            "Authorization-Validator",
            create_authorization_validator(
                session.session_secret_key.expose_secret(),
                &session.device_fingerprint,
            )?,
        );

    if let Some(body) = body {
        request = request.json(&encrypt_request_body(
            &body,
            session.session_secret_key.expose_secret(),
        )?);
    }

    let response = request.send().context("authenticated request failed")?;
    let status = response.status();
    let response_text = response
        .text()
        .context("reading authenticated response failed")?;
    if !status.is_success() {
        bail!(
            "authenticated request failed with {}: {}",
            status,
            response_text
        );
    }

    decode_authenticated_response(&response_text, session.session_secret_key.expose_secret())
}

fn decode_authenticated_response<T: for<'de> Deserialize<'de>>(
    response_text: &str,
    session_secret_key: &str,
) -> Result<T> {
    if let Ok(encrypted_value) = serde_json::from_str::<SessionEncryptedValue>(response_text) {
        let decrypted = open_secret_box(
            &encrypted_value.text,
            &encrypted_value.nonce,
            session_secret_key,
        )
        .context("decrypting authenticated response failed")?;

        return serde_json::from_slice(&decrypted)
            .context("decoding decrypted authenticated response failed");
    }

    if let Ok(envelope) = serde_json::from_str::<EncryptedApiEnvelope>(response_text) {
        let decrypted = open_secret_box(
            &envelope.data.text,
            &envelope.data.nonce,
            session_secret_key,
        )
        .context("decrypting authenticated response failed")?;

        return serde_json::from_slice(&decrypted)
            .context("decoding decrypted authenticated response failed");
    }

    if let Ok(envelope) = serde_json::from_str::<PlainApiEnvelope<T>>(response_text) {
        return Ok(envelope.data);
    }

    log_decode_failure(response_text);

    serde_json::from_str(response_text).context("decoding authenticated response failed")
}

fn log_decode_failure(response_text: &str) {
    if std::env::var_os("PSONOCI_DEBUG_ONBOARDING").is_none() {
        return;
    }

    const MAX_LOG_CHARS: usize = 4000;
    let truncated: String = response_text.chars().take(MAX_LOG_CHARS).collect();
    let suffix = if response_text.chars().count() > MAX_LOG_CHARS {
        "... [truncated]"
    } else {
        ""
    };

    eprintln!(
        "psonoci onboarding decode failure response:\n{}{}",
        truncated, suffix
    );
}

fn create_authorization_validator(
    session_secret_key: &str,
    device_fingerprint: &str,
) -> Result<String> {
    let plaintext = Zeroizing::new(
        serde_json::to_string(&json!({
            "request_time": chrono::Utc::now().to_rfc3339(),
            "request_device_fingerprint": device_fingerprint,
        }))
        .context("serializing authorization validator failed")?,
    );
    let nonce = create_nonce_hex();
    let text = seal_secret_box_hex(plaintext.as_bytes(), &nonce, session_secret_key)
        .context("encrypting authorization validator failed")?;

    serde_json::to_string(&SessionEncryptedValue { text, nonce })
        .context("encoding authorization validator header failed")
}

fn encrypt_request_body(body: &Value, session_secret_key: &str) -> Result<SessionEncryptedValue> {
    let plaintext = Zeroizing::new(
        serde_json::to_string(body).context("serializing authenticated request body failed")?,
    );
    let nonce = create_nonce_hex();
    let text = seal_secret_box_hex(plaintext.as_bytes(), &nonce, session_secret_key)
        .context("encrypting authenticated request body failed")?;

    Ok(SessionEncryptedValue { text, nonce })
}

fn endpoint_url(server_url: &Url, endpoint: &str) -> Result<Url> {
    let mut endpoint_url = server_url.clone();
    endpoint_url.set_path(server_url.path().trim_end_matches('/'));
    let has_trailing_slash = endpoint.ends_with('/');

    for segment in endpoint.split('/') {
        if segment.is_empty() {
            continue;
        }

        endpoint_url
            .path_segments_mut()
            .map_err(|_| anyhow!("cannot create endpoint url from server_url and endpoint path"))?
            .pop_if_empty()
            .push(segment.trim_start_matches('/'));
    }

    if has_trailing_slash {
        let path = endpoint_url.path().to_string();
        endpoint_url.set_path(&format!("{}/", path.trim_end_matches('/')));
    }

    Ok(endpoint_url)
}

fn generate_device_keypair() -> (SecretKey, PublicKey) {
    let secret_key = SecretKey::generate(&mut OsRng);
    let public_key = secret_key.public_key();
    (secret_key, public_key)
}

fn compute_shared_secret(
    server_public_key_hex: &str,
    temp_secret_key: &SecretKey,
) -> Result<SalsaBox> {
    let server_public_key_bytes =
        hex::decode(server_public_key_hex).context("decoding server public key failed")?;
    if server_public_key_bytes.len() < 32 {
        bail!(
            "invalid server public key length; supplied: {}, required: 32",
            server_public_key_bytes.len()
        );
    }

    let mut server_public_key_array = [0u8; 32];
    server_public_key_array.copy_from_slice(&server_public_key_bytes[..32]);

    Ok(SalsaBox::new(
        &PublicKey::from(server_public_key_array),
        temp_secret_key,
    ))
}

fn decrypt_token_payload(
    token_response: &TokenResponse,
    salsa_box: &SalsaBox,
) -> Result<DecryptedPayload> {
    decrypt_token_payload_with_salsa_box(token_response, salsa_box)
}

fn decrypt_token_payload_with_salsa_box(
    token_response: &TokenResponse,
    salsa_box: &SalsaBox,
) -> Result<DecryptedPayload> {
    let nonce_raw = hex::decode(&token_response.nonce).context("decoding token nonce failed")?;
    if nonce_raw.len() < 24 {
        bail!(
            "invalid token nonce length; supplied: {}, required: 24",
            nonce_raw.len()
        );
    }

    let mut nonce_array = [0u8; 24];
    nonce_array.copy_from_slice(&nonce_raw[..24]);
    let nonce = crypto_box::Nonce::from(nonce_array);

    let ciphertext =
        hex::decode(&token_response.boxed_payload).context("decoding token payload failed")?;
    let plaintext = salsa_box
        .decrypt(&nonce, ciphertext.as_slice())
        .map_err(|err| anyhow!(err))
        .context("decrypting token payload failed")?;

    serde_json::from_slice(&plaintext).context("decoding token payload json failed")
}

fn decrypt_user_credentials(
    encrypted_credentials: &str,
    encrypted_credentials_nonce: &str,
    secret_box_key: &[u8; 32],
) -> Result<UserCredentials> {
    let secret_box_key_hex = Zeroizing::new(hex::encode(secret_box_key));
    let plaintext = open_secret_box(
        encrypted_credentials,
        encrypted_credentials_nonce,
        &secret_box_key_hex,
    )
    .context("decrypting user credentials failed")?;

    serde_json::from_slice(&plaintext).context("decoding user credentials failed")
}

fn generate_secret_box_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    let mut rng = OsRng;
    use crypto_box::aead::rand_core::RngCore;
    rng.fill_bytes(&mut key);
    key
}

fn build_approval_url(
    web_client_url: &str,
    device_code_id: &str,
    secret_box_key: &[u8; 32],
) -> String {
    format!(
        "{}/index.html#/device/{}/{}",
        web_client_url,
        device_code_id,
        hex::encode(secret_box_key)
    )
}

fn select_api_key(api_keys: &[ApiKeyListItem]) -> Result<ApiKeyListItem> {
    for (index, api_key) in api_keys.iter().enumerate() {
        eprintln!(
            "{}) {} [{}]",
            index + 1,
            api_key.title,
            format_api_key_flags(api_key)
        );
    }

    eprint!("Select an API key by number: ");
    io::stderr().flush().context("flushing stderr failed")?;

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .context("reading api key selection failed")?;
    let selected_index = parse_selection(&input, api_keys.len())?;

    Ok(api_keys[selected_index].clone())
}

fn parse_selection(input: &str, item_count: usize) -> Result<usize> {
    let trimmed = input.trim();
    let selected = trimmed
        .parse::<usize>()
        .with_context(|| format!("invalid api key selection '{}'", trimmed))?;

    if selected == 0 || selected > item_count {
        bail!(
            "api key selection {} is out of range 1..={}",
            selected,
            item_count
        );
    }

    Ok(selected - 1)
}

fn format_api_key_flags(api_key: &ApiKeyListItem) -> String {
    let mut flags = Vec::new();

    if api_key.restrict_to_secrets {
        flags.push("secrets-only");
    }
    if api_key.allow_insecure_access {
        flags.push("insecure");
    }
    if api_key.read {
        flags.push("read");
    }
    if api_key.write {
        flags.push("write");
    }
    if api_key.active {
        flags.push("active");
    } else {
        flags.push("inactive");
    }

    flags.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_approval_url_uses_web_client_url() {
        let key = [0u8; 32];
        let url = build_approval_url(
            "https://frontend.example.com/app",
            "123e4567-e89b-12d3-a456-426614174000",
            &key,
        );

        assert_eq!(
            url,
            "https://frontend.example.com/app/index.html#/device/123e4567-e89b-12d3-a456-426614174000/0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn parse_selection_accepts_valid_one_based_index() {
        assert_eq!(parse_selection("2\n", 3).unwrap(), 1);
    }

    #[test]
    fn parse_selection_rejects_out_of_range_index() {
        assert!(parse_selection("4", 3).is_err());
    }

    #[test]
    fn format_api_key_flags_includes_active_state() {
        let api_key = ApiKeyListItem {
            id: Uuid::nil(),
            title: "CI".to_string(),
            restrict_to_secrets: true,
            allow_insecure_access: false,
            read: true,
            write: false,
            active: true,
        };

        assert_eq!(format_api_key_flags(&api_key), "secrets-only, read, active");
    }

    #[test]
    fn build_bootstrap_config_preserves_backend_server_url() {
        let server_url = Url::parse("https://backend.example.com/server").unwrap();
        let config = build_bootstrap_config(
            server_url.clone(),
            HttpOptions::default(),
            Uuid::nil(),
            SensitiveString::from(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ),
        );

        assert_eq!(config.psono_settings.server_url, server_url);
    }

    #[test]
    fn endpoint_url_preserves_trailing_slash() {
        let server_url = Url::parse("https://backend.example.com/server").unwrap();
        let endpoint = endpoint_url(&server_url, "/device-code/").unwrap();

        assert_eq!(
            endpoint.as_str(),
            "https://backend.example.com/server/device-code/"
        );
    }

    #[test]
    fn decode_authenticated_response_accepts_plain_json() {
        let response: ApiKeyListResponse = decode_authenticated_response(
            r#"{"api_keys":[{"id":"00000000-0000-0000-0000-000000000000","title":"CI","restrict_to_secrets":true,"allow_insecure_access":false,"read":true,"write":false,"active":true}]}"#,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();

        assert_eq!(response.api_keys.len(), 1);
        assert_eq!(response.api_keys[0].title, "CI");
    }

    #[test]
    fn decode_authenticated_response_accepts_bare_encrypted_json() {
        let key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let nonce = create_nonce_hex();
        let plaintext = r#"{"api_keys":[{"id":"00000000-0000-0000-0000-000000000000","title":"CI","restrict_to_secrets":true,"allow_insecure_access":false,"read":true,"write":false,"active":true}]}"#;
        let encrypted = seal_secret_box_hex(plaintext.as_bytes(), &nonce, key).unwrap();
        let response_text = serde_json::to_string(&SessionEncryptedValue {
            text: encrypted,
            nonce,
        })
        .unwrap();

        let response: ApiKeyListResponse =
            decode_authenticated_response(&response_text, key).unwrap();

        assert_eq!(response.api_keys.len(), 1);
        assert_eq!(response.api_keys[0].title, "CI");
    }
}
