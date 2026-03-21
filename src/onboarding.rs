use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use crypto_box::aead::{Aead, OsRng};
use crypto_box::{KEY_SIZE, PublicKey, SalsaBox, SecretKey};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use ratatui::{TerminalOptions, Viewport};
use reqwest::Certificate;
use reqwest::blocking::{Client, ClientBuilder};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue, USER_AGENT};
use reqwest::redirect::Policy;
use serde::Deserialize;
use serde_json::{Value, json};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::api::{USER_AGENT_NAME, parse_url};
use crate::config::{Config, ConfigSaveFormat, HttpOptions, PsonoSettings};
use crate::crypto::{NONCE_LENGTH, create_nonce_hex, open_secret_box, seal_secret_box_hex};
use crate::opt::{OnboardCommand, OnboardOutputFormat};
use crate::sensitive::SensitiveString;

const DEFAULT_PSONO_SERVER_URL: &str = "https://www.psono.pw/server";

#[cfg(debug_assertions)]
static DEBUG_ONBOARDING_USE_CACHE_ENV: &str = "PSONOCI_DEBUG_ONBOARDING_USE_CACHE";

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
    token: SensitiveString,
    session_secret_key: SensitiveString,
    encrypted_credentials: String,
    encrypted_credentials_nonce: String,
}

#[derive(Debug, Deserialize)]
struct UserCredentials {
    user_private_key: SensitiveString,
    user_secret_key: SensitiveString,
    user_sauce: SensitiveString,
}

#[derive(Debug, Deserialize)]
struct EncryptedApiEnvelope {
    data: SessionEncryptedValue,
}

#[derive(Debug, Deserialize)]
struct PlainApiEnvelope<T> {
    data: T,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum AuthenticatedResponse<T> {
    BareEncrypted(SessionEncryptedValue),
    EnvelopeEncrypted(EncryptedApiEnvelope),
    EnvelopePlain(PlainApiEnvelope<T>),
    Plain(T),
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

#[derive(Debug, Deserialize, serde::Serialize, Clone)]
struct ApiKeyListItem {
    id: Uuid,
    title: String,
    restrict_to_secrets: bool,
    allow_insecure_access: bool,
    read: bool,
    write: bool,
    active: bool,
}

#[cfg(debug_assertions)]
#[derive(Debug, Deserialize, serde::Serialize)]
struct DebugApiKeyCache {
    server_url: String,
    api_keys: Vec<ApiKeyListItem>,
}

#[derive(Debug, Deserialize)]
struct ApiKeyDetailResponse {
    id: Uuid,
    secret_key: SensitiveString,
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

struct RawModeGuard;
struct ApiKeySelectorTerminal {
    terminal: Terminal<CrosstermBackend<io::Stderr>>,
    raw_mode: Option<RawModeGuard>,
    cleaned_up: bool,
}

enum SelectorOutcome {
    Selected(ApiKeyListItem),
    Cancelled,
    Interrupted,
}

#[derive(Debug, PartialEq, Eq)]
enum SelectorAction {
    MoveUp,
    MoveDown,
    JumpToTop,
    JumpToBottom,
    JumpToIndex(usize),
    Backspace,
    Type(char),
    Confirm,
    Cancel,
    Interrupt,
}

enum TuiSelectionError {
    Cancelled,
    Interrupted,
    TuiFailed(anyhow::Error),
}

struct ApiKeySelectorState {
    query: String,
    filtered_indices: Vec<usize>,
    list_state: ListState,
}

impl ApiKeySelectorState {
    fn new(api_keys: &[ApiKeyListItem]) -> Self {
        let mut state = Self {
            query: String::new(),
            filtered_indices: (0..api_keys.len()).collect(),
            list_state: ListState::default(),
        };
        state.list_state.select(Some(0));
        state
    }

    fn refresh_filter(&mut self, api_keys: &[ApiKeyListItem]) {
        self.filtered_indices = filter_api_keys(api_keys, &self.query);

        let next_selection = match self.list_state.selected() {
            Some(selected) if selected < self.filtered_indices.len() => Some(selected),
            Some(_) | None if self.filtered_indices.is_empty() => None,
            _ => Some(0),
        };

        self.list_state.select(next_selection);
    }

    fn selected_api_key<'a>(&self, api_keys: &'a [ApiKeyListItem]) -> Option<&'a ApiKeyListItem> {
        let filtered_index = self.list_state.selected()?;
        let api_key_index = *self.filtered_indices.get(filtered_index)?;
        api_keys.get(api_key_index)
    }

    fn move_selection_by(&mut self, delta: isize) -> bool {
        let previous = self.list_state.selected();
        move_selection(&mut self.list_state, self.filtered_indices.len(), delta);
        self.list_state.selected() != previous
    }

    fn move_to_start(&mut self) -> bool {
        let previous = self.list_state.selected();
        self.list_state.select(if self.filtered_indices.is_empty() {
            None
        } else {
            Some(0)
        });
        self.list_state.selected() != previous
    }

    fn move_to_end(&mut self) -> bool {
        let previous = self.list_state.selected();
        self.list_state
            .select(self.filtered_indices.len().checked_sub(1));
        self.list_state.selected() != previous
    }

    fn jump_to(&mut self, index: usize) -> bool {
        if index >= self.filtered_indices.len() {
            return false;
        }

        let previous = self.list_state.selected();
        self.list_state.select(Some(index));
        self.list_state.selected() != previous
    }

    fn push_query(&mut self, ch: char, api_keys: &[ApiKeyListItem]) -> bool {
        self.query.push(ch);
        self.refresh_filter(api_keys);
        true
    }

    fn pop_query(&mut self, api_keys: &[ApiKeyListItem]) -> bool {
        if self.query.pop().is_none() {
            return false;
        }

        self.refresh_filter(api_keys);
        true
    }
}

impl RawModeGuard {
    fn acquire() -> Result<Self> {
        enable_raw_mode().context("enabling raw mode failed")?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
    }
}

impl ApiKeySelectorTerminal {
    fn acquire(api_keys: &[ApiKeyListItem]) -> Result<Self> {
        let raw_mode = RawModeGuard::acquire()?;
        let stderr = io::stderr();
        let height = inline_viewport_height(api_keys.len());
        let backend = CrosstermBackend::new(stderr);
        let options = TerminalOptions {
            viewport: Viewport::Inline(height),
        };
        let mut terminal = Terminal::with_options(backend, options)
            .context("initializing onboarding selector terminal failed")?;
        terminal
            .hide_cursor()
            .context("hiding terminal cursor failed")?;

        Ok(Self {
            terminal,
            raw_mode: Some(raw_mode),
            cleaned_up: false,
        })
    }

    fn terminal_mut(&mut self) -> &mut Terminal<CrosstermBackend<io::Stderr>> {
        &mut self.terminal
    }

    fn cleanup(&mut self) -> Result<()> {
        if self.cleaned_up {
            return Ok(());
        }

        drop(self.raw_mode.take());
        cleanup_tui_terminal(&mut self.terminal)?;
        self.cleaned_up = true;
        Ok(())
    }
}

impl Drop for ApiKeySelectorTerminal {
    fn drop(&mut self) {
        if self.cleaned_up {
            return;
        }

        drop(self.raw_mode.take());
        let _ = cleanup_tui_terminal(&mut self.terminal);
    }
}

fn validate_output_path(path: Option<&Path>, overwrite: bool) -> Result<()> {
    let Some(path) = path else {
        return Ok(());
    };

    if path.is_dir() {
        bail!("output path is a directory: {}", path.display());
    }

    if path.exists() {
        if !overwrite {
            bail!("output path already exists and overwrite is not set");
        }

        return Ok(());
    }

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.exists() {
        bail!(
            "output parent directory does not exist: {}",
            parent.display()
        );
    }

    if !parent.is_dir() {
        bail!(
            "output parent path is not a directory: {}",
            parent.display()
        );
    }

    Ok(())
}

pub fn run_onboard_command(
    server_url: Option<Url>,
    http_options: HttpOptions,
    command: OnboardCommand,
) -> Result<()> {
    validate_output_path(command.path.as_deref(), command.overwrite)?;

    let server_url = resolve_server_url(server_url)?;

    let onboarding_config = onboard(server_url, http_options, &command)?;

    let format = match command.format {
        OnboardOutputFormat::Toml => ConfigSaveFormat::Toml,
        OnboardOutputFormat::Packed => ConfigSaveFormat::MessagePackBase58,
    };

    if let Some(path) = command.path.as_ref() {
        onboarding_config
            .save(path, format, command.overwrite)
            .context("saving onboarded config failed")?;
        eprintln!("Saved config to {}", path.display());
    } else if command.stdout {
        println!(
            "{}",
            onboarding_config
                .to_string(format)
                .context("serializing onboarded config failed")?
        );
    } else {
        unreachable!("clap should require either --path or --stdout for onboard");
    }

    Ok(())
}

fn resolve_server_url(server_url: Option<Url>) -> Result<Url> {
    match server_url {
        Some(server_url) => Ok(server_url),
        None => prompt_for_server_url(),
    }
}

fn ensure_interactive_server_url_prompt(stdin_is_terminal: bool) -> Result<()> {
    if !stdin_is_terminal {
        bail!("Cannot interactively enter a server url in a non-interactive environment");
    }

    Ok(())
}

fn prompt_for_server_url() -> Result<Url> {
    let stdin = io::stdin();
    ensure_interactive_server_url_prompt(stdin.is_terminal())?;

    let mut stdin = stdin.lock();
    let mut stderr = io::stderr();

    prompt_for_server_url_with(&mut stdin, &mut stderr)
}

fn prompt_for_server_url_with<R: BufRead, W: Write>(stdin: &mut R, stderr: &mut W) -> Result<Url> {
    loop {
        write!(stderr, "Enter server url [{}]: ", DEFAULT_PSONO_SERVER_URL)
            .context("writing server_url prompt failed")?;
        stderr.flush().context("flushing stderr failed")?;

        let mut input = String::new();
        let bytes_read = stdin
            .read_line(&mut input)
            .context("reading server_url from stdin failed")?;

        if bytes_read == 0 {
            continue;
        }

        let input = input.trim();
        let server_url = if input.is_empty() {
            DEFAULT_PSONO_SERVER_URL
        } else {
            input
        };

        match parse_url(server_url) {
            Ok(server_url) => return Ok(server_url),
            Err(err) => {
                writeln!(stderr, "Invalid server url: {err}")
                    .context("writing server_url validation error failed")?;
            }
        }
    }
}

fn onboard(server_url: Url, http_options: HttpOptions, command: &OnboardCommand) -> Result<Config> {
    #[cfg(debug_assertions)]
    if let Some(config) = load_debug_cached_config(&server_url, command.plain)? {
        return Ok(config);
    }

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
    )
    .context("failed to build approval url")?;

    eprintln!(
        "Open this URL in your browser to approve the device:\n{}",
        approval_url
    );
    eprintln!();

    let payload = poll_for_token(
        &client,
        &server_url,
        &device_init.id,
        &salsa_box,
        Duration::from_secs(command.polling_timeout),
        Duration::from_secs(command.polling_interval),
    )?;
    let credentials = decrypt_user_credentials(
        &payload.encrypted_credentials,
        &payload.encrypted_credentials_nonce,
        &secret_box_key,
    )?;

    let session = UserSession {
        token: payload.token,
        session_secret_key: payload.session_secret_key,
        _user_private_key: credentials.user_private_key,
        user_secret_key: credentials.user_secret_key,
        _user_sauce: credentials.user_sauce,
        device_fingerprint,
        server_url: server_url.clone(),
    };

    let api_keys = read_api_keys(&client, &session)?;
    if api_keys.is_empty() {
        bail!("No API keys found for the authenticated user");
    }

    #[cfg(debug_assertions)]
    save_debug_api_key_cache(&server_url, &api_keys)?;

    let selected_key = select_api_key(&api_keys, command.plain)?;
    eprintln!("Selected API key: {}\n", selected_key.title);
    let api_secret_key_hex = read_api_key_secret_key(&client, &session, &selected_key.id)?;

    Ok(build_bootstrap_config(
        server_url,
        http_options,
        selected_key.id,
        api_secret_key_hex,
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

#[cfg(debug_assertions)]
fn load_debug_cached_config(server_url: &Url, non_interactive: bool) -> Result<Option<Config>> {
    if std::env::var_os(DEBUG_ONBOARDING_USE_CACHE_ENV).is_none() {
        return Ok(None);
    }

    let cache_path = debug_api_key_cache_path();
    let parent = cache_path
        .parent()
        .ok_or_else(|| anyhow!("debug onboarding cache path has no parent directory"))?;
    std::fs::create_dir_all(parent).with_context(|| {
        format!(
            "creating debug onboarding cache directory failed at {}",
            parent.display()
        )
    })?;
    let cache = std::fs::read_to_string(&cache_path)
        .or_else(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                return Ok(String::new());
            }

            Err(err)
        })
        .with_context(|| {
            format!(
                "reading debug onboarding cache failed from {}",
                cache_path.display()
            )
        })?;
    if cache.is_empty() {
        return Ok(None);
    }
    let cache: DebugApiKeyCache =
        serde_json::from_str(&cache).context("decoding debug onboarding cache failed")?;

    if cache.server_url != server_url.as_str() {
        bail!(
            "debug onboarding cache server_url mismatch: expected {}, found {}",
            server_url,
            cache.server_url
        );
    }

    if cache.api_keys.is_empty() {
        bail!("debug onboarding cache does not contain any api keys");
    }

    eprintln!("Using debug onboarding cache from {}", cache_path.display());
    eprintln!();

    let selected_key = select_api_key(&cache.api_keys, non_interactive)?;

    bail!(
        "debug onboarding cache only contains API key metadata; selected '{}' ({}) - rerun without {} to fetch the secret key",
        selected_key.title,
        selected_key.id,
        DEBUG_ONBOARDING_USE_CACHE_ENV
    )
}

#[cfg(debug_assertions)]
fn save_debug_api_key_cache(server_url: &Url, api_keys: &[ApiKeyListItem]) -> Result<()> {
    if std::env::var_os(DEBUG_ONBOARDING_USE_CACHE_ENV).is_none() {
        return Ok(());
    }

    let cache_path = debug_api_key_cache_path();

    let cache = DebugApiKeyCache {
        server_url: server_url.to_string(),
        api_keys: api_keys.to_vec(),
    };

    let parent = cache_path
        .parent()
        .ok_or_else(|| anyhow!("debug onboarding cache path has no parent directory"))?;
    std::fs::create_dir_all(parent).with_context(|| {
        format!(
            "creating debug onboarding cache directory failed at {}",
            parent.display()
        )
    })?;
    write_debug_api_key_cache_file(&cache_path, &serde_json::to_vec_pretty(&cache)?).with_context(
        || {
            format!(
                "writing debug onboarding cache failed to {}",
                cache_path.display()
            )
        },
    )?;

    eprintln!("Saved debug onboarding cache to {}", cache_path.display());

    Ok(())
}

#[cfg(all(debug_assertions, unix))]
fn write_debug_api_key_cache_file(path: &Path, contents: &[u8]) -> Result<()> {
    use std::fs::{OpenOptions, Permissions};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let owner_only_rw_permissions = Permissions::from_mode(0o600);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    std::fs::set_permissions(path, owner_only_rw_permissions)?;
    Ok(())
}

#[cfg(all(debug_assertions, not(unix)))]
fn write_debug_api_key_cache_file(path: &Path, contents: &[u8]) -> Result<()> {
    std::fs::write(path, contents).with_context(|| {
        format!(
            "writing debug onboarding cache failed to {}",
            path.display()
        )
    })
}

#[cfg(debug_assertions)]
fn debug_api_key_cache_path() -> PathBuf {
    std::env::temp_dir()
        .join("psonoci")
        .join("onboarding-api-keys.json")
}

fn build_http_client(http_options: &HttpOptions) -> Result<Client> {
    let redirect_policy = match http_options.max_redirects {
        0 => Policy::none(),
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
    polling_timeout: Duration,
    polling_interval: Duration,
) -> Result<DecryptedPayload> {
    let url = endpoint_url(
        server_url,
        &format!("/device-code/{}/token/", device_code_id),
    )?;
    let started_at = Instant::now();

    loop {
        if started_at.elapsed() >= polling_timeout {
            bail!(
                "device approval polling timed out after {} seconds",
                polling_timeout.as_secs()
            );
        }

        let response = client
            .post(url.as_str())
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
            thread::sleep(
                polling_interval.min(polling_timeout.saturating_sub(started_at.elapsed())),
            );
            continue;
        }

        let body = response.text().unwrap_or_default();
        if status.as_u16() == 400 && body.contains("DEVICE_CODE_NOT_CLAIMED") {
            thread::sleep(
                polling_interval.min(polling_timeout.saturating_sub(started_at.elapsed())),
            );
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
) -> Result<SensitiveString> {
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

    let raw = Zeroizing::new(
        open_secret_box(
            response.secret_key.expose_secret(),
            &response.secret_key_nonce,
            session.user_secret_key.expose_secret(),
        )
        .context("decrypting selected api key secret key failed")?,
    );
    let secret_key = std::str::from_utf8(raw.as_ref())
        .context("selected api key secret key is not valid utf-8")?;

    Ok(SensitiveString::from(secret_key))
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
    match serde_json::from_str::<AuthenticatedResponse<T>>(response_text) {
        Ok(AuthenticatedResponse::BareEncrypted(encrypted_value)) => {
            decode_encrypted_authenticated_response(&encrypted_value, session_secret_key)
        }
        Ok(AuthenticatedResponse::EnvelopeEncrypted(envelope)) => {
            decode_encrypted_authenticated_response(&envelope.data, session_secret_key)
        }
        Ok(AuthenticatedResponse::EnvelopePlain(envelope)) => Ok(envelope.data),
        Ok(AuthenticatedResponse::Plain(value)) => Ok(value),
        Err(err) => {
            log_decode_failure(response_text);
            Err(err).context("decoding authenticated response failed")
        }
    }
}

fn decode_encrypted_authenticated_response<T: for<'de> Deserialize<'de>>(
    encrypted_value: &SessionEncryptedValue,
    session_secret_key: &str,
) -> Result<T> {
    let decrypted = Zeroizing::new(
        open_secret_box(
            &encrypted_value.text,
            &encrypted_value.nonce,
            session_secret_key,
        )
        .context("decrypting authenticated response failed")?,
    );

    serde_json::from_slice(&decrypted).context("decoding decrypted authenticated response failed")
}

#[cfg(debug_assertions)]
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

#[cfg(not(debug_assertions))]
fn log_decode_failure(_: &str) {}

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

    let mut path_segments = endpoint_url
        .path_segments_mut()
        .map_err(|_| anyhow!("cannot create endpoint url from server_url and endpoint path"))?;
    path_segments.pop_if_empty();

    for segment in endpoint.split('/') {
        if !segment.is_empty() {
            path_segments.push(segment.trim_start_matches('/'));
        }
    }

    drop(path_segments);

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
    let server_public_key_array: [u8; KEY_SIZE] =
        server_public_key_bytes.try_into().map_err(|raw: Vec<u8>| {
            anyhow!(
                "invalid server public key length; supplied: {}, required: {}",
                raw.len(),
                KEY_SIZE
            )
        })?;

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
    let nonce_array: [u8; NONCE_LENGTH] = nonce_raw.try_into().map_err(|raw: Vec<u8>| {
        anyhow!(
            "invalid token nonce length; supplied: {}, required: {}",
            raw.len(),
            NONCE_LENGTH
        )
    })?;
    let nonce = crypto_box::Nonce::from(nonce_array);

    let ciphertext =
        hex::decode(&token_response.boxed_payload).context("decoding token payload failed")?;
    let plaintext = Zeroizing::new(
        salsa_box
            .decrypt(&nonce, ciphertext.as_slice())
            .map_err(|err| anyhow!(err))
            .context("decrypting token payload failed")?,
    );

    serde_json::from_slice(&plaintext).context("decoding token payload json failed")
}

fn decrypt_user_credentials(
    encrypted_credentials: &str,
    encrypted_credentials_nonce: &str,
    secret_box_key: &[u8; 32],
) -> Result<UserCredentials> {
    let secret_box_key_hex = Zeroizing::new(hex::encode(secret_box_key));
    let plaintext = Zeroizing::new(
        open_secret_box(
            encrypted_credentials,
            encrypted_credentials_nonce,
            &secret_box_key_hex,
        )
        .context("decrypting user credentials failed")?,
    );

    serde_json::from_slice(&plaintext).context("decoding user credentials failed")
}

fn generate_secret_box_key() -> [u8; KEY_SIZE] {
    use crypto_box::aead::rand_core::RngCore;

    let mut key = [0u8; KEY_SIZE];
    let mut rng = OsRng;

    rng.fill_bytes(&mut key);

    key
}

fn validate_web_client_url(raw: &str) -> Result<Url> {
    let url = Url::parse(raw).context("web_client_url is not a valid absolute url")?;

    match url.scheme() {
        "https" => {}
        "http" if is_localhost_url(&url) => {}
        _ => bail!("web_client_url must use https unless host is localhost"),
    }

    if url.host_str().is_none() {
        bail!("web_client_url must include a host");
    }

    if !url.username().is_empty() || url.password().is_some() {
        bail!("web_client_url must not include username or password");
    }

    if url.query().is_some() {
        bail!("web_client_url must not include query parameters");
    }

    if url.fragment().is_some() {
        bail!("web_client_url must not include a fragment");
    }

    Ok(url)
}

fn is_localhost_url(url: &Url) -> bool {
    matches!(
        url.host_str(),
        Some("localhost") | Some("127.0.0.1") | Some("::1") | Some("[::1]")
    )
}

fn build_approval_url(
    web_client_url: &str,
    device_code_id: &str,
    secret_box_key: &[u8; KEY_SIZE],
) -> Result<String> {
    let mut url = validate_web_client_url(web_client_url)
        .with_context(|| format!("invalid web_client_url: {}", web_client_url))?;

    let device_code_id_validated = Uuid::parse_str(device_code_id).with_context(|| {
        format!(
            "invalid device_code_id: {}; must be a valid UUID",
            device_code_id
        )
    })?;

    let mut segments = url
        .path_segments_mut()
        .map_err(|_| anyhow!("web_client_url cannot be a base URL"))?;

    segments.pop_if_empty();
    segments.push("index.html");

    drop(segments);

    let fragment = format!(
        "/device/{}/{}",
        device_code_id_validated,
        hex::encode(secret_box_key)
    );
    url.set_fragment(Some(&fragment));

    Ok(url.to_string())
}

fn select_api_key(api_keys: &[ApiKeyListItem], non_interactive: bool) -> Result<ApiKeyListItem> {
    select_api_key_with(
        api_keys,
        non_interactive,
        io::stdin().is_terminal(),
        io::stderr().is_terminal(),
        select_api_key_tui,
        select_api_key_plain,
    )
}

fn select_api_key_with<TuiSelector, PlainSelector>(
    api_keys: &[ApiKeyListItem],
    non_interactive: bool,
    stdin_is_terminal: bool,
    stderr_is_terminal: bool,
    select_tui: TuiSelector,
    select_plain: PlainSelector,
) -> Result<ApiKeyListItem>
where
    TuiSelector:
        FnOnce(&[ApiKeyListItem]) -> std::result::Result<ApiKeyListItem, TuiSelectionError>,
    PlainSelector: FnOnce(&[ApiKeyListItem]) -> Result<ApiKeyListItem>,
{
    if !non_interactive && stdin_is_terminal && stderr_is_terminal {
        match select_tui(api_keys) {
            Ok(selected) => return Ok(selected),
            Err(TuiSelectionError::TuiFailed(err)) => {
                eprintln!("psonoci warning: falling back to plain selector: {err}");
            }
            Err(TuiSelectionError::Cancelled) => bail!("api key selection cancelled"),
            Err(TuiSelectionError::Interrupted) => process::exit(130),
        }
    }

    select_plain(api_keys)
}

fn select_api_key_plain(api_keys: &[ApiKeyListItem]) -> Result<ApiKeyListItem> {
    ensure_interactive_api_key_selection(io::stdin().is_terminal())?;

    let title_width = api_key_title_column_width(api_keys);

    for (index, api_key) in api_keys.iter().enumerate() {
        let safe_title = sanitize_terminal_text(&api_key.title);
        eprintln!(
            "{}) {}  [{}]",
            index + 1,
            pad_title(&safe_title, title_width),
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

fn ensure_interactive_api_key_selection(stdin_is_terminal: bool) -> Result<()> {
    if !stdin_is_terminal {
        bail!("Cannot interactively select an API key in a non-interactive environment");
    }

    Ok(())
}

fn select_api_key_tui(
    api_keys: &[ApiKeyListItem],
) -> std::result::Result<ApiKeyListItem, TuiSelectionError> {
    let mut terminal =
        ApiKeySelectorTerminal::acquire(api_keys).map_err(TuiSelectionError::TuiFailed)?;
    let mut selector_state = ApiKeySelectorState::new(api_keys);
    let selection = run_api_key_tui_loop(terminal.terminal_mut(), api_keys, &mut selector_state);
    terminal.cleanup().map_err(TuiSelectionError::TuiFailed)?;

    match selection.map_err(TuiSelectionError::TuiFailed)? {
        SelectorOutcome::Selected(api_key) => Ok(api_key),
        SelectorOutcome::Cancelled => Err(TuiSelectionError::Cancelled),
        SelectorOutcome::Interrupted => Err(TuiSelectionError::Interrupted),
    }
}

fn run_api_key_tui_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stderr>>,
    api_keys: &[ApiKeyListItem],
    selector_state: &mut ApiKeySelectorState,
) -> Result<SelectorOutcome> {
    let mut needs_redraw = true;

    loop {
        if needs_redraw {
            terminal
                .draw(|frame| draw_api_key_selector(frame, api_keys, selector_state))
                .context("drawing onboarding selector failed")?;
            needs_redraw = false;
        }

        match event::read().context("reading terminal event failed")? {
            Event::Resize(_, _) => {
                terminal
                    .autoresize()
                    .context("resizing onboarding selector terminal failed")?;
                terminal
                    .clear()
                    .context("clearing resized onboarding selector terminal failed")?;
                needs_redraw = true;
            }
            Event::Key(key) => {
                if key.kind != KeyEventKind::Press {
                    continue;
                }

                let Some(action) = selector_action_from_key_event(key) else {
                    continue;
                };

                needs_redraw |= match action {
                    SelectorAction::MoveUp => selector_state.move_selection_by(-1),
                    SelectorAction::MoveDown => selector_state.move_selection_by(1),
                    SelectorAction::JumpToTop => selector_state.move_to_start(),
                    SelectorAction::JumpToBottom => selector_state.move_to_end(),
                    SelectorAction::JumpToIndex(index) => selector_state.jump_to(index),
                    SelectorAction::Backspace => selector_state.pop_query(api_keys),
                    SelectorAction::Type(ch) => selector_state.push_query(ch, api_keys),
                    SelectorAction::Confirm => {
                        let Some(selected) = selector_state.selected_api_key(api_keys) else {
                            continue;
                        };
                        return Ok(SelectorOutcome::Selected(selected.clone()));
                    }
                    SelectorAction::Cancel => return Ok(SelectorOutcome::Cancelled),
                    SelectorAction::Interrupt => return Ok(SelectorOutcome::Interrupted),
                };
            }
            _ => continue,
        }
    }
}

fn selector_action_from_key_event(key: KeyEvent) -> Option<SelectorAction> {
    match (key.code, key.modifiers) {
        (KeyCode::Char('c'), modifiers) if modifiers.contains(KeyModifiers::CONTROL) => {
            Some(SelectorAction::Interrupt)
        }
        (KeyCode::Up, _) => Some(SelectorAction::MoveUp),
        (KeyCode::Char('k'), modifiers) if modifiers.contains(KeyModifiers::CONTROL) => {
            Some(SelectorAction::MoveUp)
        }
        (KeyCode::Down, _) => Some(SelectorAction::MoveDown),
        (KeyCode::Char('j'), modifiers) if modifiers.contains(KeyModifiers::CONTROL) => {
            Some(SelectorAction::MoveDown)
        }
        (KeyCode::Home, _) => Some(SelectorAction::JumpToTop),
        (KeyCode::End, _) => Some(SelectorAction::JumpToBottom),
        (KeyCode::F(n @ 1..=9), _) => Some(SelectorAction::JumpToIndex(usize::from(n - 1))),
        (KeyCode::Backspace, _) => Some(SelectorAction::Backspace),
        (KeyCode::Char(c), modifiers)
            if !modifiers.contains(KeyModifiers::CONTROL)
                && !modifiers.contains(KeyModifiers::ALT) =>
        {
            Some(SelectorAction::Type(c))
        }
        (KeyCode::Enter, _) => Some(SelectorAction::Confirm),
        (KeyCode::Esc, _) | (KeyCode::Char('q'), _) => Some(SelectorAction::Cancel),
        _ => None,
    }
}

fn cleanup_tui_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stderr>>) -> Result<()> {
    terminal
        .clear()
        .context("clearing onboarding selector terminal failed")?;
    terminal
        .show_cursor()
        .context("showing terminal cursor failed")?;
    io::stderr().flush().context("flushing stderr failed")?;
    Ok(())
}

fn inline_viewport_height(item_count: usize) -> u16 {
    let desired = item_count.saturating_add(7);
    desired.clamp(9, 17) as u16
}

fn draw_api_key_selector(
    frame: &mut ratatui::Frame<'_>,
    api_keys: &[ApiKeyListItem],
    selector_state: &mut ApiKeySelectorState,
) {
    let selector_items = build_api_key_selector_items(api_keys, &selector_state.filtered_indices);
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(4),
        ])
        .split(frame.area());

    frame.render_widget(
        Paragraph::new("Select API Key")
            .block(Block::default().borders(Borders::BOTTOM))
            .style(Style::default().add_modifier(Modifier::BOLD)),
        areas[0],
    );

    frame.render_widget(
        Paragraph::new(
            "  Up/Down or Ctrl-J/Ctrl-K to move, F1..F9 to jump, Enter to confirm, Esc to cancel",
        ),
        areas[1],
    );

    frame.render_widget(
        Paragraph::new(format!("  Search: {}", selector_state.query)),
        areas[2],
    );

    let cursor_x = areas[2]
        .x
        .saturating_add(10)
        .saturating_add(selector_state.query.chars().count() as u16);
    frame.set_cursor_position((cursor_x, areas[2].y));

    let list = List::new(selector_items.iter().cloned())
        .block(Block::default().borders(Borders::ALL))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD))
        .highlight_symbol("> ");

    frame.render_stateful_widget(list, areas[3], &mut selector_state.list_state);
}

fn build_api_key_selector_items(
    api_keys: &[ApiKeyListItem],
    filtered_indices: &[usize],
) -> Vec<ListItem<'static>> {
    let title_width = api_key_title_column_width(api_keys);

    if filtered_indices.is_empty() {
        return vec![ListItem::new(Line::from(vec![Span::raw(
            "  No API keys match the current search.",
        )]))];
    }

    filtered_indices
        .iter()
        .enumerate()
        .map(|(index, api_key_index)| {
            let api_key = &api_keys[*api_key_index];
            let safe_title = sanitize_terminal_text(&api_key.title);
            ListItem::new(Line::from(vec![
                Span::raw(format!("{:>2}. ", index + 1)),
                Span::raw(pad_title(&safe_title, title_width)),
                Span::raw("  "),
                Span::raw(format!("[{}]", format_api_key_flags(api_key))),
            ]))
        })
        .collect()
}

fn filter_api_keys(api_keys: &[ApiKeyListItem], query: &str) -> Vec<usize> {
    let normalized_query = query.to_ascii_lowercase();

    api_keys
        .iter()
        .enumerate()
        .filter(|(_, api_key)| {
            normalized_query.is_empty()
                || api_key
                    .title
                    .to_ascii_lowercase()
                    .contains(&normalized_query)
        })
        .map(|(index, _)| index)
        .collect()
}

fn api_key_title_column_width(api_keys: &[ApiKeyListItem]) -> usize {
    api_keys
        .iter()
        .map(|api_key| sanitize_terminal_text(&api_key.title).chars().count())
        .max()
        .unwrap_or(0)
}

fn sanitize_terminal_text(text: &str) -> String {
    text.chars()
        .map(|ch| if ch.is_control() { '?' } else { ch })
        .collect()
}

fn pad_title(title: &str, width: usize) -> String {
    format!("{title:<width$}")
}

fn move_selection(state: &mut ListState, len: usize, delta: isize) {
    if len == 0 {
        state.select(None);
        return;
    }

    let current = state.selected().unwrap_or(0) as isize;
    let next = (current + delta).clamp(0, len.saturating_sub(1) as isize) as usize;
    state.select(Some(next));
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
    use std::io::Cursor;

    use anyhow::anyhow;
    use tempfile::tempdir;

    use super::*;

    fn debug_api_key(title: &str) -> ApiKeyListItem {
        ApiKeyListItem {
            id: Uuid::new_v4(),
            title: title.to_string(),
            restrict_to_secrets: false,
            allow_insecure_access: false,
            read: true,
            write: false,
            active: true,
        }
    }

    fn debug_onboard_command(
        path: Option<PathBuf>,
        stdout: bool,
        overwrite: bool,
    ) -> OnboardCommand {
        OnboardCommand {
            path,
            stdout,
            plain: false,
            format: OnboardOutputFormat::Toml,
            polling_timeout: 60,
            polling_interval: 3,
            overwrite,
        }
    }

    #[test]
    fn build_approval_url_uses_web_client_url() {
        let key = [0u8; 32];
        let url = build_approval_url(
            "https://frontend.example.com/app",
            "123e4567-e89b-12d3-a456-426614174000",
            &key,
        )
        .unwrap();

        assert_eq!(
            url,
            "https://frontend.example.com/app/index.html#/device/123e4567-e89b-12d3-a456-426614174000/0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn validate_web_client_url_accepts_https_url() {
        let url = validate_web_client_url("https://frontend.example.com/app").unwrap();

        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("frontend.example.com"));
        assert_eq!(url.path(), "/app");
    }

    #[test]
    fn validate_web_client_url_accepts_localhost_http() {
        let url = validate_web_client_url("http://localhost:3000/app").unwrap();

        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host_str(), Some("localhost"));
        assert_eq!(url.port(), Some(3000));
    }

    #[test]
    fn validate_web_client_url_rejects_non_https_non_localhost() {
        let err = validate_web_client_url("http://frontend.example.com/app").unwrap_err();

        assert_eq!(
            err.to_string(),
            "web_client_url must use https unless host is localhost"
        );
    }

    #[test]
    fn validate_web_client_url_rejects_javascript_scheme() {
        let err = validate_web_client_url("javascript:alert(1)").unwrap_err();

        assert_eq!(
            err.to_string(),
            "web_client_url must use https unless host is localhost"
        );
    }

    #[test]
    fn validate_web_client_url_rejects_data_scheme() {
        let err = validate_web_client_url("data:text/html,evil").unwrap_err();

        assert_eq!(
            err.to_string(),
            "web_client_url must use https unless host is localhost"
        );
    }

    #[test]
    fn validate_web_client_url_accepts_loopback_ip_http() {
        let ipv4_url = validate_web_client_url("http://127.0.0.1:3000/app").unwrap();
        assert_eq!(ipv4_url.host_str(), Some("127.0.0.1"));

        let ipv6_url = validate_web_client_url("http://[::1]:3000/app").unwrap();
        assert!(matches!(ipv6_url.host_str(), Some("::1") | Some("[::1]")));
    }

    #[test]
    fn validate_web_client_url_rejects_embedded_credentials() {
        let err =
            validate_web_client_url("https://user:pass@frontend.example.com/app").unwrap_err();

        assert_eq!(
            err.to_string(),
            "web_client_url must not include username or password"
        );
    }

    #[test]
    fn validate_web_client_url_rejects_query_and_fragment() {
        let err = validate_web_client_url("https://frontend.example.com/app?next=1").unwrap_err();
        assert_eq!(
            err.to_string(),
            "web_client_url must not include query parameters"
        );

        let err =
            validate_web_client_url("https://frontend.example.com/app#/existing").unwrap_err();
        assert_eq!(
            err.to_string(),
            "web_client_url must not include a fragment"
        );
    }

    #[test]
    fn build_approval_url_rejects_invalid_web_client_url() {
        let key = [0u8; 32];
        let err = build_approval_url(
            "javascript:alert(1)",
            "123e4567-e89b-12d3-a456-426614174000",
            &key,
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid web_client_url: javascript:alert(1)"
        );
    }

    #[test]
    fn build_approval_url_rejects_invalid_device_code_id() {
        let key = [0u8; 32];
        let err =
            build_approval_url("https://frontend.example.com/app", "not-a-uuid", &key).unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid device_code_id: not-a-uuid; must be a valid UUID"
        );
    }

    #[test]
    #[cfg(unix)]
    fn write_debug_api_key_cache_file_sets_user_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let path = dir.path().join("onboarding-api-keys.json");

        write_debug_api_key_cache_file(&path, br#"{"server_url":"https://example.com"}"#).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn validate_output_path_accepts_new_file_in_existing_directory() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");

        validate_output_path(Some(&path), false).unwrap();
    }

    #[test]
    fn validate_output_path_rejects_existing_file_without_overwrite() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "existing").unwrap();

        let err = validate_output_path(Some(&path), false).unwrap_err();

        assert_eq!(
            err.to_string(),
            "output path already exists and overwrite is not set"
        );
    }

    #[test]
    fn validate_output_path_accepts_existing_file_with_overwrite() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "existing").unwrap();

        validate_output_path(Some(&path), true).unwrap();
    }

    #[test]
    fn validate_output_path_rejects_missing_parent_directory() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("missing").join("config.toml");

        let err = validate_output_path(Some(&path), false).unwrap_err();

        assert_eq!(
            err.to_string(),
            format!(
                "output parent directory does not exist: {}",
                path.parent().unwrap().display()
            )
        );
    }

    #[test]
    fn validate_output_path_rejects_directory_path() {
        let dir = tempdir().unwrap();

        let err = validate_output_path(Some(dir.path()), false).unwrap_err();

        assert_eq!(
            err.to_string(),
            format!("output path is a directory: {}", dir.path().display())
        );
    }

    #[test]
    fn validate_output_path_rejects_non_directory_parent() {
        let dir = tempdir().unwrap();
        let parent = dir.path().join("parent-file");
        std::fs::write(&parent, "not a directory").unwrap();
        let path = parent.join("config.toml");

        let err = validate_output_path(Some(&path), false).unwrap_err();

        assert_eq!(
            err.to_string(),
            format!(
                "output parent path is not a directory: {}",
                parent.display()
            )
        );
    }

    #[test]
    fn run_onboard_command_rejects_missing_output_parent_before_onboarding() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("missing").join("config.toml");
        let command = debug_onboard_command(Some(path.clone()), false, false);

        let err = run_onboard_command(
            Some(Url::parse("https://backend.example.com/server").unwrap()),
            HttpOptions::default(),
            command,
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            format!(
                "output parent directory does not exist: {}",
                path.parent().unwrap().display()
            )
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
    fn endpoint_url_normalizes_repeated_slashes() {
        let server_url = Url::parse("https://backend.example.com/server/").unwrap();
        let endpoint = endpoint_url(&server_url, "device-code//poll").unwrap();

        assert_eq!(
            endpoint.as_str(),
            "https://backend.example.com/server/device-code/poll"
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
    fn poll_for_token_times_out_before_request_when_timeout_is_zero() {
        let client = Client::builder().build().unwrap();
        let server_secret_key = SecretKey::generate(&mut OsRng);
        let temp_secret_key = SecretKey::generate(&mut OsRng);
        let salsa_box = SalsaBox::new(&server_secret_key.public_key(), &temp_secret_key);
        let server_url = Url::parse("https://backend.example.com/server").unwrap();

        let err = poll_for_token(
            &client,
            &server_url,
            "123e4567-e89b-12d3-a456-426614174000",
            &salsa_box,
            Duration::from_secs(0),
            Duration::from_secs(3),
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "device approval polling timed out after 0 seconds"
        );
    }

    #[test]
    fn resolve_server_url_returns_supplied_value() {
        let server_url = Url::parse("https://backend.example.com/server").unwrap();

        let resolved = resolve_server_url(Some(server_url.clone())).unwrap();

        assert_eq!(resolved, server_url);
    }

    #[test]
    fn prompt_for_server_url_rejects_non_interactive_stdin() {
        let err = ensure_interactive_server_url_prompt(false).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Cannot interactively enter a server url in a non-interactive environment"
        );
    }

    #[test]
    fn prompt_for_server_url_with_empty_input_uses_default() {
        let mut input = Cursor::new(b"\n");
        let mut output = Vec::new();

        let server_url = prompt_for_server_url_with(&mut input, &mut output).unwrap();

        assert_eq!(server_url.as_str(), DEFAULT_PSONO_SERVER_URL);
        assert_eq!(
            String::from_utf8(output).unwrap(),
            format!("Enter server url [{}]: ", DEFAULT_PSONO_SERVER_URL)
        );
    }

    #[test]
    fn prompt_for_server_url_with_invalid_input_retries_until_valid() {
        let mut input = Cursor::new(b"not-a-url\nhttps://backend.example.com/server\n");
        let mut output = Vec::new();

        let server_url = prompt_for_server_url_with(&mut input, &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();

        assert_eq!(server_url.as_str(), "https://backend.example.com/server");
        assert!(output.contains("Invalid server url:"));
        assert_eq!(
            output
                .matches("Enter server url [https://www.psono.pw/server]: ")
                .count(),
            2
        );
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

    #[test]
    fn inline_viewport_height_is_bounded() {
        assert_eq!(inline_viewport_height(1), 9);
        assert_eq!(inline_viewport_height(8), 15);
        assert_eq!(inline_viewport_height(20), 17);
    }

    #[test]
    fn select_api_key_plain_rejects_non_interactive_stdin() {
        let err = ensure_interactive_api_key_selection(false).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Cannot interactively select an API key in a non-interactive environment"
        );
    }

    #[test]
    fn select_api_key_with_cancelled_tui_returns_error_without_plain_fallback() {
        let api_keys = vec![debug_api_key("CI")];

        let err = select_api_key_with(
            &api_keys,
            false,
            true,
            true,
            |_| Err(TuiSelectionError::Cancelled),
            |_| Err(anyhow!("plain selector should not be called")),
        )
        .unwrap_err();

        assert_eq!(err.to_string(), "api key selection cancelled");
    }

    #[test]
    fn select_api_key_with_tui_failure_falls_back_to_plain_selector() {
        let api_keys = vec![debug_api_key("CI"), debug_api_key("Deploy")];

        let selected = select_api_key_with(
            &api_keys,
            false,
            true,
            true,
            |_| Err(TuiSelectionError::TuiFailed(anyhow!("tui failed"))),
            |api_keys| Ok(api_keys[1].clone()),
        )
        .unwrap();

        assert_eq!(selected.title, "Deploy");
    }

    #[test]
    fn selector_action_from_key_event_maps_navigation_aliases() {
        assert_eq!(
            selector_action_from_key_event(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE)),
            Some(SelectorAction::MoveUp)
        );
        assert_eq!(
            selector_action_from_key_event(KeyEvent::new(
                KeyCode::Char('k'),
                KeyModifiers::CONTROL,
            )),
            Some(SelectorAction::MoveUp)
        );
        assert_eq!(
            selector_action_from_key_event(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE)),
            Some(SelectorAction::MoveDown)
        );
        assert_eq!(
            selector_action_from_key_event(KeyEvent::new(
                KeyCode::Char('j'),
                KeyModifiers::CONTROL,
            )),
            Some(SelectorAction::MoveDown)
        );
        assert_eq!(
            selector_action_from_key_event(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::ALT)),
            None
        );
    }

    #[test]
    fn api_key_selector_state_query_mutation_refreshes_filter() {
        let api_keys = vec![debug_api_key("CI"), debug_api_key("Deploy")];
        let mut state = ApiKeySelectorState::new(&api_keys);

        assert!(state.push_query('d', &api_keys));
        assert_eq!(state.query, "d");
        assert_eq!(state.filtered_indices, vec![1]);
        assert_eq!(state.list_state.selected(), Some(0));

        assert!(state.pop_query(&api_keys));
        assert_eq!(state.query, "");
        assert_eq!(state.filtered_indices, vec![0, 1]);
        assert_eq!(state.list_state.selected(), Some(0));

        assert!(!state.pop_query(&api_keys));
    }

    #[test]
    fn move_selection_clamps_to_bounds() {
        let mut state = ListState::default();
        state.select(Some(0));

        move_selection(&mut state, 3, -1);
        assert_eq!(state.selected(), Some(0));

        move_selection(&mut state, 3, 2);
        assert_eq!(state.selected(), Some(2));

        move_selection(&mut state, 3, 2);
        assert_eq!(state.selected(), Some(2));
    }

    #[test]
    fn pad_title_aligns_shorter_titles() {
        assert_eq!(pad_title("CI", 6), "CI    ");
        assert_eq!(pad_title("staging", 6), "staging");
    }

    #[test]
    fn filter_api_keys_matches_case_insensitive_titles() {
        let api_keys = vec![
            ApiKeyListItem {
                id: Uuid::nil(),
                title: "CI Staging".to_string(),
                restrict_to_secrets: false,
                allow_insecure_access: false,
                read: true,
                write: false,
                active: true,
            },
            ApiKeyListItem {
                id: Uuid::nil(),
                title: "Deploy".to_string(),
                restrict_to_secrets: false,
                allow_insecure_access: false,
                read: true,
                write: true,
                active: true,
            },
        ];

        assert_eq!(filter_api_keys(&api_keys, "stAg"), vec![0]);
        assert_eq!(filter_api_keys(&api_keys, ""), vec![0, 1]);
    }

    #[test]
    fn sanitize_terminal_text_replaces_control_characters() {
        assert_eq!(sanitize_terminal_text("ok\n\tname\u{7f}"), "ok??name?");
    }

    #[test]
    fn decrypt_token_payload_rejects_oversized_nonce() {
        let server_secret_key = SecretKey::generate(&mut OsRng);
        let temp_secret_key = SecretKey::generate(&mut OsRng);
        let salsa_box = SalsaBox::new(&server_secret_key.public_key(), &temp_secret_key);
        let token_response = TokenResponse {
            boxed_payload: String::new(),
            nonce: hex::encode([0u8; NONCE_LENGTH + 1]),
        };

        let err = decrypt_token_payload_with_salsa_box(&token_response, &salsa_box).unwrap_err();

        assert_eq!(
            err.to_string(),
            format!(
                "invalid token nonce length; supplied: {}, required: {}",
                NONCE_LENGTH + 1,
                NONCE_LENGTH
            )
        );
    }

    #[test]
    fn compute_shared_secret_rejects_oversized_public_key() {
        let temp_secret_key = SecretKey::generate(&mut OsRng);
        let err = compute_shared_secret(&hex::encode([0u8; KEY_SIZE + 1]), &temp_secret_key)
            .err()
            .unwrap();

        assert_eq!(
            err.to_string(),
            format!(
                "invalid server public key length; supplied: {}, required: {}",
                KEY_SIZE + 1,
                KEY_SIZE
            )
        );
    }
}
