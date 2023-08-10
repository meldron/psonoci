use anyhow::{anyhow, bail, Context, Result};
use totp_rs::{Algorithm, Secret as TotpSecret, TOTP};
use uuid::Uuid;

use crate::{
    api::{get_secret, Secret as PsonoSecret, SecretType, TOTP as TOTPSecret},
    config::Config,
    opt::TotpCommand,
};

fn parse_algorithm(s: &str) -> Result<Algorithm> {
    match s.to_uppercase().as_str() {
        "SHA1" => Ok(Algorithm::SHA1),
        "SHA256" => Ok(Algorithm::SHA256),
        "SHA512" => Ok(Algorithm::SHA512),
        _ => Err(anyhow!("Unsupported Algorithm: {}", s)),
    }
}

pub fn is_valid_totp_algorithm(s: &str) -> bool {
    match s.to_uppercase().as_str() {
        "SHA1" | "SHA256" | "SHA512" => true,
        _ => false,
    }
}

pub fn is_valid_totp_digit(d: u32) -> bool {
    (6..=8).contains(&d)
}

fn create_totp(
    totp_secret: &TOTPSecret,
    issuer: Option<String>,
    account_name: Option<String>,
) -> Result<TOTP> {
    let algorithm_raw = totp_secret
        .algorithm
        .as_ref()
        .ok_or_else(|| anyhow!("algorithm is not set"))?;

    let algorithm = parse_algorithm(&algorithm_raw)?;

    let digits = totp_secret
        .digits
        .ok_or_else(|| anyhow!("digits is not set"))?;

    let period = totp_secret
        .period
        .ok_or_else(|| anyhow!("period is not set"))?;

    let code = totp_secret
        .code
        .as_ref()
        .ok_or_else(|| anyhow!("code is not set"))?;

    let totp_secret = TotpSecret::Encoded(code.to_owned())
        .to_bytes()
        .map_err(|e| anyhow!(e))?;

    TOTP::new(
        algorithm,
        digits as usize,
        1,
        period as u64,
        totp_secret,
        issuer,
        account_name.unwrap_or("".to_owned()),
    )
    .context("Could not create TOTP Instance")
}

fn get_token_secret(secret_id: &Uuid, config: &Config) -> Result<(PsonoSecret, String)> {
    let (secret, secret_key_hex) = get_secret(&secret_id, &config)
        .context("get_token_secret loading secret from store failed")?;

    if secret.secret_type != SecretType::TOTP {
        bail!("The specified secret is not an TOTP secret");
    }

    Ok((secret, secret_key_hex))
}

fn get_totp(
    secret_id: &Uuid,
    issuer: Option<String>,
    account_name: Option<String>,
    config: &Config,
) -> Result<TOTP> {
    let (secret, _) = get_token_secret(&secret_id, &config)?;
    let totp_secret = secret.totp.ok_or_else(|| anyhow!("totp data not set"))?;

    create_totp(&totp_secret, issuer, account_name)
}

fn generate_token(totp: &TOTP) -> Result<String> {
    totp.generate_current().map_err(|e| anyhow!(e))
}

fn print_token_command(secret_id: Uuid, config: Config) -> Result<()> {
    let totp = get_totp(&secret_id, None, None, &config)?;

    let token = generate_token(&totp)?;

    print!("{}", token);

    Ok(())
}

fn print_totp_url(
    secret_id: Uuid,
    issuer: Option<String>,
    account_name: Option<String>,
    config: Config,
) -> Result<()> {
    let totp = get_totp(&secret_id, issuer, account_name, &config)?;

    let url = totp.get_url();

    print!("{}", url);

    Ok(())
}

fn validate_totp_token(secret_id: Uuid, config: Config, token: String) -> Result<()> {
    let totp = get_totp(&secret_id, None, None, &config)?;

    let valid = totp.check_current(&token)?;

    match valid {
        true => {}
        false => bail!("token invalid"),
    }

    Ok(())
}

pub fn run_totp_command(totp_command: TotpCommand, config: Config) -> Result<()> {
    match totp_command {
        TotpCommand::GetToken { secret_id } => print_token_command(secret_id, config)?,
        TotpCommand::GetUrl {
            secret_id,
            issuer,
            account_name,
        } => print_totp_url(secret_id, issuer, account_name, config)?,
        TotpCommand::ValidateToken { secret_id, token } => {
            validate_totp_token(secret_id, config, token)?
        }
    };

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
}
