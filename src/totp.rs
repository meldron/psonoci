use anyhow::{Context, Result, anyhow, bail};
use totp_rs::{Algorithm, Secret as TotpSecret, TOTP};
use uuid::Uuid;

use crate::{
    api::{Secret as PsonoSecret, SecretType, Totp as TOTPSecret, get_secret},
    config::Config,
    opt::TotpCommand,
    sensitive::SensitiveString,
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
    matches!(s.to_uppercase().as_str(), "SHA1" | "SHA256" | "SHA512")
}

pub fn is_valid_totp_digit(d: u32) -> bool {
    (6..=8).contains(&d)
}

fn create_totp(
    totp_secret: &TOTPSecret,
    issuer: Option<String>,
    account_name: Option<String>,
    allow_short_seed: bool,
) -> Result<TOTP> {
    let algorithm_raw = totp_secret
        .algorithm
        .as_ref()
        .ok_or_else(|| anyhow!("algorithm is not set"))?;

    let algorithm = parse_algorithm(algorithm_raw)?;

    let digits = totp_secret
        .digits
        .ok_or_else(|| anyhow!("digits is not set"))?;

    let period = totp_secret
        .period
        .ok_or_else(|| anyhow!("period is not set"))?;
    if period == 0 {
        bail!("TOTP period must be greater than zero");
    }

    let code = totp_secret
        .code
        .as_ref()
        .ok_or_else(|| anyhow!("code is not set"))?;

    let totp_secret = TotpSecret::Encoded(code.to_owned())
        .to_bytes()
        .map_err(|e| anyhow!(e))?;
    let account_name = account_name.unwrap_or_default();

    if allow_short_seed {
        // Psono accepts existing website seeds shorter than the library's
        // 128-bit minimum. Keep all other constructor checks for this path.
        if !is_valid_totp_digit(digits) {
            bail!("Could not create TOTP Instance: digits must be between 6 and 8");
        }
        if totp_secret.is_empty() {
            bail!("TOTP seed is empty");
        }
        if issuer.as_ref().is_some_and(|value| value.contains(':')) || account_name.contains(':') {
            bail!("TOTP issuer and account name must not contain ':'");
        }
        return Ok(TOTP::new_unchecked(
            algorithm,
            digits as usize,
            1,
            period as u64,
            totp_secret,
            issuer,
            account_name,
        ));
    }

    TOTP::new(
        algorithm,
        digits as usize,
        1,
        period as u64,
        totp_secret,
        issuer,
        account_name,
    )
    .context("Could not create TOTP Instance")
}

fn get_token_secret(secret_id: &Uuid, config: &Config) -> Result<(PsonoSecret, SensitiveString)> {
    let (secret, secret_key_hex) = get_secret(secret_id, config)
        .context("get_token_secret loading secret from store failed")?;

    if !matches!(secret.secret_type, SecretType::Totp | SecretType::Website) {
        bail!("The specified secret is not a TOTP or website secret");
    }

    Ok((secret, secret_key_hex))
}

fn get_totp(
    secret_id: &Uuid,
    issuer: Option<String>,
    account_name: Option<String>,
    config: &Config,
) -> Result<TOTP> {
    let (secret, _) = get_token_secret(secret_id, config)?;
    let mut totp_secret = secret.totp.ok_or_else(|| anyhow!("TOTP data is not set"))?;
    if secret.secret_type == SecretType::Website {
        // Psono's website authenticator uses these defaults for absent/falsy settings.
        totp_secret.period = Some(totp_secret.period.filter(|value| *value != 0).unwrap_or(30));
        totp_secret.digits = Some(totp_secret.digits.filter(|value| *value != 0).unwrap_or(6));
        totp_secret.algorithm = Some(
            totp_secret
                .algorithm
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "SHA1".into()),
        );
    }

    create_totp(
        &totp_secret,
        issuer,
        account_name,
        secret.secret_type == SecretType::Website,
    )
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

    #[test]
    fn standalone_totp_still_matches_rfc_6238() {
        let totp = create_totp(
            &TOTPSecret {
                algorithm: Some("SHA1".into()),
                digits: Some(8),
                period: Some(30),
                code: Some("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into()),
            },
            None,
            None,
            false,
        )
        .unwrap();
        for (time, expected) in [
            (59, "94287082"),
            (1111111109, "07081804"),
            (2000000000, "69279037"),
        ] {
            assert_eq!(totp.generate(time), expected);
        }
    }

    #[test]
    fn zero_period_returns_an_error_before_generating_a_token() {
        let result = create_totp(
            &TOTPSecret {
                algorithm: Some("SHA1".into()),
                digits: Some(6),
                period: Some(0),
                code: Some("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into()),
            },
            None,
            None,
            false,
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("period must be greater than zero")
        );
    }

    #[test]
    fn website_accepts_psonos_short_seeds_without_relaxing_other_checks() {
        let secret = TOTPSecret {
            algorithm: Some("SHA1".into()),
            digits: Some(6),
            period: Some(30),
            code: Some("JBSWY3DPEHPK3PXP".into()),
        };
        let totp = create_totp(&secret, None, None, true).unwrap();
        assert_eq!(totp.generate(59), "996554");
        assert!(totp.get_url().contains("secret=JBSWY3DPEHPK3PXP"));
        assert!(create_totp(&secret, None, None, false).is_err());
        assert!(create_totp(&secret, Some("bad:issuer".into()), None, true).is_err());
        assert!(create_totp(&secret, None, Some("bad:account".into()), true).is_err());
        for secret in [
            TOTPSecret {
                code: Some("".into()),
                ..secret.clone()
            },
            TOTPSecret {
                digits: Some(5),
                ..secret.clone()
            },
        ] {
            assert!(create_totp(&secret, None, None, true).is_err());
        }
    }
}
