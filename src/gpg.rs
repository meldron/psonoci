use crate::api::SecretType;
use crate::config::Config;
use crate::opt::{GpgCommand, GpgSignCommand, GpgVerifyCommand};
use crate::secret_provider::{PsonoSecretProvider, SecretProvider};
use anyhow::{bail, Context, Result};
use chrono::Local;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::packet::{SignatureConfig, SignatureType, Subpacket, SubpacketData};
use pgp::ser::Serialize;
use pgp::types::PublicKeyTrait;
use pgp::{
    packet, ArmorOptions, Deserializable, SignedPublicKey, SignedSecretKey, StandaloneSignature,
};
use std::fs::File;
use std::io::{stdin, stdout, Read, Write};
use std::path::PathBuf;
use std::process::exit;
use uuid::Uuid;

fn get_gpg_key_pair(
    secret_id: &Uuid,
    config: &Config,
    secret_provider: Box<dyn SecretProvider>,
) -> Result<(Option<String>, Option<String>)> {
    let (secret, _) = secret_provider
        .get_secret(secret_id, config)
        .context("ssh_agent_add_identity loading secret from store failed")?;

    if secret.secret_type != SecretType::GPGKey {
        bail!("the specified secret is not an GPGKey secret");
    }

    Ok((secret.gpg_key_private, secret.gpg_key_public))
}

fn get_signed_public_key(gpg_key_public_raw: Option<String>) -> Result<SignedPublicKey> {
    let gpg_key_public = gpg_key_public_raw.context("gpg_key_public not set for secret")?;

    let (signed_public_key, _) = SignedPublicKey::from_string(&gpg_key_public)
        .context("failed to decode gpg_key_private")?;

    Ok(signed_public_key)
}

fn get_signed_secret_key(gpg_key_private_raw: Option<String>) -> Result<SignedSecretKey> {
    let gpg_key_private = gpg_key_private_raw.context("gpg_key_private not set for secret")?;

    let (signed_secret_key, _) = SignedSecretKey::from_string(&gpg_key_private)
        .context("failed to decode gpg_key_private")?;

    Ok(signed_secret_key)
}

fn create_signature(
    signed_secret_key: &SignedSecretKey,
    input_reader: Box<dyn Read>,
) -> Result<StandaloneSignature> {
    let now = chrono::Utc::now();
    let mut sig_cfg = SignatureConfig::v4(
        SignatureType::Binary,
        PublicKeyAlgorithm::RSA,
        HashAlgorithm::SHA2_256,
    );
    sig_cfg.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(now)),
        Subpacket::regular(SubpacketData::Issuer(signed_secret_key.key_id())),
    ];

    let signature_packet = sig_cfg
        .sign(&signed_secret_key, || "".to_string(), input_reader)
        .context("Signing failed:")?;

    let mut signature_bytes = Vec::with_capacity(1024);
    packet::write_packet(&mut signature_bytes, &signature_packet)
        .context("serializing signature failed")?;

    Ok(StandaloneSignature::new(signature_packet))
}

fn get_locked_stdin() -> Box<dyn Read + 'static> {
    Box::new(stdin().lock())
}

/**
 * Create a reader from an input file if provided,
 * otherwise use stdin.
 */
fn get_input_reader<R>(input_file_path: &Option<PathBuf>, stdin: Box<R>) -> Result<Box<dyn Read>>
where
    R: Read + 'static + ?Sized,
{
    let reader: Box<dyn Read> = if let Some(input_file_path) = input_file_path {
        let file = File::open(input_file_path).context("opening input file failed")?;
        Box::new(file)
    } else {
        Box::new(stdin)
    };

    Ok(reader)
}

fn format_signature(signature: StandaloneSignature, armored: bool) -> Result<Vec<u8>> {
    let formatted_signature = if armored {
        signature
            .to_armored_bytes(ArmorOptions::default())
            .context("could not armor signature")?
    } else {
        signature
            .to_bytes()
            .context("could not serialize signature")?
    };

    Ok(formatted_signature)
}

fn gpg_sign(
    gpg_sign_command: GpgSignCommand,
    config: Config,
    secret_provider: Box<dyn SecretProvider>,
) -> Result<()> {
    let input_reader = get_input_reader(&gpg_sign_command.input_file, get_locked_stdin())?;

    let (gpg_key_private_key, _) =
        get_gpg_key_pair(&gpg_sign_command.secret_id, &config, secret_provider)
            .context("Loading gpg secret failed")?;
    let signed_secret_key = get_signed_secret_key(gpg_key_private_key)
        .context("Creating GPG signed secret key failed")?;

    let signature =
        create_signature(&signed_secret_key, input_reader).context("Creating signature failed")?;
    let signature_formatted = format_signature(signature, gpg_sign_command.armor)
        .context("output formatting signature failed")?;

    let mut output_target: Box<dyn Write> = if let Some(path) = gpg_sign_command.output {
        Box::new(File::create(path).context("could not create output file")?)
    } else {
        Box::new(stdout().lock())
    };

    output_target
        .write_all(&signature_formatted)
        .context("could not write signature")?;

    Ok(())
}

fn load_signature(signature_reader: Box<dyn Read>) -> Result<StandaloneSignature> {
    let (signature, _) = StandaloneSignature::from_reader_single(signature_reader)?;

    Ok(signature)
}

fn load_input(mut input_reader: Box<dyn Read>) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    input_reader
        .read_to_end(&mut buf)
        .context("reading input failed")?;

    Ok(buf)
}

fn format_success_message(
    signature: &StandaloneSignature,
    signed_public_key: &SignedPublicKey,
) -> String {
    let created_at = signature
        .signature
        .created()
        .map(|f| f.with_timezone(&Local).to_rfc3339())
        .unwrap_or("'".to_string());
    let created_by: String = signed_public_key
        .details
        .users
        .iter()
        .map(|u| u.id.to_string())
        .collect::<Vec<String>>()
        .join(", ");

    format!(
        "Signature made {}\nGood signature from {}",
        created_at, created_by
    )
}

fn gpg_verify(
    gpg_verify_command: GpgVerifyCommand,
    config: Config,
    secret_provider: Box<dyn SecretProvider>,
) -> Result<()> {
    let input_reader = get_input_reader(&gpg_verify_command.input_file, get_locked_stdin())?;
    let input = load_input(input_reader)?;

    let signature_reader =
        Box::new(File::open(gpg_verify_command.signature).context("Reading input file failed")?);
    let signature = load_signature(signature_reader)?;

    let (_, gpg_key_public_key) =
        get_gpg_key_pair(&gpg_verify_command.secret_id, &config, secret_provider)
            .context("Loading gpg secret failed")?;
    let signed_public_key = get_signed_public_key(gpg_key_public_key)
        .context("Creating GPG signed secret key failed")?;

    let is_valid = signature
        .verify(&signed_public_key, &input)
        .context("verify failed");

    if is_valid.is_ok() {
        if gpg_verify_command.verbose {
            let success_message = format_success_message(&signature, &signed_public_key);

            eprintln!("{}", success_message);
        }

        return Ok(());
    }

    if gpg_verify_command.quiet {
        exit(1)
    }

    is_valid
}

pub fn run_gpg_command(gpg_command: GpgCommand, config: Config) -> Result<()> {
    let secret_provider = Box::new(PsonoSecretProvider);

    match gpg_command {
        GpgCommand::Sign(gpg_sign_command) => gpg_sign(gpg_sign_command, config, secret_provider)?,
        GpgCommand::Verify(gpg_verify_command) => {
            gpg_verify(gpg_verify_command, config, secret_provider)?
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use super::*;
    use crate::api::Secret;
    use crate::config::tests::debug_config_v1;
    use crate::secret_provider::MockSecretProvider;
    use lazy_static::lazy_static;
    use mockall::predicate::eq;
    use std::env;
    use std::io::{BufReader, Cursor};
    use tempfile::NamedTempFile;

    lazy_static! {
        static ref GPG_PRIVATE_KEY: String = r#"-----BEGIN PGP PRIVATE KEY BLOCK-----

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
MNysAmOtzAVxzQ==
=GsSB
-----END PGP PRIVATE KEY BLOCK-----
"#
        .to_owned();
        static ref GPG_PUBLIC_KEY: String = r#"-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=4cxJ
-----END PGP PUBLIC KEY BLOCK-----
"#
        .to_owned();
        static ref SIGNATURE_RAW: String = r#"-----BEGIN PGP SIGNATURE-----

wsFcBAABCAAQBQJnJ96sCRCpIxER8wTwegAAZAcP+waW3J0SJxA5APspe6NZQcNz
mMLkaRFCoQLZ3Z0SWFte5w9g5OidiBF2j8vTG7Ppn5Z1grQhO+1xlivxFVU7t416
nBt/GOO+fhzw1gAduoiierMOuj2eQXhAkvjCv3KzB82g8LaxzxAvTWv0Iy0a+1i9
n9+LEQC6fqUdEpGShvnmUHgJiiB65wT2icULCHy7IZBe9Se6hV82UnjXvxxpJfhf
uzM2Xn0NZh1wKY4kZTAOCmTmvJiuz3D1vXSeB5ePbRK3P75Xv7zSZuNT/kCAvfjZ
MbKTEDyrup1fqIw1sTbPBKPkiqpIK+SHyIEBVxloc/e2/+y5vU7ZctLv28TIBIXn
BYi2RR3y6xxLBKBWjZJxwcjWrLnMGhW42TCY02C5T+ugMSSHgtukrVtC+noozzrk
4mdZrrdZVwQRoKih4ZRMt21vgQzKIz0NtCHaOfjnTHmnKKgcB/4yO+MUZ6m/TWTg
ynZ5UW/U+YMN7WkUTxjaheb4avvO4aT0dVb39R4USm+eDa2QqY7M2Ld63aBx2Pfs
Mth6hCcb7ra1le4m9EYSXDPj02tSfBEnhOhJSe9zqdpgNxeNr+Ygprcg5HYzQaBW
9K5mSq6enRSouvT22/vzI8s9aca0i/efr5rsGItep/zjeeOILpXmPAVvU/3xLz95
5WS3jvLnwhG4GlEokU98
=yWLA
-----END PGP SIGNATURE-----
"#
        .to_owned();
    }

    fn mock_gpg_key_secret(key_private: Option<String>, key_public: Option<String>) -> Secret {
        let mut secret = Secret::new(SecretType::GPGKey);

        secret.gpg_key_private = key_private;
        secret.gpg_key_public = key_public;

        secret
    }

    #[test]
    fn create_and_verify_signature__success() {
        let signed_secret_key = SignedSecretKey::from_string(&GPG_PRIVATE_KEY)
            .expect("decoding key failed")
            .0;

        let input = "Test".as_bytes();
        let input_reader: Box<dyn Read> = Box::new(BufReader::new(input));

        let signature =
            create_signature(&signed_secret_key, input_reader).expect("sig creation failed");

        let signed_public_key = SignedPublicKey::from_string(&GPG_PUBLIC_KEY)
            .expect("decoding key failed")
            .0;

        signature
            .verify(&signed_public_key, input)
            .expect("signature verification failed");
    }

    #[test]
    fn create_and_verify_signature__fail() {
        let signed_secret_key = SignedSecretKey::from_string(&GPG_PRIVATE_KEY)
            .expect("decoding key failed")
            .0;

        let input = "Test".as_bytes();
        let input_reader: Box<dyn Read> = Box::new(BufReader::new(input));

        let signature =
            create_signature(&signed_secret_key, input_reader).expect("sig creation failed");

        let signed_public_key = SignedPublicKey::from_string(&GPG_PUBLIC_KEY)
            .expect("decoding key failed")
            .0;

        let result = signature.verify(&signed_public_key, "other content".as_bytes());

        assert!(result.is_err());
    }

    #[test]
    fn format_success_message__format() {
        env::set_var("TZ", "Europe/Berlin");

        let signed_public_key = SignedPublicKey::from_string(&GPG_PUBLIC_KEY)
            .expect("decoding key failed")
            .0;
        let signature = StandaloneSignature::from_string(&SIGNATURE_RAW)
            .expect("decoding signature failed")
            .0;

        let success_message = format_success_message(&signature, &signed_public_key);

        assert_eq!(success_message, "Signature made 2024-11-03T21:35:56+01:00\nGood signature from User ID: \"Tester <tester@test.invalid>\"".to_owned())
    }

    #[test]
    fn input_file_reader__from_path() {
        let fake_stdin = Box::new(Cursor::new(""));
        let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
        writeln!(temp_file, "Test file content").expect("Failed to write to temp file");
        let file_path = temp_file.path().to_path_buf();

        let mut reader =
            get_input_reader(&Some(file_path), fake_stdin).expect("Failed to get reader");

        let mut content = String::new();
        reader
            .read_to_string(&mut content)
            .expect("Failed to read content");

        assert_eq!(content, "Test file content\n");
    }

    #[test]
    fn test_get_input_reader_with_stdin() {
        let simulated_stdin = b"Test stdin content";
        let cursor = Box::new(Cursor::new(simulated_stdin));

        let mut reader = get_input_reader(&None, cursor).expect("Failed to get reader");

        let mut content = String::new();
        reader
            .read_to_string(&mut content)
            .expect("Failed to read content");

        assert_eq!(content, "Test stdin content");
    }

    #[test]
    fn get_gpg_key_pair__gpg_secret() {
        let mut secret_provider_mock = MockSecretProvider::new();

        let uuid = Uuid::new_v4();
        let config = debug_config_v1();

        let secret_key_expected = Some("SK".to_owned());
        let public_key_expected = Some("PK".to_owned());

        secret_provider_mock
            .expect_get_secret()
            .times(1)
            .with(eq(uuid), eq(config.clone()))
            .returning(move |_, _| {
                Ok((
                    mock_gpg_key_secret(Some("SK".to_owned()), Some("PK".to_owned())),
                    "".to_owned(),
                ))
            });

        let (secret_key, public_key) =
            get_gpg_key_pair(&uuid, &config, Box::new(secret_provider_mock))
                .expect("Failed to get key pair");

        assert_eq!(secret_key, secret_key_expected);
        assert_eq!(public_key, public_key_expected);
    }

    #[test]
    fn get_gpg_key_pair__wrong_secret_type() {
        let mut secret_provider_mock = MockSecretProvider::new();

        let uuid = Uuid::new_v4();
        let config = debug_config_v1();

        secret_provider_mock
            .expect_get_secret()
            .times(1)
            .with(eq(uuid), eq(config.clone()))
            .returning(move |_, _| Ok((Secret::new(SecretType::Bookmark), "".to_owned())));

        let result = get_gpg_key_pair(&uuid, &config, Box::new(secret_provider_mock));
        let error = result.unwrap_err().to_string();

        assert_eq!(error, "the specified secret is not an GPGKey secret");
    }
}
