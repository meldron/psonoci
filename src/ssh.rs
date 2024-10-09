use crate::api::SecretType;
use crate::config::Config;
use crate::opt::{SshAddCommand, SshCommand};
use crate::secret_provider::{PsonoSecretProvider, SecretProvider};
use anyhow::{bail, Context, Result};
use russh_keys::agent::client::{AgentClient, AgentStream};
use russh_keys::agent::Constraint;
use russh_keys::key::KeyPair;
use russh_keys::*;
use std::env;
use std::path::{Path, PathBuf};
use tokio::runtime::Runtime;
use uuid::Uuid;

#[cfg(test)]
use mockall::{automock, predicate::*};

#[cfg_attr(test, automock)]
trait SshAgentProvider {
    fn add_identity(
        &self,
        agent_path: &Path,
        keypair: &KeyPair,
        constraints: &[Constraint],
    ) -> Result<()>;
}

pub struct SshAgentClient;

async fn get_agent_client(
    agent_path: &Path,
) -> Result<AgentClient<Box<dyn AgentStream + Send + Unpin>>> {
    #[cfg(windows)]
    {
        let agent_client = AgentClient::connect_named_pipe(agent_path)
            .await
            .context(format!(
                "opening named pipe '{}' failed:",
                agent_path.display()
            ))?;
        let dynamic = agent_client.dynamic();

        Ok(dynamic)
    }
    #[cfg(unix)]
    {
        let agent_client = AgentClient::connect_uds(agent_path).await.context(format!(
            "opening unix domain socket '{}' failed:",
            agent_path.display()
        ))?;
        let dynamic = agent_client.dynamic();

        Ok(dynamic)
    }
}

impl SshAgentProvider for SshAgentClient {
    fn add_identity(
        &self,
        agent_path: &Path,
        keypair: &KeyPair,
        constraints: &[Constraint],
    ) -> Result<()> {
        let runtime = Runtime::new()?;
        runtime.block_on(async move {
            let mut agent_client = get_agent_client(agent_path).await?;
            agent_client
                .add_identity(keypair, constraints)
                .await
                .context("adding key pair failed")?;
            Ok(())
        })
    }
}

fn get_ssh_auth_sock_path(ssh_auth_socket_path: Option<PathBuf>) -> Result<PathBuf> {
    #[cfg(unix)]
    {
        if let Some(path) = ssh_auth_socket_path {
            Ok(path.clone())
        } else if let Ok(env_path) = env::var("SSH_AUTH_SOCK") {
            Ok(PathBuf::from(env_path))
        } else {
            bail!(
                "No SSH_AUTH_SOCK path provided and SSH_AUTH_SOCK environment variable is not set."
            );
        }
    }
    #[cfg(windows)]
    {
        if let Some(path) = ssh_auth_socket_path {
            Ok(path.clone())
        } else if let Ok(env_path) = env::var("SSH_AUTH_SOCK") {
            Ok(PathBuf::from(env_path))
        } else {
            Ok(PathBuf::from(r"\\.\pipe\openssh-ssh-agent"))
        }
    }
}

fn get_ssh_key_pair(
    secret_id: &Uuid,
    key_passphrase: &Option<String>,
    config: &Config,
    secret_provider: Box<dyn SecretProvider>,
) -> Result<KeyPair> {
    let (secret, _) = secret_provider
        .get_secret(secret_id, config)
        .context("ssh_agent_add_identity loading secret from store failed")?;

    if secret.secret_type != SecretType::SSHKey {
        bail!("the specified secret is not an SSHKey secret");
    }

    let ssh_private_key = secret
        .ssh_key
        .context("ssh key not set")?
        .key_private
        .context("private key not set")?;

    decode_secret_key(&ssh_private_key, key_passphrase.as_deref())
        .context("decoding key pair failed")
}

fn get_constraints(key_lifetime: Option<u32>, key_conformation: bool) -> Vec<Constraint> {
    let mut constraints = vec![];

    if let Some(key_lifetime) = key_lifetime {
        constraints.push(Constraint::KeyLifetime {
            seconds: key_lifetime,
        });
    }

    if key_conformation {
        constraints.push(Constraint::Confirm);
    }

    constraints
}

fn ssh_add(
    add_command: SshAddCommand,
    config: Config,
    agent_client: Box<dyn SshAgentProvider>,
    secret_provider: Box<dyn SecretProvider>,
) -> Result<()> {
    let agent_path = get_ssh_auth_sock_path(add_command.ssh_auth_sock_path)?;
    let keypair = get_ssh_key_pair(
        &add_command.secret_id,
        &add_command.key_passphrase,
        &config,
        secret_provider,
    )?;
    let constraints = get_constraints(add_command.key_lifetime, add_command.key_conformation);

    agent_client.add_identity(&agent_path, &keypair, &constraints)
}

pub fn run_ssh_command(ssh_command: SshCommand, config: Config) -> Result<()> {
    match ssh_command {
        SshCommand::Add(add_command) => ssh_add(
            add_command,
            config,
            Box::new(SshAgentClient),
            Box::new(PsonoSecretProvider),
        )?,
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api;
    use crate::api::Secret;
    use crate::config::tests::debug_config_v1;
    use crate::secret_provider::MockSecretProvider;
    use lazy_static::lazy_static;

    lazy_static! {
        static ref SSH_PRIVATE_KEY: &'static str = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDBi0jwlU6ffruDI/wDJMGA3O5a2nmRuZY/B4fnDqPm2wAAAJgyL39nMi9/
ZwAAAAtzc2gtZWQyNTUxOQAAACDBi0jwlU6ffruDI/wDJMGA3O5a2nmRuZY/B4fnDqPm2w
AAAEAS4iul81pzZYMeLecfBpJCMi9bGDfmh9FZLgNn3w6ffMGLSPCVTp9+u4Mj/AMkwYDc
7lraeZG5lj8Hh+cOo+bbAAAAEHBzb25vY2lAcHNvbm8ucHcBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----"#;
        static ref SSH_PRIVATE_KEY_ENCRYPTED: &'static str = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCdO/q1zY
wUZlawNgXP+WpUAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIL1uUc21yfi4EnbJ
SdqbDo7lTg01DR3PijsrxqazSlkfAAAAoCly4c9kN1NPqhnGPj5JobqmDZLjvdlXyXoWzv
LlMy8LbspsXti/0NXhUIBybL1DpK+ekc33WO2SuENfl9RrL5DIJOcvktPI/KD4fQne4b4A
Hotifd/sshFYoKTOKfOBG6NI6d6cz5SSBW9J/J9Clcwr76dLrTTflk8XNVu134VsmurK1L
LyJ8KFD6VrTBU5pj881bJv8YqItvmUROnBZQQ=
-----END OPENSSH PRIVATE KEY-----"#;
    }

    fn mock_ssh_key_secret(key_private: Option<String>, key_public: Option<String>) -> Secret {
        let mut secret = Secret::new(SecretType::SSHKey);

        secret.ssh_key = Some(api::SSHKey {
            key_private,
            key_public,
        });

        secret
    }

    #[test]
    fn get_ssh_key_pair_wrong_secret_type() {
        let mut secret_provider_mock = MockSecretProvider::new();

        let uuid = Uuid::new_v4();
        let config = debug_config_v1();

        secret_provider_mock
            .expect_get_secret()
            .times(1)
            .with(eq(uuid), eq(config.clone()))
            .returning(|_, _| Ok((Secret::new(SecretType::Bookmark), "".to_owned())));

        let error =
            get_ssh_key_pair(&uuid, &None, &config, Box::new(secret_provider_mock)).unwrap_err();

        assert_eq!(
            error.to_string(),
            "the specified secret is not an SSHKey secret"
        );
    }

    #[test]
    fn get_ssh_key_pair_no_private_key() {
        let mut secret_provider_mock = MockSecretProvider::new();

        let uuid = Uuid::new_v4();
        let config = debug_config_v1();

        secret_provider_mock
            .expect_get_secret()
            .times(1)
            .with(eq(uuid), eq(config.clone()))
            .returning(|_, _| Ok((mock_ssh_key_secret(None, None), "".to_owned())));

        let error =
            get_ssh_key_pair(&uuid, &None, &config, Box::new(secret_provider_mock)).unwrap_err();

        assert_eq!(error.to_string(), "private key not set");
    }

    #[test]
    fn get_ssh_key_pair_invalid_ssh_private_key() {
        let mut secret_provider_mock = MockSecretProvider::new();

        let uuid = Uuid::new_v4();
        let config = debug_config_v1();

        secret_provider_mock
            .expect_get_secret()
            .times(1)
            .with(eq(uuid), eq(config.clone()))
            .returning(|_, _| {
                Ok((
                    mock_ssh_key_secret(Some("invalid".to_owned()), None),
                    "".to_owned(),
                ))
            });

        let error =
            get_ssh_key_pair(&uuid, &None, &config, Box::new(secret_provider_mock)).unwrap_err();

        assert_eq!(error.to_string(), "decoding key pair failed");
    }

    #[test]
    fn get_ssh_key_pair_code_decode_valid_key_pair() {
        let mut secret_provider_mock = MockSecretProvider::new();

        let uuid = Uuid::new_v4();
        let config = debug_config_v1();

        secret_provider_mock
            .expect_get_secret()
            .times(1)
            .with(eq(uuid), eq(config.clone()))
            .returning(|_, _| {
                Ok((
                    mock_ssh_key_secret(Some(SSH_PRIVATE_KEY.to_owned()), None),
                    "".to_owned(),
                ))
            });

        let key_pair =
            get_ssh_key_pair(&uuid, &None, &config, Box::new(secret_provider_mock)).unwrap();

        assert_eq!(key_pair.name(), "ssh-ed25519");
        assert_eq!(
            key_pair.public_key_base64(),
            "AAAAC3NzaC1lZDI1NTE5AAAAIMGLSPCVTp9+u4Mj/AMkwYDc7lraeZG5lj8Hh+cOo+bb"
        );
    }

    #[test]
    fn get_ssh_key_pair_code_decode_valid_encrypted_key_pair_no_password() {
        let mut secret_provider_mock = MockSecretProvider::new();

        let uuid = Uuid::new_v4();
        let config = debug_config_v1();

        secret_provider_mock
            .expect_get_secret()
            .times(1)
            .with(eq(uuid), eq(config.clone()))
            .returning(|_, _| {
                Ok((
                    mock_ssh_key_secret(Some(SSH_PRIVATE_KEY_ENCRYPTED.to_owned()), None),
                    "".to_owned(),
                ))
            });

        let error =
            get_ssh_key_pair(&uuid, &None, &config, Box::new(secret_provider_mock)).unwrap_err();

        assert_eq!(error.to_string(), "decoding key pair failed");
    }

    #[test]
    fn get_ssh_key_pair_code_decode_valid_encrypted_key_pair_wrong_password() {
        let mut secret_provider_mock = MockSecretProvider::new();

        let uuid = Uuid::new_v4();
        let config = debug_config_v1();

        secret_provider_mock
            .expect_get_secret()
            .times(1)
            .with(eq(uuid), eq(config.clone()))
            .returning(|_, _| {
                Ok((
                    mock_ssh_key_secret(Some(SSH_PRIVATE_KEY_ENCRYPTED.to_owned()), None),
                    "".to_owned(),
                ))
            });

        let error = get_ssh_key_pair(
            &uuid,
            &Some("wrong password".to_owned()),
            &config,
            Box::new(secret_provider_mock),
        )
        .unwrap_err();

        assert_eq!(error.to_string(), "decoding key pair failed");
    }

    #[test]
    fn get_ssh_key_pair_code_decode_valid_encrypted_key_pair() {
        let mut secret_provider_mock = MockSecretProvider::new();

        let uuid = Uuid::new_v4();
        let config = debug_config_v1();

        secret_provider_mock
            .expect_get_secret()
            .times(1)
            .with(eq(uuid), eq(config.clone()))
            .returning(|_, _| {
                Ok((
                    mock_ssh_key_secret(Some(SSH_PRIVATE_KEY_ENCRYPTED.to_owned()), None),
                    "".to_owned(),
                ))
            });

        let key_pair = get_ssh_key_pair(
            &uuid,
            &Some("test".to_owned()),
            &config,
            Box::new(secret_provider_mock),
        )
        .unwrap();

        assert_eq!(key_pair.name(), "ssh-ed25519");
        assert_eq!(
            key_pair.public_key_base64(),
            "AAAAC3NzaC1lZDI1NTE5AAAAIL1uUc21yfi4EnbJSdqbDo7lTg01DR3PijsrxqazSlkf"
        );
    }
}
