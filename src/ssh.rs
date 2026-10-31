use crate::api::SecretType;
use crate::config::Config;
use crate::opt::{SshAddCommand, SshCommand};
use crate::secret_provider::{PsonoSecretProvider, SecretProvider};
use crate::sensitive::SensitiveString;
use anyhow::{Context, Result, bail};
use russh::keys::agent::Constraint;
use russh::keys::agent::client::{AgentClient, AgentStream};
use russh::keys::{PrivateKey, decode_secret_key};
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
        private_key: &PrivateKey,
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
        private_key: &PrivateKey,
        constraints: &[Constraint],
    ) -> Result<()> {
        let runtime = Runtime::new()?;
        runtime.block_on(async move {
            let mut agent_client = get_agent_client(agent_path).await?;
            agent_client
                .add_identity(private_key, constraints)
                .await
                .context("adding private key failed")?;
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

fn get_ssh_private_key(
    secret_id: &Uuid,
    key_passphrase: Option<&SensitiveString>,
    config: &Config,
    secret_provider: Box<dyn SecretProvider>,
) -> Result<PrivateKey> {
    let (secret, _) = secret_provider
        .get_secret(secret_id, config)
        .context("ssh_agent_add_identity loading secret from store failed")?;

    if secret.secret_type != SecretType::SSHKey {
        bail!("the specified secret is not an SSHKey secret");
    }

    let ssh_private_key = SensitiveString::from(
        secret
            .ssh_key
            .context("ssh key not set")?
            .key_private
            .context("private key not set")?,
    );

    decode_secret_key(
        ssh_private_key.expose_secret(),
        key_passphrase.map(|s| s.expose_secret()),
    )
    .context("decoding private key failed")
}

fn get_constraints(key_lifetime: Option<u32>, key_confirmation: bool) -> Vec<Constraint> {
    let mut constraints = vec![];

    if let Some(key_lifetime) = key_lifetime {
        constraints.push(Constraint::KeyLifetime {
            seconds: key_lifetime,
        });
    }

    if key_confirmation {
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
    let key_passphrase = add_command
        .key_passphrase
        .as_deref()
        .map(SensitiveString::from);
    let private_key = get_ssh_private_key(
        &add_command.secret_id,
        key_passphrase.as_ref(),
        &config,
        secret_provider,
    )?;
    let constraints = get_constraints(add_command.key_lifetime, add_command.key_confirmation);

    agent_client.add_identity(&agent_path, &private_key, &constraints)
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
#[allow(non_snake_case)]
mod tests {
    use super::*;
    use crate::api;
    use crate::api::Secret;
    use crate::config::tests::debug_config_v1;
    use crate::secret_provider::MockSecretProvider;
    use lazy_static::lazy_static;
    use russh::keys::PublicKeyBase64;

    #[test]
    fn get_constraints__all_combinations() {
        assert_eq!(get_constraints(None, false), vec![]);
        assert_eq!(
            get_constraints(Some(60), false),
            vec![Constraint::KeyLifetime { seconds: 60 }]
        );
        assert_eq!(get_constraints(None, true), vec![Constraint::Confirm]);
        assert_eq!(
            get_constraints(Some(60), true),
            vec![Constraint::KeyLifetime { seconds: 60 }, Constraint::Confirm]
        );
    }

    #[test]
    fn ssh_add__forwards_socket_decrypted_key_and_constraints() {
        let uuid = Uuid::new_v4();
        let config = debug_config_v1();
        let agent_path = PathBuf::from("test-agent.sock");
        let expected_path = agent_path.clone();
        let mut secret_provider = MockSecretProvider::new();
        secret_provider
            .expect_get_secret()
            .once()
            .with(eq(uuid), eq(config.clone()))
            .returning(|_, _| {
                Ok((
                    mock_ssh_key_secret(Some(SSH_PRIVATE_KEY_ENCRYPTED.to_string()), None),
                    SensitiveString::from(""),
                ))
            });

        let mut agent = MockSshAgentProvider::new();
        agent
            .expect_add_identity()
            .once()
            .withf(move |path, key, constraints| {
                path == expected_path
                    && key.public_key_base64()
                        == "AAAAC3NzaC1lZDI1NTE5AAAAIL1uUc21yfi4EnbJSdqbDo7lTg01DR3PijsrxqazSlkf"
                    && constraints == [Constraint::KeyLifetime { seconds: 60 }, Constraint::Confirm]
            })
            .returning(|_, _, _| Ok(()));

        ssh_add(
            SshAddCommand {
                secret_id: uuid,
                ssh_auth_sock_path: Some(agent_path),
                key_passphrase: Some("test".to_owned()),
                key_lifetime: Some(60),
                key_confirmation: true,
            },
            config,
            Box::new(agent),
            Box::new(secret_provider),
        )
        .unwrap();
    }

    // Opt-in because these tests require the OpenSSH executables. Each run
    // creates its own agent and disposable keys; the user's agent is untouched.
    #[cfg(unix)]
    mod openssh {
        use super::*;
        use std::process::{Child, Command, Stdio};
        use std::thread::sleep;
        use std::time::{Duration, Instant};

        struct Agent(Child);

        impl Drop for Agent {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        #[test]
        #[ignore = "requires ssh-agent, ssh-add and ssh-keygen; uses a disposable local agent"]
        fn openssh_agent_roundtrip() {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("agent.sock");
            let mut agent = Agent(
                Command::new("ssh-agent")
                    .arg("-D")
                    .arg("-a")
                    .arg(&socket)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("start ssh-agent"),
            );
            let deadline = Instant::now() + Duration::from_secs(5);
            while !socket.exists() {
                assert!(agent.0.try_wait().unwrap().is_none(), "ssh-agent exited");
                assert!(Instant::now() < deadline, "ssh-agent startup timed out");
                sleep(Duration::from_millis(20));
            }

            for (index, (algorithm, passphrase)) in [
                ("ed25519", ""),
                ("ed25519", "test-passphrase"),
                ("rsa", ""),
                ("ecdsa", ""),
            ]
            .into_iter()
            .enumerate()
            {
                let path = dir.path().join(format!("key-{index}"));
                let generated = Command::new("ssh-keygen")
                    .args(["-q", "-t", algorithm, "-N", passphrase, "-f"])
                    .arg(&path)
                    .output()
                    .expect("run ssh-keygen");
                assert!(generated.status.success(), "ssh-keygen: {generated:?}");

                let key_text = std::fs::read_to_string(&path).unwrap();
                let public_path = path.with_extension("pub");
                let public_text = std::fs::read_to_string(&public_path).unwrap();
                let public_blob = public_text.split_whitespace().nth(1).unwrap();
                let uuid = Uuid::new_v4();
                let config = debug_config_v1();
                let mut provider = MockSecretProvider::new();
                provider
                    .expect_get_secret()
                    .once()
                    .with(eq(uuid), eq(config.clone()))
                    .return_once(move |_, _| {
                        Ok((
                            mock_ssh_key_secret(Some(key_text), None),
                            SensitiveString::from(""),
                        ))
                    });
                ssh_add(
                    SshAddCommand {
                        secret_id: uuid,
                        ssh_auth_sock_path: Some(socket.clone()),
                        key_passphrase: (!passphrase.is_empty()).then(|| passphrase.to_owned()),
                        key_lifetime: Some(60),
                        key_confirmation: false,
                    },
                    config,
                    Box::new(SshAgentClient),
                    Box::new(provider),
                )
                .unwrap();

                let identities = Command::new("ssh-add")
                    .arg("-L")
                    .env("SSH_AUTH_SOCK", &socket)
                    .output()
                    .expect("list agent identities");
                assert!(identities.status.success(), "ssh-add: {identities:?}");
                assert!(
                    String::from_utf8(identities.stdout)
                        .unwrap()
                        .contains(public_blob)
                );

                // OpenSSH asks the agent to sign, then verifies the signature.
                let signed = Command::new("ssh-add")
                    .arg("-T")
                    .arg(&public_path)
                    .env("SSH_AUTH_SOCK", &socket)
                    .output()
                    .expect("test agent signing");
                assert!(signed.status.success(), "ssh-add -T: {signed:?}");
            }

            // Replace one identity with a short-lived copy and check expiry.
            let key_text = std::fs::read_to_string(dir.path().join("key-3")).unwrap();
            let key = decode_secret_key(&key_text, None).unwrap();
            let public_blob = key.public_key_base64();
            SshAgentClient
                .add_identity(&socket, &key, &get_constraints(Some(1), false))
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let identities = Command::new("ssh-add")
                    .arg("-L")
                    .env("SSH_AUTH_SOCK", &socket)
                    .output()
                    .unwrap();
                assert!(identities.status.success(), "ssh-add: {identities:?}");
                if !String::from_utf8(identities.stdout)
                    .unwrap()
                    .contains(&public_blob)
                {
                    break;
                }
                assert!(Instant::now() < deadline, "key lifetime was not enforced");
                sleep(Duration::from_millis(100));
            }
        }
    }

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
    fn get_ssh_key_pair__wrong_secret_type() {
        let mut secret_provider_mock = MockSecretProvider::new();

        let uuid = Uuid::new_v4();
        let config = debug_config_v1();

        secret_provider_mock
            .expect_get_secret()
            .times(1)
            .with(eq(uuid), eq(config.clone()))
            .returning(|_, _| Ok((Secret::new(SecretType::Bookmark), SensitiveString::from(""))));

        let error =
            get_ssh_private_key(&uuid, None, &config, Box::new(secret_provider_mock)).unwrap_err();

        assert_eq!(
            error.to_string(),
            "the specified secret is not an SSHKey secret"
        );
    }

    #[test]
    fn get_ssh_key_pair__no_private_key() {
        let mut secret_provider_mock = MockSecretProvider::new();

        let uuid = Uuid::new_v4();
        let config = debug_config_v1();

        secret_provider_mock
            .expect_get_secret()
            .times(1)
            .with(eq(uuid), eq(config.clone()))
            .returning(|_, _| Ok((mock_ssh_key_secret(None, None), SensitiveString::from(""))));

        let error =
            get_ssh_private_key(&uuid, None, &config, Box::new(secret_provider_mock)).unwrap_err();

        assert_eq!(error.to_string(), "private key not set");
    }

    #[test]
    fn get_ssh_key_pair__invalid_ssh_private_key() {
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
                    SensitiveString::from(""),
                ))
            });

        let error =
            get_ssh_private_key(&uuid, None, &config, Box::new(secret_provider_mock)).unwrap_err();

        assert_eq!(error.to_string(), "decoding private key failed");
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
                    SensitiveString::from(""),
                ))
            });

        let private_key =
            get_ssh_private_key(&uuid, None, &config, Box::new(secret_provider_mock)).unwrap();

        assert_eq!(private_key.algorithm().as_str(), "ssh-ed25519");
        assert_eq!(
            private_key.public_key_base64(),
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
                    SensitiveString::from(""),
                ))
            });

        let error =
            get_ssh_private_key(&uuid, None, &config, Box::new(secret_provider_mock)).unwrap_err();

        assert_eq!(error.to_string(), "decoding private key failed");
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
                    SensitiveString::from(""),
                ))
            });

        let passphrase = SensitiveString::from("wrong password");
        let error = get_ssh_private_key(
            &uuid,
            Some(&passphrase),
            &config,
            Box::new(secret_provider_mock),
        )
        .unwrap_err();

        assert_eq!(error.to_string(), "decoding private key failed");
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
                    SensitiveString::from(""),
                ))
            });

        let passphrase = SensitiveString::from("test");
        let private_key = get_ssh_private_key(
            &uuid,
            Some(&passphrase),
            &config,
            Box::new(secret_provider_mock),
        )
        .unwrap();

        assert_eq!(private_key.algorithm().as_str(), "ssh-ed25519");
        assert_eq!(
            private_key.public_key_base64(),
            "AAAAC3NzaC1lZDI1NTE5AAAAIL1uUc21yfi4EnbJSdqbDo7lTg01DR3PijsrxqazSlkf"
        );
    }
}
