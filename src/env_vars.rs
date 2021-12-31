use anyhow::{bail, Context, Result};
use uuid::Uuid;

use crate::{
    api::{get_secret, set_secret, EnvironmentVariable, Secret, SecretType},
    config::Config,
    opt::{EnvVarsCommand, PasswordCreationSettings},
    passwords::create_random_password,
};

pub fn run_env_vars_command(env_command: EnvVarsCommand, config: Config) -> Result<()> {
    match env_command {
        EnvVarsCommand::GetOrCreate {
            secret_id,
            env_var_name,
            password_creation_settings,
        } => {
            let secret_env_value = get_or_create_env_value_by_name(
                secret_id,
                env_var_name,
                config,
                password_creation_settings,
            )?;

            print!("{}", secret_env_value);
        }
        EnvVarsCommand::UpdateOrCreate {
            secret_id,
            env_var_name,
            env_var_value,
        } => update_or_create_env_value_by_name(secret_id, env_var_name, env_var_value, config)?,
    }

    Ok(())
}

pub fn get_or_create_env_value_by_name(
    secret_id: Uuid,
    env_var_name: String,
    config: Config,
    password_creation_settings: PasswordCreationSettings,
) -> Result<String> {
    let (secret, secret_key_hex) = get_env_var_secret(&secret_id, &config)
        .context("get_or_create_env_value_by_name loading secret from store failed")?;

    let (secret_updated, secret_value) =
        get_or_create(secret, env_var_name, password_creation_settings);

    if let Some(updated) = secret_updated {
        set_secret(&secret_id, &config, &updated, &secret_key_hex)
            .context("Updating secret failed")?;
    }

    Ok(secret_value)
}

fn get_env_var_secret(secret_id: &Uuid, config: &Config) -> Result<(Secret, String)> {
    let (secret, secret_key_hex) = get_secret(&secret_id, &config)
        .context("get_or_create_env_value_by_name loading secret from store failed")?;

    if secret.secret_type != SecretType::EnvVars {
        bail!("The specified secret is not an EnvVars secret");
    }

    Ok((secret, secret_key_hex))
}

fn get_or_create(
    mut secret: Secret,
    env_var_name: String,
    password_creation_settings: PasswordCreationSettings,
) -> (Option<Secret>, String) {
    let mut env_vars = secret.env_vars.unwrap_or_default();

    let needle = env_vars.iter().find(|ev| ev.key == env_var_name);

    if let Some(ev) = needle {
        return (None, ev.value.to_owned());
    }

    let new_secret_env_var_value = create_random_password(
        password_creation_settings.password_length,
        password_creation_settings.danger_password_allowed_chars,
    );

    env_vars.push(EnvironmentVariable {
        key: env_var_name,
        value: new_secret_env_var_value.clone(),
    });

    secret.env_vars = Some(env_vars);

    (Some(secret), new_secret_env_var_value)
}

pub fn update_or_create_env_value_by_name(
    secret_id: Uuid,
    env_var_name: String,
    env_var_value: String,
    config: Config,
) -> Result<()> {
    let (secret, secret_key_hex) = get_env_var_secret(&secret_id, &config)
        .context("update_or_create_env_value_by_name loading secret from store failed")?;

    let secret_updated = update_or_create(secret, env_var_name, env_var_value);

    if let Some(updated) = secret_updated {
        set_secret(&secret_id, &config, &updated, &secret_key_hex)
            .context("Updating secret failed")?;
    }

    Ok(())
}

fn update_or_create(
    mut secret: Secret,
    env_var_name: String,
    env_var_value: String,
) -> Option<Secret> {
    let mut env_vars = secret.env_vars.unwrap_or_default();

    let needle = env_vars.iter_mut().find(|ev| ev.key == env_var_name);

    if let Some(ev) = needle {
        if ev.value == env_var_value {
            return None;
        }

        ev.value = env_var_value;
    } else {
        env_vars.push(EnvironmentVariable {
            key: env_var_name,
            value: env_var_value,
        });
    }

    secret.env_vars = Some(env_vars);

    Some(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(non_snake_case)]
    fn get_or_create__get_first_existing_env_var() {
        let env_vars = vec![
            EnvironmentVariable {
                key: "name".to_owned(),
                value: "before".to_owned(),
            },
            EnvironmentVariable {
                key: "unchanged".to_owned(),
                value: "unchanged".to_owned(),
            },
            EnvironmentVariable {
                key: "name".to_owned(),
                value: "unchanged".to_owned(),
            },
        ];

        let secret = Secret {
            title: Some("test".to_owned()),
            url_filter: None,
            notes: None,
            password: None,
            username: None,
            url: None,
            secret_type: SecretType::EnvVars,
            gpg_key_private: None,
            gpg_key_public: None,
            gpg_key_name: None,
            gpg_key_email: None,
            env_vars: Some(env_vars),
        };

        let (secret_updated, env_var_value) = get_or_create(
            secret,
            "name".to_owned(),
            PasswordCreationSettings {
                password_length: 21,
                danger_password_allowed_chars: None,
            },
        );

        assert_eq!(secret_updated, None);
        assert_eq!(env_var_value, "before");
    }

    #[test]
    #[allow(non_snake_case)]
    fn get_or_create__create_new_env_var() {
        let env_vars = vec![
            EnvironmentVariable {
                key: "name".to_owned(),
                value: "before".to_owned(),
            },
            EnvironmentVariable {
                key: "unchanged".to_owned(),
                value: "unchanged".to_owned(),
            },
        ];

        let secret = Secret {
            title: Some("test".to_owned()),
            url_filter: None,
            notes: None,
            password: None,
            username: None,
            url: None,
            secret_type: SecretType::EnvVars,
            gpg_key_private: None,
            gpg_key_public: None,
            gpg_key_name: None,
            gpg_key_email: None,
            env_vars: Some(env_vars),
        };

        let (secret_updated, new_env_var_value) = get_or_create(
            secret,
            "new".to_owned(),
            PasswordCreationSettings {
                password_length: 21,
                danger_password_allowed_chars: None,
            },
        );

        assert!(secret_updated.is_some());

        let updated = secret_updated.unwrap();
        let new_env_var = updated.env_vars.unwrap()[2].clone();
        assert_eq!(
            new_env_var,
            EnvironmentVariable {
                key: "new".to_owned(),
                value: new_env_var_value
            }
        )
    }

    #[test]
    #[allow(non_snake_case)]
    fn update_or_create__change_existing_env_var() {
        let env_vars = vec![
            EnvironmentVariable {
                key: "name".to_owned(),
                value: "before".to_owned(),
            },
            EnvironmentVariable {
                key: "unchanged".to_owned(),
                value: "unchanged".to_owned(),
            },
            EnvironmentVariable {
                key: "name".to_owned(),
                value: "unchanged".to_owned(),
            },
        ];

        let secret = Secret {
            title: Some("test".to_owned()),
            url_filter: None,
            notes: None,
            password: None,
            username: None,
            url: None,
            secret_type: SecretType::EnvVars,
            gpg_key_private: None,
            gpg_key_public: None,
            gpg_key_name: None,
            gpg_key_email: None,
            env_vars: Some(env_vars),
        };

        let secret_updated = update_or_create(secret, "name".to_owned(), "after".to_owned());

        let env_vars_expected = vec![
            EnvironmentVariable {
                key: "name".to_owned(),
                value: "after".to_owned(),
            },
            EnvironmentVariable {
                key: "unchanged".to_owned(),
                value: "unchanged".to_owned(),
            },
            EnvironmentVariable {
                key: "name".to_owned(),
                value: "unchanged".to_owned(),
            },
        ];
        let secret_expected = Secret {
            title: Some("test".to_owned()),
            url_filter: None,
            notes: None,
            password: None,
            username: None,
            url: None,
            secret_type: SecretType::EnvVars,
            gpg_key_private: None,
            gpg_key_public: None,
            gpg_key_name: None,
            gpg_key_email: None,
            env_vars: Some(env_vars_expected),
        };
        assert_eq!(secret_updated, Some(secret_expected));
    }

    #[test]
    #[allow(non_snake_case)]
    fn update_or_create__add_new_env_var() {
        let env_vars = vec![
            EnvironmentVariable {
                key: "name".to_owned(),
                value: "before".to_owned(),
            },
            EnvironmentVariable {
                key: "unchanged".to_owned(),
                value: "unchanged".to_owned(),
            },
        ];

        let secret = Secret {
            title: Some("test".to_owned()),
            url_filter: None,
            notes: None,
            password: None,
            username: None,
            url: None,
            secret_type: SecretType::EnvVars,
            gpg_key_private: None,
            gpg_key_public: None,
            gpg_key_name: None,
            gpg_key_email: None,
            env_vars: Some(env_vars),
        };

        let secret_updated = update_or_create(secret, "new".to_owned(), "new".to_owned());

        let env_vars_expected = vec![
            EnvironmentVariable {
                key: "name".to_owned(),
                value: "before".to_owned(),
            },
            EnvironmentVariable {
                key: "unchanged".to_owned(),
                value: "unchanged".to_owned(),
            },
            EnvironmentVariable {
                key: "new".to_owned(),
                value: "new".to_owned(),
            },
        ];
        let secret_expected = Secret {
            title: Some("test".to_owned()),
            url_filter: None,
            notes: None,
            password: None,
            username: None,
            url: None,
            secret_type: SecretType::EnvVars,
            gpg_key_private: None,
            gpg_key_public: None,
            gpg_key_name: None,
            gpg_key_email: None,
            env_vars: Some(env_vars_expected),
        };
        assert_eq!(secret_updated, Some(secret_expected));
    }

    #[test]
    #[allow(non_snake_case)]
    fn update_or_create__env_var_not_changed() {
        let env_vars = vec![
            EnvironmentVariable {
                key: "name".to_owned(),
                value: "before".to_owned(),
            },
            EnvironmentVariable {
                key: "unchanged".to_owned(),
                value: "unchanged".to_owned(),
            },
        ];

        let secret = Secret {
            title: Some("test".to_owned()),
            url_filter: None,
            notes: None,
            password: None,
            username: None,
            url: None,
            secret_type: SecretType::EnvVars,
            gpg_key_private: None,
            gpg_key_public: None,
            gpg_key_name: None,
            gpg_key_email: None,
            env_vars: Some(env_vars),
        };

        let secret_updated =
            update_or_create(secret, "unchanged".to_owned(), "unchanged".to_owned());

        assert_eq!(secret_updated, None);
    }
}
