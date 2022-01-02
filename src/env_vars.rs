use anyhow::{bail, Context, Result};
use uuid::Uuid;

use crate::{
    api::{get_secret, set_secret, EnvironmentVariable, Secret, SecretType},
    config::Config,
    opt::{EnvVarsCommand, PasswordCreationSettings},
    passwords::create_random_password,
};

pub fn run_env_vars_command(env_command: EnvVarsCommand, config: Config) -> Result<()> {
    let secret_env_value = match env_command {
        EnvVarsCommand::GetOrCreate {
            secret_id,
            env_var_name,
            password_creation_settings,
        } => get_or_create_env_value_by_name(
            secret_id,
            env_var_name,
            config,
            password_creation_settings,
        )?,
        EnvVarsCommand::UpdateOrCreate {
            secret_id,
            env_var_name,
            env_var_value,
            password_creation_settings,
        } => update_or_create_env_value_by_name(
            secret_id,
            env_var_name,
            env_var_value,
            config,
            password_creation_settings,
        )?,
    };

    print!("{}", secret_env_value);

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
    env_var_value: Option<String>,
    config: Config,
    password_creation_settings: PasswordCreationSettings,
) -> Result<String> {
    let (secret, secret_key_hex) = get_env_var_secret(&secret_id, &config)
        .context("update_or_create_env_value_by_name loading secret from store failed")?;

    let (secret_updated, new_value) = update_or_create(
        secret,
        env_var_name,
        env_var_value,
        password_creation_settings,
    );

    if let Some(updated) = secret_updated {
        set_secret(&secret_id, &config, &updated, &secret_key_hex)
            .context("Updating secret failed")?;
    }

    Ok(new_value)
}

fn update_or_create(
    mut secret: Secret,
    env_var_name: String,
    env_var_value: Option<String>,
    password_creation_settings: PasswordCreationSettings,
) -> (Option<Secret>, String) {
    let mut env_vars = secret.env_vars.unwrap_or_default();

    let new_value = match env_var_value {
        Some(v) => v,
        None => create_random_password(
            password_creation_settings.password_length,
            password_creation_settings.danger_password_allowed_chars,
        ),
    };
    let needle = env_vars.iter_mut().find(|ev| ev.key == env_var_name);

    if let Some(ev) = needle {
        if ev.value == new_value {
            return (None, new_value);
        }

        ev.value = new_value.clone();
    } else {
        env_vars.push(EnvironmentVariable {
            key: env_var_name,
            value: new_value.clone(),
        });
    }

    secret.env_vars = Some(env_vars);

    (Some(secret), new_value)
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

        let (secret_updated, new_secret) = update_or_create(
            secret,
            "name".to_owned(),
            Some("after".to_owned()),
            PasswordCreationSettings::default(),
        );

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
        assert_eq!(new_secret, "after");
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

        let (secret_updated, new_secret) = update_or_create(
            secret,
            "new".to_owned(),
            Some("new".to_owned()),
            PasswordCreationSettings::default(),
        );

        assert_eq!(new_secret, "new");

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
    fn update_or_create__add_new_env_var_with_random_value() {
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

        let (secret_updated, new_secret) = update_or_create(
            secret,
            "new".to_owned(),
            None,
            PasswordCreationSettings::default(),
        );

        let new_env_var = &secret_updated.unwrap().env_vars.unwrap()[2];
        assert_eq!(new_env_var.key, "new");
        assert_eq!(new_env_var.value, new_secret);
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

        let (secret_updated, new_secret) = update_or_create(
            secret,
            "unchanged".to_owned(),
            Some("unchanged".to_owned()),
            PasswordCreationSettings::default(),
        );

        assert_eq!(new_secret, "unchanged");
        assert_eq!(secret_updated, None);
    }
}
