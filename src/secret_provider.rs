use crate::api::{Secret, get_secret};
use crate::config::Config;
use crate::sensitive::SensitiveString;
use anyhow::Result;
use uuid::Uuid;

#[cfg(test)]
use mockall::automock;

#[cfg_attr(test, automock)]
pub trait SecretProvider {
    fn get_secret(&self, secret_id: &Uuid, config: &Config) -> Result<(Secret, SensitiveString)>;
}

pub struct PsonoSecretProvider;

impl SecretProvider for PsonoSecretProvider {
    fn get_secret(&self, secret_id: &Uuid, config: &Config) -> Result<(Secret, SensitiveString)> {
        get_secret(secret_id, config)
    }
}
