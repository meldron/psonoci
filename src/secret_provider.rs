use crate::api::{get_secret, Secret};
use crate::config::Config;
use anyhow::Result;
use uuid::Uuid;

#[cfg(test)]
use mockall::automock;

#[cfg_attr(test, automock)]
pub trait SecretProvider {
    fn get_secret(&self, secret_id: &Uuid, config: &Config) -> Result<(Secret, String)>;
}

pub struct PsonoSecretProvider;

impl SecretProvider for PsonoSecretProvider {
    fn get_secret(&self, secret_id: &Uuid, config: &Config) -> Result<(Secret, String)> {
        get_secret(secret_id, config)
    }
}
