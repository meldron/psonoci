use std::collections::HashMap;
// use std::ffi::OsString;
use std::process::Command;

use anyhow::{Context, Result};
use uuid::Uuid;

use crate::api::{api_key_get_secrets, Secret};
use crate::config::Config;
use crate::opt::RunCommand;

fn create_env_vars_map(
    secrets: HashMap<Uuid, Secret>,
    filter: Option<Vec<Uuid>>,
) -> HashMap<String, String> {
    let mut env_vars_map: HashMap<String, String> = HashMap::new();

    let filtered: HashMap<Uuid, Secret> = match filter {
        Some(ids) => secrets
            .into_iter()
            .filter(|(id, _)| ids.contains(id))
            .collect(),
        None => secrets,
    };

    filtered
        .into_iter()
        .map(|(_, s)| s)
        // .filter(|s| s.secret_type == SecretType::EnvVars)
        .for_each(|s| {
            if let Some(evs) = s.env_vars {
                evs.into_iter().for_each(|ev| {
                    if env_vars_map.contains_key(&ev.key) {
                        eprintln!(
                            "psonoci warning: duplicate env var with name {}; previous one will be overwritten",
                            &ev.key
                        );
                    }
                    env_vars_map.insert(ev.key, ev.value);
                });
            }
        });

    env_vars_map
}

pub fn run_run_command(config: Config, rc: RunCommand) -> Result<()> {
    let command_values = rc.command_values;
    let program = &command_values[0];
    let args = &command_values[1..];

    let secrets = api_key_get_secrets(&config).context("api key secrets failed")?;
    let env_vars = create_env_vars_map(secrets, rc.filter);

    let mut command = Command::new(program);
    command.args(args);

    if rc.clear_env {
        command.env_clear();
    }

    if env_vars.len() > 0 {
        command.envs(env_vars);
    } else {
        eprintln!("psonoci warning: no env vars found");
    }

    command
        .status()
        .context(format!("spawning program {:?} failed", program))?;

    Ok(())
}
