use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::ErrorKind;
use std::process::{exit, Command, ExitStatus};

use anyhow::{Context, Result};
use uuid::Uuid;

use crate::api::{api_key_get_secrets, Secret};
use crate::config::Config;
use crate::opt::RunCommand;

type EnvironmentVars = HashMap<String, String>;
type Duplicates = HashMap<String, usize>;

fn create_env_vars_map(
    secrets: HashMap<Uuid, Secret>,
    filter: Option<Vec<Uuid>>,
) -> (HashMap<String, String>, Duplicates) {
    let mut env_vars_map: HashMap<String, String> = HashMap::new();
    let mut duplicates: Duplicates = HashMap::new();

    let filtered: HashMap<Uuid, Secret> = match filter {
        Some(ids) => secrets
            .into_iter()
            .filter(|(id, _)| ids.contains(id))
            .collect(),
        None => secrets,
    };

    filtered
        .into_values()
        // .filter(|s| s.secret_type == SecretType::EnvVars)
        .for_each(|s| {
            if let Some(evs) = s.env_vars {
                evs.into_iter().for_each(|ev| {
                    if env_vars_map.contains_key(&ev.key) {
                        let key = ev.key.clone();
                        *duplicates.entry(key).or_insert(0) += 1;
                    }
                    env_vars_map.insert(ev.key, ev.value);
                });
            }
        });

    (env_vars_map, duplicates)
}

fn build_command<P, A>(
    program: P,
    args: A,
    envs: &EnvironmentVars,
    duplicates: &Duplicates,
    clear_env: bool,
) -> Command
where
    P: AsRef<OsStr>,
    A: IntoIterator,
    A::Item: AsRef<OsStr>,
{
    let mut command = Command::new(program);
    command.args(args);

    if clear_env {
        command.env_clear();
    }

    if !envs.is_empty() {
        duplicates.iter().for_each(|(name, dup)| {
            eprintln!(
                "psonoci warning: duplicate env var with name '{}'; overwritten '{}' times",
                name, dup
            );
        });
        command.envs(envs);
    } else {
        eprintln!("psonoci warning: no env vars found");
    }

    command
}

#[cfg(target_family = "unix")]
fn execute_error_status_code(error_kind: &ErrorKind) -> i32 {
    // this emulates the behavior of shells like bash and zsh
    // https://tldp.org/LDP/abs/html/exitcodes.html
    match error_kind {
        ErrorKind::PermissionDenied => 126,
        ErrorKind::NotFound => 127,
        _ => 1,
    }
}

#[cfg(not(target_family = "unix"))]
fn execute_error_status_code(error_kind: &ErrorKind) -> i32 {
    1
}

#[cfg(target_family = "unix")]
fn exit_status_code(exit_status: &ExitStatus) -> i32 {
    use std::os::unix::prelude::*;

    match exit_status.code() {
        Some(code) => code,
        None => {
            let signal: Option<i32> = exit_status.signal();

            // this emulates the behavior of shells like bash and zsh
            // 128+n fatal error signal "n"
            // https://tldp.org/LDP/abs/html/exitcodes.html
            match signal {
                Some(n) => 128 + n,
                None => 1,
            }
        }
    }
}

#[cfg(not(target_family = "unix"))]
fn exit_status_code(exit_status: &ExitStatus) -> i32 {
    exit_status.code().unwrap_or_else(|| 1)
}

pub fn run_run_command(config: Config, rc: RunCommand) -> Result<()> {
    let command_values = rc.command_values;
    let program = &command_values[0];
    let args = &command_values[1..];

    let secrets = api_key_get_secrets(&config).context("api key secrets failed")?;
    let (envs, duplicates) = create_env_vars_map(secrets, rc.filter);

    let mut command = build_command(program, args, &envs, &duplicates, rc.clear_env);

    let command_result = command.status();

    if let Err(e) = &command_result {
        let error_kind = e.kind();

        let spawn_error_code = execute_error_status_code(&error_kind);

        eprintln!("Could not spawn {:?}: {}", program, e);

        exit(spawn_error_code);
    }

    let exit_status =
        command_result.expect("exit was error; should not happen please file a bug report");

    let exit_status_code = exit_status_code(&exit_status);

    exit(exit_status_code)
}
