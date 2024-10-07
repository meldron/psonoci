use anyhow::{anyhow, Context, Result};
use env_vars::run_env_vars_command;
use run::run_run_command;
use structopt::StructOpt;

mod api;
mod config;
mod crypto;
mod env_vars;
mod license;
mod opt;
mod passwords;
mod run;
mod totp;

use api::{api_key_get_secrets, api_key_info, get_secret, set_secret};
use config::{Config, ConfigSaveFormat};
use license::print_license;
use opt::{ApiKeyCommand, Command, ConfigCommand, ConfigSource, Opt, SecretCommand};
use totp::run_totp_command;

fn run_secret_command(config: Config, command: SecretCommand) -> Result<()> {
    match command {
        SecretCommand::Get {
            secret_id,
            secret_value_type: secret_value,
        } => {
            let (secret, _) = get_secret(&secret_id, &config).context("get_secret failed")?;
            let secret_type = secret.secret_type.clone();
            let value: Option<String> = secret.get_value(&secret_value);

            if value.is_none() {
                return Err(anyhow!(
                    "value {} not present in secret (type: {})",
                    secret_value.as_str(),
                    secret_type.as_str()
                ));
            }

            print!("{}", value.unwrap());
        }
        SecretCommand::Set {
            secret_id,
            secret_value_type,
            secret_new_value,
        } => {
            let (mut secret, secret_key_hex) = get_secret(&secret_id, &config)
                .context("set_secret loading secret from store failed")?;

            secret
                .set_value(&secret_value_type, secret_new_value)
                .context("set secret value failed")?;

            set_secret(&secret_id, &config, &secret, &secret_key_hex)
                .context("set secret api call failed")?;
        }
    }

    Ok(())
}

fn run_inspect_command(config: Config, command: ApiKeyCommand) -> Result<()> {
    match command {
        ApiKeyCommand::Info => {
            let api_key_info = api_key_info(&config).context("api key info failed")?;
            let api_key_info_json = serde_json::to_string_pretty(&api_key_info)
                .context("serializing api key info as json failed")?;
            println!("{}", api_key_info_json);
        }
        ApiKeyCommand::Secrets => {
            let secrets = api_key_get_secrets(&config).context("api key secrets failed")?;
            let secrets_json = serde_json::to_string_pretty(&secrets)
                .context("serializing api key secrets as json failed")?;
            println!("{}", secrets_json);
        }
    }

    Ok(())
}

fn run_config_command(
    config_source: ConfigSource,
    config: Config,
    command: ConfigCommand,
) -> Result<()> {
    match command {
        ConfigCommand::Pack => {
            println!(
                "{}",
                config
                    .to_string(ConfigSaveFormat::MessagePackBase58)
                    .context("packing as message pack base58 encoded failed")?
            );
        }
        ConfigCommand::Save { overwrite, path } => {
            config
                .save(&path, ConfigSaveFormat::Toml, overwrite)
                .context("saving config failed")?;
        }
        ConfigCommand::Show => {
            eprintln!("# The config is loaded from {}\n", config_source);
            let c = config
                .to_string(ConfigSaveFormat::Toml)
                .context("serializing config to toml failed")?;
            println!("{}", c);
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    let opt: Opt = Opt::from_args();

    let (config_source, config) = opt.raw_config.into_config()?;

    match opt.command {
        Command::Secret(secret_command) => run_secret_command(config, secret_command)?,
        Command::ApiKey(api_key_command) => run_inspect_command(config, api_key_command)?,
        Command::Config(config_command) => {
            run_config_command(config_source, config, config_command)?
        }
        Command::Run(rc) => run_run_command(config, rc)?,
        Command::EnvVars(env_command) => run_env_vars_command(env_command, config)?,
        Command::Totp(tc) => run_totp_command(tc, config)?,
        Command::License => print_license(),
    }

    Ok(())
}
