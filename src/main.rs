use anyhow::{anyhow, Context, Result};
use structopt::StructOpt;

mod api;
mod crypto;
mod opt;

use api::get_secret;
use opt::{Command, Opt, SecretCommand};

fn run_secret_command(opt: &Opt, command: &SecretCommand) -> Result<()> {
    match command {
        SecretCommand::Get {
            secret_id,
            secret_value,
        } => {
            let secret = get_secret(&secret_id, &opt.api_settings).context("get_secret failed")?;
            let secret_type = secret.secret_type.clone();
            let value: Option<String> = secret.get_value(secret_value);

            if value.is_none() {
                return Err(anyhow!(
                    "value {} not present in secret (type: {})",
                    secret_value.as_str(),
                    secret_type.as_str()
                ));
            }

            print!("{}", value.unwrap());
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    let opt = Opt::from_args();

    match &opt.command {
        Command::Secret { 0: secret_command } => run_secret_command(&opt, secret_command)?,
    }

    Ok(())
}
