use structopt::StructOpt;

use uuid::Uuid;

use crate::api::{ApiSettings, SecretValue};

#[derive(StructOpt, Debug)]
#[structopt(name = "psonoci", about = "Psono ci client")]
pub struct Opt {
    #[structopt(subcommand)]
    pub command: Command,
    #[structopt(flatten)]
    pub api_settings: ApiSettings,
}

#[derive(StructOpt, Debug)]
pub enum Command {
    #[structopt(about = "Psono secret commands (/api-key-access/secret/)")]
    Secret(SecretCommand),
}

#[derive(StructOpt, Debug)]
pub enum SecretCommand {
    #[structopt(about = "Get a psono secret by its uuid")]
    Get {
        #[structopt(required = true, help = "The secret's uuid")]
        secret_id: Uuid,
        #[structopt(required = true, possible_values = &SecretValue::variants(), case_insensitive = true, help = "Which secret value-type to return ('json' returns all value-types in a json object)")]
        secret_value: SecretValue,
    },
}
