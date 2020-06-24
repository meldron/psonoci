# psonoci

[PSONO](https://psono.com/) CI client.

PSONO is a secure Open Source Password Manager, which can be self hosted by anyone so you have to trust no one.

`psonoci` allows a secure access to your psono passwords (and other values) within your CI process.

## Usage

`psonoci --help`

```
psonoci 0.1.0
psono ci client

USAGE:
    psonoci [OPTIONS] --api-key-id <api-key-id> --api-secret-key-hex <api-secret-key-hex> --server-url <server-url> <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --api-key-id <api-key-id>                    api key as uuid [env: PSONO_CI_API_KEY_ID=]
        --api-secret-key-hex <api-secret-key-hex>
            api secret key as 64 byte hex string [env: PSONO_CI_API_SECRET_KEY_HEX=]

        --server-url <server-url>                    Url of the psono backend server [env: PSONO_CI_SERVER_URL=]
        --timeout <timeout>
            Connection timeout in seconds [env: PSONO_CI_TIMEOUT=]  [default: 60]


SUBCOMMANDS:
    help      Prints this message or the help of the given subcommand(s)
    secret    psono secret commands (/api-key-access/secret/)
```

### Basic Options

These options must be specified before the subcommand:

<!-- TODO UPDATE with new options -->

| Option                   | Env var                     | Type               | Required | Default | Description                                                               |
| ------------------------ | --------------------------- | ------------------ | -------- | ------- | ------------------------------------------------------------------------- |
| --api_key_id             | PSONO_CI_API_KEY_ID         | UUID               | yes      | None    | The UUID of your API key                                                  |
| --api_key_secret_key_hex | PSONO_CI_API_SECRET_KEY_HEX | 64 byte hex string | yes      | None    | Secret key used for decryption of the user's secret key                   |
| --server_url             | PSONO_CI_SERVER_URL         | URL                | yes      | None    | Address of the PSONO's backend server - e.g.: https://www.psono.pw/server |
| --timeout                | PSONO_CI_TIMEOUT            | uint64             | no       | 60      | Max http(s) request duration in seconds                                   |

### Secret sub command

Right now the secret sub command only supports getting secrets, but maybe further commands will be added in the future.

`psonoci secret --help`

```

psonoci-secret 0.1.0
psono secret commands (/api-key-access/secret/)

USAGE:
    psonoci --api-key-id <api-key-id> --api-secret-key-hex <api-secret-key-hex> --server-url <server-url> secret <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    get     Get a psono secret by its uuid
    help    Prints this message or the help of the given subcommand(s)
```

#### SecretGet

Get secret values from the psono backend server.

If the selected value is not set for this secret the process will fail.

`psonoci secret get --help`

```
psonoci-secret-get 0.1.0
Get a psono secret by its uuid

USAGE:
    psonoci secret get <secret-id> <secret-value>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

ARGS:
    <secret-id>       The secret's uuid
    <secret-value>    Which secret value to return ('json' returns all values in a json object) [possible values:
                      json, notes, password, title, url, url_filter, username, gpg_key_email, gpg_key_name,
                      gpg_key_private, gpg_key_public]
```

Supported secret types:

-   Website
-   Application
-   Note
-   GPGKey
-   Bookmark

## CI/CD Usage Example

TODO

<!-- See [ci.sh](./examples/ci.sh) for an example script on how to use `psonoci` during your CI/CD process. -->

## Build

### Rust native

If you have rust installed just run `cargo build --release`.

The current version builds with Rust `1.44`.

### Docker approach to create a static linux binary (musl)

[build_docker.sh](./build_docker.sh) can be used to build a static binary using `x86_64-unknown-linux-musl`.

Afterwards the stripped binary will be located at: `./build/psonoci`.

Cleanup:

-   delete docker_cache directory
-   delete docker image

```
$> file build/psono
build/psonoci: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped
```

This way is also used to create the `psonoci` releases.

## Install

Download `psonoci` binary, make executable (`chmod +x psonoci`), and place into a directory which is part of your `$PATH`.

## Key Setup

TODO

<!-- ### Create API Key

1. Go to `Other -> API Keys` and click `Create new API Key`.
2. Name your API key and make sure neither `Secret Restriction?` nor `Allow insecure usage?` are activated. (see Image )
3. Click Create
4. In the API key overview click on the edit Icon for the newly created key
5. In this view you will see all secrets you need for the `psoco` config (see image 2)

#### Create API Key

![Create API Key](./images/create_api_key.png "Create API Key")

#### View API Key

![View API Key](./images/view_api_key_secrets.png "View API Key") -->

## License

[The MIT License](https://opensource.org/licenses/MIT)

Copyright (c) 2020 Bernd Kaiser
