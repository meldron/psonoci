# psonoci

[PSONO](https://psono.com/) CI Client.

PSONO is a secure Open Source Password Manager, which can be self hosted by anyone so you have to trust no one.

`psonoci` allows a secure access to your psono passwords (and other values) within your CI process.

## Usage

`psonoci --help`

```
psonoci 0.5.0
Bernd Kaiser
Psono CI Client (https://github.com/meldron/psonoci)

USAGE:
    psonoci [FLAGS] [OPTIONS] --api-key-id <api-key-id> --api-secret-key-hex <api-secret-key-hex> --server-url <server-url> <SUBCOMMAND>

FLAGS:
        --danger-disable-tls-verification    DANGER: completely disables all TLS (common name and certificate)
                                             verification. You should not use this. A better approach is just using
                                             plain http so there's no false sense of security (Psono secrets are still
                                             authenticated)
    -h, --help                               Prints help information
        --use-native-tls                     Use native TLS implementation (for linux musl builds a vendored openssl is
                                             used)
    -V, --version                            Prints version information

OPTIONS:
        --api-key-id <api-key-id>                                  Api key as uuid [env: PSONO_CI_API_KEY_ID=]
        --api-secret-key-hex <api-secret-key-hex>
            Api secret key as 64 byte hex string [env: PSONO_CI_API_SECRET_KEY_HEX=]

        --config-packed <config_packed>
            psonci config as packed string [env: PSONO_CI_CONFIG_PACKED=]

    -c, --config-path <config_path>                                psonoci config path [env: PSONO_CI_CONFIG_PATH=]
        --der-root-certificate-path <der-root-certificate-path>
            Path to a DER encoded root certificate which should be added to the trust store [env:
            PSONO_CI_ADD_DER_ROOT_CERTIFICATE_PATH=]
        --max-redirects <max-redirects>
            Maximum numbers of redirects [env: PSONO_CI_MAX_REDIRECTS=]  [default: 0]

        --pem-root-certificate-path <pem-root-certificate-path>
            Path to a pem encoded root certificate which should be added to the trust store [env:
            PSONO_CI_ADD_PEM_ROOT_CERTIFICATE_PATH=]
        --server-url <server-url>
            Url of the psono backend server [env: PSONO_CI_SERVER_URL=]

        --timeout <timeout>
            Connection timeout in seconds [env: PSONO_CI_TIMEOUT=]  [default: 60]


SUBCOMMANDS:
    api-key     Psono api-key inspect (/api-key-access/inspect/)
    config      Config commands (create, save, pack,...)
    env-vars    Convenience commands on environment variable secrets
    gpg         GPG commands
    help        Prints this message or the help of the given subcommand(s)
    license     Prints psonoci's license
    run         Spawns processes with environment vars from the api-keys secrets
    secret      Psono secret commands (/api-key-access/secret/)
    ssh         SSH commands
    totp        TOTP commands
```

### Required Options

These three options must be supplied (and be in front of the subcommand):

| Option                   | Env var                     | Type               | Required | Default | Description                                                               |
| ------------------------ | --------------------------- | ------------------ | -------- | ------- | ------------------------------------------------------------------------- |
| --api_key_id             | PSONO_CI_API_KEY_ID         | UUID               | yes      | None    | The UUID of your API key                                                  |
| --api_key_secret_key_hex | PSONO_CI_API_SECRET_KEY_HEX | 64 byte hex string | yes      | None    | Secret key used for decryption of the user's secret key                   |
| --server_url             | PSONO_CI_SERVER_URL         | URL                | yes      | None    | Address of the PSONO's backend server - e.g.: https://www.psono.pw/server |

There are several more options, please use the `help` commands for more info.

## SSH

Since version `0.5` `psonoci` supports Psono's SSH sub command, which allows you to add SSH keys stored in your Psono vault to your SSH agent.

This feature is currently **not** available on Windows.

The SSH subcommand provides the following operation:

### `add`

`psonoci ssh add secret-id [OPTIONS]`: adds an SSH key from a Psono secret to your SSH agent.

Options:
- `--ssh-auth-sock-path <PATH>`: Path of the SSH_AUTH_SOCK (overwrites $SSH_AUTH_SOCK environment variable)
- `--key-passphrase <PASSPHRASE>`: Optional passphrase which was used to encrypt the key
- `--key-lifetime <SECONDS>`: Limit the key's lifetime by deleting it after the specified duration in seconds
- `--key-confirmation`: Require explicit user confirmation for each private key operation using the key

The secret must be of type SSH Key and contain a private key. On Unix systems, if `--ssh-auth-sock-path` is not provided, the command will use the `SSH_AUTH_SOCK` environment variable. 

## GPG

Since version `0.5` `psonoci` supports Psono's GPG secret type, allowing you to securely manage GPG keys stored in your Psono vault for signing and verification operations.

The GPG subcommand provides two main operations:

### `sign`

`psonoci gpg sign secret-id [OPTIONS] [INPUT_FILE]`: signs data using the GPG private key stored in the specified secret. 

Options:
- `--input-file <PATH>`: File to sign (if not provided, reads from stdin)
- `--output <PATH>`: Write signature to file (if not provided, writes to stdout)
- `--armor`: Output ASCII armored signature instead of binary

The secret must be of type GPG Key and contain a private key.

### `verify`

`psonoci gpg verify secret-id --signature <SIGNATURE_FILE> [OPTIONS] [INPUT_FILE]`: verifies a signature using the GPG public key stored in the specified secret.

Options:
- `--input-file <PATH>`: File to verify (if not provided, reads from stdin)
- `--signature <PATH>`, `-s <PATH>`: Path to the signature file (required)
- `--quiet`, `-q`: Do not print verification error
- `--verbose`, `-v`: Print success message with signature details

Returns with exit code `0` if the signature is valid, otherwise displays an error and returns with exit code `1`. When using `--verbose`, displays information about when the signature was created and by whom.

## TOTP

Since version `0.4` `psonoci` supports Psono's [Time-based one-time password (TOTP)](https://en.wikipedia.org/wiki/Time-based_one-time_password) secret type.

Besides the standard functionality to read and write the secret info (`secret` subcommand), 
`psonoci` also supports the creation and validation of tokens (both commands require a correctly configured system time).

### get-token

`psonoci topt get-token secret-id`: returns a currently valid TOTP token.

### validate-token

`psonoci topt validate-token secret-id token`: checks if a token is currently valid. Returns with exit code `0` if valid, otherwise displays an error and returns with exit code `1`.

### get-url

Also there is the option to export the token [otpauth url](https://github.com/google/google-authenticator/wiki/Key-Uri-Format) with `psonoci topt get-url secret-id`.
## Run With Protected Environments

`psonoci` can now inject environment variables from your secrets right into you programs!

First create a new secret of the type "`Environment Variables`":

![create Environment Variables](examples/env_vars_create.png "Create Environment Variables")

Then add this secret to your api key

![create api key with env vars](examples/env_vars_api_key.png "create api key with env vars")

and afterwards run:

```sh
psonoci -c /path/to/config-staging.toml run -- ./my_backend.py --timeout 10
```

This command will execute `./my_backend.py` and inject all environment variables of all secrets into the process:

```py
#!/usr/bin/python3

# content of my_backend.py
import os
import sys

print("args: {}".format(sys.argv))
print("environment: {}".format(os.environ))
```

Would return:

```
args: ['my_backend.py', '--timeout', '60']
environment: environ({'db_host': 'staging.psono.pw', 'db_password': '5IYqNwDwB6pPSr2YTK5fW', 'db_username': 'staging'})
```

## Environment Variable Convenience Commands (`env-vars`)

Since `v0.3.0` `psonoci` supports the new `env-vars` sub command, which provides convenience functions to get/update or create environment variable names in a specific secret.

Both subcommands work only on secrets of the type environment variables. If they are used with another type of secret, `psonoci` will return an error.

### `get-or-create`

`psonoci env-vars get-or-create` returns the environment variable value by name. If more than one environment variable have the same name/key, the first one will be returned. If there is no environment variable with that name, a new entry will be created with that name and a random value.

`--danger-password-allowed-chars` adjusts of the used characters in the generated value. If this option is not supplied, `psonoci` will create an alphanumeric string (`[a-zA-Z0-9]`).

The length of the newly created random value can set with `--password-length`. Please take notice that this length specifies the number of unicode characters (not bytes).

Example

```sh
psonoci -c psonoci.toml env-vars get-or-create \
    --password-length 10 \
    --danger-password-allowed-chars "🙈🙉🙊👹🦀🦐🦑🍦🍧🍨🍩🎂🏴󠁧󠁢󠁷󠁬󠁳󠁿" \
    e6305462-1d5d-478c-90eb-03da80e85cff DB_PASSWORD
```

creates (for example) this string: `🏴󠁧󠁢󠁷󠁬󠁳󠁿🦑👹🦑🙉🍧🦑🏴󠁧󠁢󠁷󠁬󠁳󠁿🙊🦀`

-   String length: `10`
-   Byte length: `88`

(Please don't use only these chars as `--danger-password-allowed-chars`)

### `update-or-create`

`psonoci env-vars update-or-create` updates or creates environment variable value by name with the supplied value and then returns this value. If there is no environment variable with that name a new one is created. If there are more than one with the same name, only the first will be updated. If no new value is provided a random one will be created. The new value can be adjusted with `--password-length` and `-danger-password-allowed-chars`. Please see above.

## Config

`psonoci` can also be configured with a config file or config string.

### Config File

```sh
psonoci \
    --api-key-id 00000000-0000-0000-0000-000000000000 \
    --api-secret-key-hex 0000000000000000000000000000000000000000000000000000000000000000 \
    --server-url 'https://psono.pw/server' \
    config save /tmp/psonoci.toml
```

Creates the following config file at `/tmp/psonoci.toml`

```toml
version = "1"

[psono_settings]
api_key_id = "00000000-0000-0000-0000-000000000000"
api_secret_key_hex = "0000000000000000000000000000000000000000000000000000000000000000"
server_url = "https://psono.pw/server/"

[http_options]
timeout = 60
max_redirects = 0
use_native_tls = false
danger_disable_tls_verification = false
```

The config file then can be loaded with:

```sh
psonoci -c /path/to/config.toml config show
```

or be supplied by an environment variable

```sh
PSONO_CI_CONFIG_PATH="/path/to/config.toml" psonoci config show
```

### Config String

If you don't want to use files to load the config there is also the option to load the config from a base58 encoded string which can be supplied as an environment variable.

```sh
psonoci \
    --api-key-id 00000000-0000-0000-0000-000000000000 \
    --api-secret-key-hex 0000000000000000000000000000000000000000000000000000000000000000 \
    --server-url 'https://psono.pw/server' \
    config pack
```

Returns this string :

```
5dtuTPxg1kDP3Qoz2HKbMxT4kDqTYxbUo8mxR9yEp7YNSYq6dP8Gv4ysoVAjW8qS2iYwEaRm9NxzpbSXuwwXL45aHLiWi8TBSee3KnitgJPGyiuGCREGibB2pVCPCVg1zb11TpsbKuzV3aGhqQyE1NJnYwo9qrVjw6P
```

which than can be used with:

```sh
psonoci \
    --config-packed="5dtuTPxg1kDP3Qoz2HKbMxT4kDqTYxbUo8mxR9yEp7YNSYq6dP8Gv4ysoVAjW8qS2iYwEaRm9NxzpbSXuwwXL45aHLiWi8TBSee3KnitgJPGyiuGCREGibB2pVCPCVg1zb11TpsbKuzV3aGhqQyE1NJnYwo9qrVjw6P" \
    config show
```

or

```sh
PSONO_CI_CONFIG_PACKED="5dtuTPxg1kDP3Qoz2HKbMxT4kDqTYxbUo8mxR9yEp7YNSYq6dP8Gv4ysoVAjW8qS2iYwEaRm9NxzpbSXuwwXL45aHLiWi8TBSee3KnitgJPGyiuGCREGibB2pVCPCVg1zb11TpsbKuzV3aGhqQyE1NJnYwo9qrVjw6P" psonoci config show
```

## Supported secret types:

-   Website
-   Application
-   Note
-   GPGKey
-   Bookmark
-   Environment Variables
-   Credit Card
-   TOTP
-   SSH Key

## Build

### Rust native

If you have rust installed just run `cargo build --release`.

The current version is tested with Rust `1.71.1`.

### cross

[cross](https://github.com/rust-embedded/cross) (which uses `docker`) is used to cross compile `psonoci` to several architectures.

After you installed `cross` just run:

```sh
cross build --target aarch64-unknown-linux-musl --release
```

`Cross.toml` defines which docker images are used to compile the binary. The images itself are build with the `Dockerfile`s located in `./build_files`.

## Supported Architectures

-   x86_64-unknown-linux-gnu
-   x86_64-unknown-linux-musl
-   x86_64-pc-windows-msvc
-   x86_64-pc-windows-gnu
-   x86_64-apple-darwin
-   aarch64-apple-darwin
-   aarch64-unknown-linux-musl
-   armv7-unknown-linux-gnueabihf
-   armv7-unknown-linux-musleabihf

~~Sadly I have to drop support for `armv7-unknown-linux-musleabihf` until Rust is able to link against `MUSL v1.2.2`.~~

~~Falling back to `MUSL <=1.1` is no longer an option because of [CVE-2020-28928](https://www.openwall.com/lists/musl/2020/11/19/1)~~

Since version `0.4` the `armv7-unknown-linux-musleabihf` target is back!

Since version `0.4` the `aarch64-apple-darwin` target is also build and released.

## Install

Download `psonoci` binary, make executable (`chmod +x psonoci`), and place into a directory which is part of your `$PATH`.

## License

[The MIT License](https://opensource.org/licenses/MIT)

Copyright (c) 2020, 2021, 2022, 2023 Bernd Kaiser
