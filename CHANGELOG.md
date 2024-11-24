# v0.5.0 (`2024-11-25`)

- Add `gpg` sub command
    - `sign` signs data using a GPG private key stored in a Psono secret
    - `verify` verifies signatures using a GPG public key stored in a Psono secret
- Add `ssh` sub command (Unix only)
    - `add` adds SSH keys from Psono secrets to the SSH agent with optional lifetime and confirmation constraints
- Add Elster certificate secret type support
- Add aarch64-apple-darwin target to releases
- Update Rust toolchain to `1.82.0`
- Use native TLS implementation for musl builds
- Various dependency updates and CI/CD improvements
- Fix missing API setters and JSON get functionality

# v0.4.0 (`2023-08-11`)

- Add `totp` sub command
    - `validate-token` checks if a token is currently valid for a TOTP Secret
    - `get-token` gets the current token for a TOTP secret
    - `get-url` gets the otpauth url for a TOTP secret
- Add credit card, totp and ssh key secret types
- Reenable `armv7-unknown-linux-musleabihf` target
- Update dependencies

# v0.3.0 (`2022-01-01`)

- Add `env-vars` sub command, which provides convenience commands for environment variable secrets

    - `get-or-create` returns or creates a specific environment variable by name (key).

      If the environment variable does not exist it creates a new entry add the end of the environment variables list
      and inserts a random env var value. The length and the charset can be adjusted (`--password-length` and
      `--danger-password-allowed-chars`). By default created environment values are alphanumeric (`[a-zA-Z0-9]`) and
      have a length of `21` chars.

    - `update-or-create` updates or creates a specific environment variable by name (key) with the supplied value.

# v0.2.3 (`2021-12-27`)

- Fix: Docker `cross` build for `aarch64-unknown-linux-musl` and `armv7-unknown-linux-gnueabihf`

# v0.2.2 (`2021-05-05`)

- Fix: fix api endpoint url creation with `server-url` (also now ignores trailing slashes)

# v0.2.1 (`2021-04-15`)

- `api-key` show now contains `api_key_secrets_meta_data`, which for now contain the write_date of a secret.
- Fix: Add missing help texts

# v0.2.0 (`2021-04-15`)

- Add support to write secrets
- Add `config` support
- Add `run` commands to spawn programs with environment variables from your secrets
- Add `api-keys` command to query all secrets which are associated with the api key
- Update dependencies

# v0.1.0 (`2020-06-17`)

- Initial release with supports to get secrets
