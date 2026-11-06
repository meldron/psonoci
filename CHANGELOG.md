# v0.7.0-rc.1 (`2026-11-06`)

- Added: alpha, beta and release-candidate tags publish downloadable prereleases on GitLab and GitHub, including signed archives and SBOMs, without uploading to `get.psono.com`.
- Added: `totp get-token`, `validate-token`, `get-url` and the `totp-*` secret fields now support website authenticators. They accept existing short seeds and period and digit settings stored as strings.
- Added: each release archive has a signed CycloneDX 1.6 SBOM. It lists Rust dependencies, bundled native libraries and direct external runtime dependencies. Release jobs check signatures, schema, target coverage and archive hashes before publishing. GitHub releases also include artifact attestations.
- Fixed: secret updates keep fields that `psonoci` does not recognize, including custom fields, tags, attachments and metadata on individual environment variables.
- Fixed: updates send the server's previous `write_date`. If the secret changed, the command stops without overwriting it. Servers that omit the timestamp keep the old update behavior.
- Fixed: unknown secret types no longer break bulk reads or `run`. You can read them as raw JSON. Typed updates to these secrets fail. Invalid known fields and decryption errors still stop the command.
- Fixed: `run --filter` fetches only selected secrets. Problems with excluded entries no longer stop the command.
- Fixed: password changes update Psono's `password_modification_datetime`. Other edits keep the password's age. Older entries without a valid timestamp use the previous server write date when available.
- Fixed: a standalone TOTP secret with a zero period now returns an error before token generation.
- Fixed: SSH and Elster JSON exports include their stored key and certificate fields.
- Changed: SSH key handling now uses `russh` in place of `russh-keys`. RSA keys and SSH-agent constraints still work.
- Changed: command-line and config parsing now store API secret keys in sensitive types.
- Changed: vendored native TLS now uses pinned OpenSSL 3.5.9 LTS source. Initialize its Git submodule before building from source. See the README.
- Changed: this release uses Rust `1.99.1` and updates dependencies and release tools.
- Changed: GitLab is the primary repository for development and releases; GitHub remains a secondary repository.
- Changed: security updates cover only the latest stable minor series. Once 0.7.0 is released, earlier versions are no longer supported.

# v0.6.0 (`2026-04-06`)

- Breaking: config files are now written with user-only permissions (`0600` on Linux/macOS, user-only ACL on Windows)
- Breaking: `run` no longer forwards inherited `PSONO_CI_*` config and authentication environment variables to spawned subprocesses
- Added: `onboard` sub command to bootstrap psonoci config with device-auth flow
- Added: Identity secret type support
- Changed: help output now uses canonical kebab-case option and enum spellings due to the clap 4 upgrade, while legacy snake_case secret value types remain accepted for compatibility
- Changed: upgraded Rust toolchain to `1.94.1`
- Changed: hardened internal secret handling with `secrecy` and `zeroize`
- Changed: dependency updates
- Changed: GitHub Actions updates (new actions, newer base systems, ...)

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
