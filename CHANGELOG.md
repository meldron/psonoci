# v0.2.2 (`2021-05-05`)

-   Fix: fix api endpoint url creation with `server-url` (also now ignores trailing slashes)

# v0.2.1 (`2021-04-15`)

-   `api-key` show now contains `api_key_secrets_meta_data`, which for now contain the write_date of a secret.
-   Fix: Add missing help texts

# v0.2.0 (`2021-04-15`)

-   Add support to write secrets
-   Add `config` support
-   Add `run` commands to spawn programs with environment variables from your secrets
-   Add `api-keys` command to query all secrets which are associated with the api key
-   Update dependencies

# v0.1.0 (`2020-06-17`)

-   Initial release with supports to get secrets
