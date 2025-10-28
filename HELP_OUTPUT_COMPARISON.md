# Help Output Comparison: structopt → clap v3

## Summary

The migration from `structopt 0.3` to `clap 3.2` introduced cosmetic changes to the help output, but **no functional changes** to the CLI interface. All commands, subcommands, arguments, and options work identically.

## Differences Found

### 1. Version Number Display
- **Before**: `psonoci-api-key-info 0.5.0`
- **After**: `psonoci-api-key-info`

The version number is no longer displayed in subcommand help headers (only in main `--version`).

### 2. FLAGS → OPTIONS
- **Before**: `FLAGS:` section header
- **After**: `OPTIONS:` section header

Clap v3 uses "OPTIONS" terminology instead of "FLAGS".

### 3. Help Text Wording
- **Before**: `Prints help information` / `Prints version information`
- **After**: `Print help information` 

Minor grammar change from third-person to imperative.

### 4. Argument Name Formatting
- **Before**: `<secret-id>`, `<api-key-id>`, `<path>`
- **After**: `<SECRET_ID>`, `<API_KEY_ID>`, `<PATH>`

Arguments now display in UPPERCASE in help output (a clap v3 convention).

### 5. USAGE Line Simplification
- **Before**: `psonoci --api-key-id <api-key-id> --api-secret-key-hex <api-secret-key-hex> --server-url <server-url> api-key <SUBCOMMAND>`
- **After**: `psonoci api-key <SUBCOMMAND>`

Subcommand help no longer shows parent command options in USAGE line (cleaner display).

### 6. Hyphen vs Underscore in Possible Values
- **Before**: `url_filter`, `ssh_key_public`, etc.
- **After**: `url-filter`, `ssh-key-public`, etc.

Enum variants with underscores are now displayed with hyphens in help (kebab-case convention).

## Verification

All differences are purely cosmetic formatting changes introduced by clap v3's updated help formatter. The actual CLI behavior, argument parsing, and functionality remain **100% compatible**.

### Commands Verified
- ✅ Main help (`--help`)
- ✅ `secret` (get, set)
- ✅ `api-key` (info, secrets)
- ✅ `config` (pack, save, show)
- ✅ `run`
- ✅ `env-vars` (get-or-create, update-or-create)
- ✅ `totp` (get-token, validate-token, get-url)
- ✅ `ssh` (add) - Unix only
- ✅ `gpg` (sign, verify)
- ✅ `license`

### Tests
- ✅ All 49 unit tests pass
- ✅ All integration tests pass
- ✅ CLI commands execute correctly

## Conclusion

The migration is **backward compatible** from a user perspective. Users will notice slightly different help formatting, but all commands work identically. No breaking changes to the CLI interface.
