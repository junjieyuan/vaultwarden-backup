# vaultwarden-backup

Backs up a vaultwarden `DATA_FOLDER` into a single timestamped `.tgz`:
`<name>-<UTC timestamp>.tgz`, e.g. `vaultwarden-backup-2026-07-22T11:04:59Z.tgz`,
delivered to every local target you name.

The archive is safe to upload and safe to restore:

- The `db.sqlite3` entry is a **standalone snapshot** taken with the SQLite
  Online Backup API (`Connection::backup`), so a running instance can be
  backed up without a write lock and without copying the `-wal`/`-shm`
  sidecars. Anything written to the source after the snapshot is not in the
  archive.
- Every other file (`attachments/`, `sends/`, `config.json`, `rsa_key*`,
  `icon_cache/`, …) is copied byte-exact, permissions and mtime included.
  Symlinks, special files, and empty directories are skipped with a warning
  on stderr. If a file is rewritten while being copied (vaultwarden
  refreshes `icon_cache/` or `config.json` while running), the run **fails
  loudly** instead of shipping a mis-sized tar entry that would corrupt the
  rest of the archive — re-run to pick up a clean copy.
- The data directory's contents sit directly at the archive root (no
  top-level directory), so restoring is `tar -x -C <data dir>`.
- All intermediate artifacts (database snapshot, the `.tgz`, and — when
  encrypted — the plaintext archive itself) live in a scratch directory and
  are copied to the targets only once finished; delivery writes a unique
  `<final>.part.<pid>` + fsync + rename, so a failed run never leaves a
  partial archive in any target.
- The same physical directory named through two spellings (e.g. via a
  symlink) is delivered exactly once.

## Usage

```
vaultwarden-backup
  --source-type <TYPE> --local-source <DIR>
  --target-type <TYPE> --local-target <DIR>
  --name <NAME> --database-type <TYPE> --encryption-type <TYPE>
  [--recipient <FPR>]...
```

All options are long-only. Every option can come from the command line or
its environment variable; the command line wins.

| Option | Env var | Meaning |
| --- | --- | --- |
| `--source-type` | `VWB_SOURCE_TYPE` | source type; only `local` |
| `--local-source` | `VWB_LOCAL_SOURCE` | the vaultwarden data directory (contains `db.sqlite3`); a single directory — the source is always one |
| `--target-type` | `VWB_TARGET_TYPE` | destination type(s); only `local` |
| `--local-target` | `VWB_LOCAL_TARGET` | local target directory (created if missing); repeat or comma-separate (`A,B`) to deliver one copy to several local directories; the same physical directory given twice is delivered once |
| `--name` | `VWB_NAME` | archive name prefix (final file is `<name>-<YYYY-MM-DDTHH:MM:SSZ>.tgz`); at most 200 bytes, must not contain `/` (any other character, including non-ASCII, is fine) |
| `--database-type` | `VWB_DATABASE_TYPE` | database type; only `sqlite` is supported |
| `--encryption-type` | `VWB_ENCRYPTION_TYPE` | encryption type: `none` (plaintext) or `openpgp`; the choice is explicit so a run can never silently come out unencrypted |
| `--recipient` | `VWB_RECIPIENTS` | OpenPGP **40-hex-digit fingerprint** (short keyids are rejected; primary or subkey) — repeat `--recipient`, or comma-separate (`A,B`); `VWB_RECIPIENTS` is also comma-separated; **required** with `--encryption-type openpgp`, **forbidden** with `none`; public key must be in the local gpg keyring; see **Encryption** |

### Type/value cross-checks

A declared type requires its value flag, and a value flag requires its
declared type — so a second `--local-source` is a duplicate value, not a
second source, and `--local-source` without `--source-type local` is an
error (`--encryption-type` / `--recipient` follow the same rule). A
preflight failure writes nothing to any target.

The timestamp is UTC, the **start** time, at second precision. If a target
already holds this run's file name (a re-run within the same second), the run
aborts **before doing any backup work** instead of overwriting the previous
archive.

On success the delivered archive path is printed to stdout, **one line per
target**, in target order, and the exit code is 0. On failure the reason goes
to stderr and the exit code is non-zero; when delivery fails for some but not
all targets, every failing target is named and the already-delivered ones
stay.

### Examples

```sh
# command line, plaintext (--encryption-type none means no --recipient)
vaultwarden-backup \
  --source-type local --local-source /srv/vaultwarden/data \
  --target-type local --local-target /backup \
  --name vaultwarden-backup --database-type sqlite --encryption-type none

# two local destinations, encrypted (recipients may be repeated or comma-separated)
vaultwarden-backup \
  --source-type local --local-source /srv/vaultwarden/data \
  --target-type local --local-target /backup,/backup-raid \
  --name vaultwarden-backup --database-type sqlite --encryption-type openpgp \
  --recipient AAAABBBBCCCCDDDD111122223333444455556666

# environment only (cron / systemd)
export VWB_SOURCE_TYPE=local VWB_LOCAL_SOURCE=/srv/vaultwarden/data
export VWB_TARGET_TYPE=local VWB_LOCAL_TARGET=/backup
export VWB_NAME=vaultwarden-backup VWB_DATABASE_TYPE=sqlite
export VWB_ENCRYPTION_TYPE=openpgp
export VWB_RECIPIENTS=AAAABBBBCCCCDDDD111122223333444455556666
vaultwarden-backup
```

```cron
0 3 * * * VWB_SOURCE_TYPE=local VWB_LOCAL_SOURCE=/srv/vaultwarden/data VWB_TARGET_TYPE=local VWB_LOCAL_TARGET=/backup VWB_NAME=vaultwarden-backup VWB_DATABASE_TYPE=sqlite VWB_ENCRYPTION_TYPE=openpgp VWB_RECIPIENTS=<FINGERPRINT> /usr/local/bin/vaultwarden-backup >> /var/log/vwb-backup.log 2>&1
```

## Online backup notes

- The source is opened `SQLITE_OPEN_READ_ONLY`: no write lock, no `-shm`
  side file next to the live database.
- The backup retries for 10 s against a transient `SQLITE_BUSY`; a longer
  uncommitted write transaction still fails, with a message telling you to
  retry shortly or stop the instance first.

## Scratch space

Intermediates live in one `tempfile::tempdir()` directory (honoring
`TMPDIR`), auto-deleted even on failure. Allow roughly the size of the final
archive. Files are streamed into the archive (no whole file is read into
memory) and the tar goes straight into gzip, so there is no uncompressed
scratch file.

## Encryption (OpenPGP)

The archive contains **plaintext secrets** — encrypt it before object storage
or cloud drives:

- `config.json` — admin token, SMTP credentials, and other plaintext config;
- `rsa_key.pem` / `rsa_key.pub.der` — the service signing key;
- `db.sqlite3` — all entries (vaultwarden field-encrypts values, but keys and
  metadata live in the file).

The official wiki also recommends encrypted backups:
<https://github.com/dani-garcia/vaultwarden/wiki/Backing-up-your-vault>

Set `--encryption-type openpgp` and pass recipients with `--recipient`
(repeat the flag, or comma-separate them into one value) — see Examples
above. The same comma-separation applies to the `VWB_RECIPIENTS` environment
variable.

- Recipients must be **full key fingerprints**: exactly 40 hex
  digits (short keyids are rejected — they are subject to collision
  attacks); matching is case-insensitive, so upper-case hex is fine.
  Primary and subkey fingerprints both work — anything `gpg --encrypt`
  accepts as a recipient. To find a key's full fingerprint:
  `gpg --list-keys --fingerprint <keyid-or-email>` — the 40-hex-digit line is
  what `--recipient` takes. Encryption is selected explicitly via
  `--encryption-type openpgp`, and `--recipient` is then required — the two
  are cross-checked up front, so a plaintext archive can never come out by
  accident (missing `--recipient`) and a run with `--encryption-type none`
  cannot silently carry `--recipient`.
- The public key must already be in the **local gpg keyring** of the user
  running the backup (`gpg --import recipient.pub`). The tool only takes
  fingerprints and invokes the system `gpg`; it never handles key material
  itself. Recipients are verified up front, so a typo fails before any
  backup work and writes nothing.
- With recipients, the output is `<name>-<timestamp>.tgz.gpg`; the
  plaintext `.tgz` is deleted once encryption succeeded and never lingers,
  even on failure.

## Restore

1. Stop the vaultwarden instance.
2. Encrypted archives: decrypt first (`gpg -d <archive>.tgz.gpg > archive.tgz`)
   — this needs the private key, so do it as the user that owns it.
3. Extract the archive over the instance root — the entries sit directly at
   the archive root (no top-level `data/` folder), so extract into the
   `DATA_FOLDER` itself: `tar -xzf <archive>.tgz -C /path/to/instance/data`.
4. Delete any leftover `db.sqlite3-wal` — the snapshot does not include WAL
   sidecars, and an old one would be loaded for the wrong database.
5. Start the instance and verify your entries load.
6. Practice restores regularly.

## Build & test

Requires Rust **1.98 or newer** (enforced via `rust-version` in
`Cargo.toml`). A [`rust-toolchain.toml`](rust-toolchain.toml) pins the
toolchain (with `clippy`/`rustfmt` components) for rustup users — clone and
`cargo build` just works, in CI too.

```sh
cargo build --release   # -> target/release/vaultwarden-backup
cargo test              # unit + integration (incl. real-binary CLI tests)
```

`cargo test` needs `gpg` on `PATH` (the integration tests generate throwaway
keys in a temporary `GNUPGHOME`).

`rusqlite` uses the `bundled` feature (compiles SQLite; no system libsqlite
needed).

## Format & lint (pre-commit)

Formatting, linting and commit-message format are enforced by local
[pre-commit](https://pre-commit.com) hooks (`.pre-commit-config.yaml`):

- `conventional-pre-commit` — validates the Conventional Commits format of
  every commit message (commit-msg stage)
- `rust-fmt` — `cargo fmt`: auto-fixes on commit, so a commit can
  never land unformatted
- `rust-clippy` — `cargo clippy --all-targets --all-features`: fails the
  commit on any warning

The lint policy itself lives in `Cargo.toml` (`[lints]`: rust `warnings` and
the whole `clippy::all` default set are `deny`, and `unwrap`/`expect` are
banned outside tests via `clippy::unwrap_used`/`expect_used`), so
`cargo build`, `cargo clippy` and the hooks all share the same
warnings-are-errors policy — the command line stays free of `-- -D warnings`
flag duplication.

The same fmt/clippy/test checks run in CI on every push and PR
(`.github/workflows/ci.yml`).

Install once per clone: `uvx pre-commit install`. If `uv` cache pruning
removes the hook's environment, commits fail closed until you re-run that
command. Manual check: `uvx pre-commit run --all-files`.
