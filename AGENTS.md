# AGENTS.md

## What this is

`vaultwarden-backup` backs up a vaultwarden `DATA_FOLDER` into one
timestamped `.tgz`: an SQLite online snapshot for `db.sqlite3` plus every
other file streamed into a tar → gzip archive, delivered atomically to each
local target and/or one S3-compatible object store (via the `object_store`
crate), optionally OpenPGP-encrypted via the system `gpg`.

## Commands

- Build: `cargo build` (release: `cargo build --release`)
- Test: `cargo test --all-targets` — **`gpg` must be on PATH** (integration
  tests generate throwaway keys in a temp `GNUPGHOME`)
- Lint: `cargo clippy --all-targets --all-features` — policy lives in
  `Cargo.toml` `[lints]` (rust `warnings` and `clippy::all` are `deny`), so
  no `-- -D warnings` flag
- Format: `cargo fmt`; check-only: `cargo fmt --check`
- CI (`.github/workflows/ci.yml`) runs the same fmt/clippy/test commands
  as the pre-commit hooks (`.pre-commit-config.yaml`), which additionally
  check commit-message format.

## Layout

- `src/main.rs` — `clap` CLI; the declared-type/value cross-checks happen
  here before any work; parses the required `--retention-period`
  (`VWB_RETENTION_PERIOD`) into `RetentionPeriod`
- `src/lib.rs` — `run()`: validate → preflight → db snapshot → archive →
  encrypt → deliver → (on success only) retention cleanup; `stamp()` mints the
  second-precision UTC file name; `archive_stamp()`/`should_delete()` are the
  shared retention predicates
- `src/db.rs` — `Connection::backup` (SQLite Online Backup), read-only open
  with a short busy retry
- `src/archive.rs` — streams the snapshot + files straight into gzip (no
  uncompressed scratch file), `.part` → rename in the scratch dir
- `src/files.rs` — iterative (explicit-stack) directory walk; skips
  `db.sqlite3` and its `-wal`/`-shm` sidecars **at the source root only**
- `src/crypto.rs` — recipient format/keyring preflight (full 40-hex-digit
  fingerprints, primary or subkey) + `gpg --encrypt` with compression off
  (input is already gzip)
- `src/deliver.rs` — atomic per-target copy; targets are independent but any
  failure fails the run, naming every failing target; also best-effort local
  retention cleanup (`cleanup_retention`)
- `src/s3.rs` — S3-compatible delivery (`object_store` + a shared lazily
  created tokio runtime behind a sync `block_on` wrapper): client build,
  head-based no-overwrite preflight, streaming multipart upload,
  `join_prefix` key composition, and best-effort S3 retention cleanup
  (`cleanup_retention` over `list_with_delimiter` + `delete`)

## Conventions & gotchas

- Errors are `anyhow::Error` + context; everything fallible uses `?` —
  `clippy::unwrap_used`/`expect_used` are denied in `Cargo.toml` `[lints]`,
  so production code may not `unwrap`/`expect` (only `stamp()`'s static
  format string, with an explicit allow). Test builds opt out via
  `cfg_attr(test, ..)` in `src/lib.rs` and `#![allow]` in
  `tests/`.
- Archive layout is **flat**: the data directory's contents sit at the
  archive root with no top-level directory — restore is
  `tar -x -C <data dir>`. Don't add a wrapper directory.
- `--name` is a file-name prefix: no `/` or NUL, ≤ 200 bytes. The suffix is
  a second-precision UTC stamp, so a same-second re-run aborts on the
  already-present name instead of overwriting.
- A file whose size/**mtime** changes while being archived fails the run
  loudly: tar records must match what was streamed, or the whole archive
  tail corrupts. Keep that check if you touch `files::write`.
- `.part` names must stay unique across concurrent runs (delivery appends
  the pid; scratch files live in a per-run `tempfile::tempdir()`).
- Comments are "why", not "what" — do not restate code.
- Tests: unit tests live in each `src/*.rs` module; end-to-end and
  real-binary CLI tests in `tests/` — `core.rs` (library-level), `cli.rs`
  (binary CLI + OpenPGP), `s3.rs` (offline cross-checks + gated e2e), with
  shared fixtures in `tests/common/mod.rs`.
- Commit messages follow **Conventional Commits**:
  `type(optional scope): imperative subject` — e.g. `feat:`, `fix:`,
  `docs:`, `ci:`; use a scope only when it adds context, e.g.
  `feat(deliver):`.
- The codebase language is **English** — code, comments, docs and commit
  messages.