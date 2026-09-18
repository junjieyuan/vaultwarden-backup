# vaultwarden-backup

Backs up a vaultwarden `DATA_FOLDER` into a single timestamped `.tgz`:
`<name>-<UTC timestamp>.tgz`, e.g. `vaultwarden-backup-2026-07-22T11:04:59Z.tgz`,
delivered to every local target you name, and optionally to one S3-compatible
object-store target (AWS S3, Cloudflare R2, Wasabi, Backblaze B2, MinIO,
RustFS, …).

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
  --target-type <TYPE> [--local-target <DIR>]...
  [--s3-endpoint <URL> --s3-region <REGION> --s3-access-key <KEY>
   --s3-secret-key <SECRET> --s3-bucket <BUCKET> --s3-prefix <PREFIX>
   --s3-addressing <virtual-hosted|path-style>]
  --name <NAME> --database-type <TYPE> --encryption-type <TYPE>
  --retention-period <PERIOD>
  [--recipient <FPR>]...
```

All options are long-only. Every option can come from the command line or
its environment variable; the command line wins.

| Option | Env var | Meaning |
| --- | --- | --- |
| `--source-type` | `VWB_SOURCE_TYPE` | source type; only `local` |
| `--local-source` | `VWB_LOCAL_SOURCE` | the vaultwarden data directory (contains `db.sqlite3`); a single directory — the source is always one |
| `--target-type` | `VWB_TARGET_TYPE` | destination type(s): `local` and/or `s3` |
| `--local-target` | `VWB_LOCAL_TARGET` | local target directory (created if missing); repeat or comma-separate (`A,B`) to deliver one copy to several local directories; the same physical directory given twice is delivered once |
| `--s3-endpoint` | `VWB_S3_ENDPOINT` | S3-compatible endpoint URL, **required** with `--target-type s3`: self-hosted (RustFS, MinIO), S3-compatible clouds (Wasabi, Backblaze B2, Cloudflare R2) or AWS itself (`https://s3.<region>.amazonaws.com`) |
| `--s3-region` | `VWB_S3_REGION` | region used for signing, **required** with `--target-type s3`; passed through verbatim — Cloudflare R2 uses `auto` |
| `--s3-access-key` | `VWB_S3_ACCESS_KEY` | S3 access key, **required** with `--target-type s3` |
| `--s3-secret-key` | `VWB_S3_SECRET_KEY` | S3 secret key, **required** with `--target-type s3` |
| `--s3-bucket` | `VWB_S3_BUCKET` | S3 bucket name, **required** with `--target-type s3`; the bucket must already exist |
| `--s3-prefix` | `VWB_S3_PREFIX` | object key prefix, **required** with `--target-type s3`; `/` (or the empty string) means bucket root, `weekly`/`weekly/` are the same |
| `--s3-addressing` | `VWB_S3_ADDRESSING` | addressing style, **required** with `--target-type s3`: `virtual-hosted` (`https://<bucket>.<endpoint>/<key>`) for AWS-style endpoints, `path-style` (`https://<endpoint>/<bucket>/<key>`) for IP/self-hosted/R2 endpoints |
| `--name` | `VWB_NAME` | archive name prefix (final file is `<name>-<YYYY-MM-DDTHH:MM:SSZ>.tgz`); at most 200 bytes, must not contain `/` (any other character, including non-ASCII, is fine) |
| `--database-type` | `VWB_DATABASE_TYPE` | database type; only `sqlite` is supported |
| `--encryption-type` | `VWB_ENCRYPTION_TYPE` | encryption type: `none` (plaintext) or `openpgp`; the choice is explicit so a run can never silently come out unencrypted |
| `--retention-period` | `VWB_RETENTION_PERIOD` | how long to keep previous archives, **required** and always supplied; exactly `unlimited` (keep everything) or a positive integer followed by `d` (days) or `h` (hours), e.g. `14d`, `72h`; see **Retention** |
| `--recipient` | `VWB_RECIPIENTS` | OpenPGP **40-hex-digit fingerprint** (short keyids are rejected; primary or subkey) — repeat `--recipient`, or comma-separate (`A,B`); `VWB_RECIPIENTS` is also comma-separated; **required** with `--encryption-type openpgp`, **forbidden** with `none`; public key must be in the local gpg keyring; see **Encryption** |

### Type/value cross-checks

A declared type requires its value flag, and a value flag requires its
declared type — so a second `--local-source` is a duplicate value, not a
second source, and `--local-source` without `--source-type local` is an
error. The S3 destination follows the same rule, tightened: `--target-type s3`
requires **all seven** `--s3-*` flags, and any `--s3-*` flag without
`--target-type s3` is an error. Nothing about the S3 destination is silently
defaulted — no implicit endpoint, region, prefix or addressing style.
`--encryption-type` / `--recipient` follow the same rule. A preflight failure
writes nothing to any target.

The timestamp is UTC, the **start** time, at second precision. If a target
already holds this run's file name (a re-run within the same second), the run
aborts **before doing any backup work** instead of overwriting the previous
archive — the check applies to local files **and** to the S3 object.

On success one line per target is printed to stdout, in target order: the
delivered local path, or `s3://<bucket>/<key>` for the S3 target, and the exit
code is 0. On failure the reason goes to stderr and the exit code is
non-zero; when delivery fails for some but not all targets, every failing
target is named and the already-delivered ones stay.

### Examples

```sh
# command line, plaintext (--encryption-type none means no --recipient)
vaultwarden-backup \
  --source-type local --local-source /srv/vaultwarden/data \
  --target-type local --local-target /backup \
  --name vaultwarden-backup --database-type sqlite --encryption-type none \
  --retention-period 30d

# two local destinations, encrypted (recipients may be repeated or comma-separated)
vaultwarden-backup \
  --source-type local --local-source /srv/vaultwarden/data \
  --target-type local --local-target /backup,/backup-raid \
  --name vaultwarden-backup --database-type sqlite --encryption-type openpgp \
  --recipient AAAABBBBCCCCDDDD111122223333444455556666 \
  --retention-period 14d

# S3-compatible target (Cloudflare R2), encrypted (plaintext is never uploaded)
vaultwarden-backup \
  --source-type local --local-source /srv/vaultwarden/data \
  --target-type s3 --s3-endpoint https://<account_id>.r2.cloudflarestorage.com \
  --s3-region auto --s3-access-key <R2_ACCESS_KEY> --s3-secret-key <R2_SECRET_KEY> \
  --s3-bucket my-backups --s3-prefix / --s3-addressing path-style \
  --name vaultwarden-backup --database-type sqlite --encryption-type openpgp \
  --recipient AAAABBBBCCCCDDDD111122223333444455556666 \
  --retention-period 14d

# local AND S3 in one run (--target-type local,s3), environment only (cron / systemd)
export VWB_SOURCE_TYPE=local VWB_LOCAL_SOURCE=/srv/vaultwarden/data
export VWB_TARGET_TYPE=local,s3 VWB_LOCAL_TARGET=/backup
export VWB_S3_ENDPOINT=https://s3.eu-central-1.wasabisys.com VWB_S3_REGION=eu-central-1
export VWB_S3_ACCESS_KEY=<KEY> VWB_S3_SECRET_KEY=<SECRET> VWB_S3_BUCKET=backups
export VWB_S3_PREFIX=host-a VWB_S3_ADDRESSING=virtual-hosted
export VWB_NAME=vaultwarden-backup VWB_DATABASE_TYPE=sqlite
export VWB_ENCRYPTION_TYPE=openpgp
export VWB_RECIPIENTS=AAAABBBBCCCCDDDD111122223333444455556666
export VWB_RETENTION_PERIOD=14d
vaultwarden-backup
```

```cron
0 3 * * * VWB_SOURCE_TYPE=local VWB_LOCAL_SOURCE=/srv/vaultwarden/data VWB_TARGET_TYPE=local VWB_LOCAL_TARGET=/backup VWB_NAME=vaultwarden-backup VWB_DATABASE_TYPE=sqlite VWB_ENCRYPTION_TYPE=openpgp VWB_RECIPIENTS=<FINGERPRINT> VWB_RETENTION_PERIOD=14d /usr/local/bin/vaultwarden-backup >> /var/log/vwb-backup.log 2>&1
```

## S3-compatible object storage targets

`--target-type s3` streams the finished archive (`<name>-<timestamp>.tgz`, or
`.tgz.gpg` when encrypted) to an S3-compatible object store — AWS S3 and
stores like Cloudflare R2, Wasabi, Backblaze B2, MinIO or RustFS are all
treated the same; nothing is AWS-specific.

- **Everything is explicit, nothing is defaulted.** All seven flags are
  required with `--target-type s3`, so a run can never quietly reach the
  wrong endpoint, region or bucket: `--s3-endpoint`, `--s3-region`,
  `--s3-access-key`, `--s3-secret-key`, `--s3-bucket`, `--s3-prefix`,
  `--s3-addressing`. The bucket must already exist (the tool does not create
  buckets).
- `--s3-prefix` organizes keys under a prefix: `--s3-prefix weekly` produces
  `weekly/<name>-<timestamp>.tgz` (useful for per-host separation in one
  bucket or per-prefix lifecycle rules). `/` or the empty string means bucket
  root. Paths are normalized: leading/trailing slashes are trimmed, so
  `weekly/` is the same as `weekly`.
- `--s3-addressing` picks the request addressing style explicitly:
  `virtual-hosted` (`https://<bucket>.<endpoint>/<key>`, for AWS and most
  managed S3-compatible stores) or `path-style`
  (`https://<endpoint>/<bucket>/<key>`, for IP/self-hosted and R2 endpoints,
  which cannot resolve `<bucket>.host`).
- **No overwrites, ever:** an S3 object with this run's file name already
  present (a same-second re-run) aborts the run before any backup work, and
  the upload re-checks right before it starts — the same semantics as local
  targets.
- The upload is a streaming multipart upload; the object only appears
  atomically when complete, and memory stays flat even for very large
  archives. With `--encryption-type openpgp` only the encrypted file is
  uploaded; the plaintext archive never leaves the scratch directory.
- At most one S3 target per run; combine with local targets via
  `--target-type local,s3`. Success prints one line per target — the local
  path first, then `s3://<bucket>/<key>`.

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

## Retention

`--retention-period` (or `VWB_RETENTION_PERIOD`) is **always required** and is
how you control how many previous archives to keep. It is not optional: a run
must state its policy explicitly rather than silently default to keeping
everything. The value is exactly one of:

- `unlimited` — keep every archive, no cleanup (the safe "keep everything"
  choice; nothing is ever deleted);
- `<N>d` — a positive integer `N` followed by `d` (days), e.g. `14d`;
- `<N>h` — a positive integer `N` followed by `h` (hours), e.g. `72h`.

Any other value (zero, `0d`, a missing unit, a sign, a decimal, …) is rejected
at parse time, naming the flag.

**How cleanup works** (best-effort, on success only):

- After the archive is **fully delivered** to every target (and only then — a
  failed run deletes nothing), cleanup walks each local target directory and,
  for an S3 target, one level below its `--s3-prefix`.
- It matches only this tool's own archives — a file name exactly
  `<name>-<UTC stamp>.tgz` (or `.tgz.gpg` when encrypted). Anything else,
  including other programs' files and archives under a different `--name`, is
  left untouched.
- An archive is deleted when its stamp is strictly older than the period;
  one exactly at the period boundary is **kept**. This run's own archive
  (the one just delivered) is always kept, even if it is older than the
  period — the stamp is fixed at the start of the run.
- Cleanup is best-effort by design: a cleanup failure is logged to stderr
  (`retention: warning: …` / `retention: removed …`) and never turns a
  successful backup into a failure. The stdout contract (one line per
  target) and the exit code are unchanged.

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
