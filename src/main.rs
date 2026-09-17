use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Parser;
use vaultwarden_backup::{DatabaseType, Delivered, EncryptionType, S3Addressing, S3Target, Target};

/// Back up a vaultwarden data directory to a timestamped .tgz archive,
/// delivered to every local and/or S3-compatible target.
///
/// Declared types (`--source-type`, `--target-type`) are cross-checked with
/// the value flags: a declared type needs at least one corresponding value
/// flag, and a value flag without its declared type is an error.
#[derive(Parser, Debug)]
#[command(
    version,
    about = "Back up a vaultwarden data directory to a .tgz archive"
)]
struct Cli {
    /// Source type (possible value: local)
    #[arg(long, required = true, env = "VWB_SOURCE_TYPE")]
    source_type: SourceType,

    /// Local source: the vaultwarden data directory (the DATA_FOLDER,
    /// containing db.sqlite3). The source is a single directory.
    #[arg(long, env = "VWB_LOCAL_SOURCE")]
    local_source: Option<PathBuf>,

    /// Target type (possible values: local, s3); repeat or comma-separate
    /// when several destination kinds are declared
    #[arg(
        long = "target-type",
        required = true,
        env = "VWB_TARGET_TYPE",
        value_delimiter = ','
    )]
    target_types: Vec<TargetType>,

    /// Local target directory (created if missing); repeat or comma-separate
    /// for multiple local destinations
    #[arg(long = "local-target", env = "VWB_LOCAL_TARGET", value_delimiter = ',')]
    local_targets: Vec<PathBuf>,

    /// S3-compatible endpoint URL (required with `--target-type s3`):
    /// self-hosted (RustFS, MinIO), S3-compatible clouds (Wasabi,
    /// Backblaze B2, Cloudflare R2) or AWS itself
    /// (`https://s3.<region>.amazonaws.com`)
    #[arg(long = "s3-endpoint", env = "VWB_S3_ENDPOINT")]
    s3_endpoint: Option<String>,

    /// S3 region used for signing (required with `--target-type s3`);
    /// passed through verbatim — Cloudflare R2 uses `auto`
    #[arg(long = "s3-region", env = "VWB_S3_REGION")]
    s3_region: Option<String>,

    /// S3 access key (required with `--target-type s3`)
    #[arg(long = "s3-access-key", env = "VWB_S3_ACCESS_KEY")]
    s3_access_key: Option<String>,

    /// S3 secret key (required with `--target-type s3`)
    #[arg(long = "s3-secret-key", env = "VWB_S3_SECRET_KEY")]
    s3_secret_key: Option<String>,

    /// S3 bucket name (required with `--target-type s3`)
    #[arg(long = "s3-bucket", env = "VWB_S3_BUCKET")]
    s3_bucket: Option<String>,

    /// S3 object key prefix (required with `--target-type s3`); `/` or the
    /// empty string means bucket root; `weekly` and `weekly/` are the same
    #[arg(long = "s3-prefix", env = "VWB_S3_PREFIX")]
    s3_prefix: Option<String>,

    /// S3 addressing style (required with `--target-type s3`): `path-style`
    /// for IP/self-hosted/R2 endpoints, `virtual-hosted` for AWS-style
    #[arg(long = "s3-addressing", env = "VWB_S3_ADDRESSING")]
    s3_addressing: Option<S3Addressing>,

    /// Archive name prefix (final file name is <name>-<YYYY-MM-DDTHH:MM:SSZ>.tgz;
    /// at most 200 bytes)
    #[arg(long, required = true, env = "VWB_NAME")]
    name: String,

    /// Database type (possible value: sqlite)
    #[arg(long, required = true, env = "VWB_DATABASE_TYPE")]
    database_type: DatabaseType,

    /// Encryption type (possible value: none, openpgp); `openpgp` requires
    /// at least one `--recipient`, `none` forbids `--recipient`
    #[arg(long, required = true, env = "VWB_ENCRYPTION_TYPE")]
    encryption_type: EncryptionType,

    /// OpenPGP recipient fingerprint (repeat, or comma-separate); required
    /// with `--encryption-type openpgp`, forbidden with `none`; the public
    /// key must be in the local gpg keyring. The VWB_RECIPIENTS environment
    /// variable is split on commas as well.
    #[arg(long = "recipient", env = "VWB_RECIPIENTS", value_delimiter = ',')]
    recipients: Vec<String>,
}

/// Source types.
#[derive(Debug, Clone, Copy, PartialEq, clap::ValueEnum)]
enum SourceType {
    Local,
}

/// Target types.
#[derive(Debug, Clone, Copy, PartialEq, clap::ValueEnum)]
enum TargetType {
    Local,
    S3,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let source_type_local = cli.source_type == SourceType::Local;
    let target_type_local = cli.target_types.contains(&TargetType::Local);
    let target_type_s3 = cli.target_types.contains(&TargetType::S3);
    let s3_flags_given = cli.s3_endpoint.is_some()
        || cli.s3_region.is_some()
        || cli.s3_access_key.is_some()
        || cli.s3_secret_key.is_some()
        || cli.s3_bucket.is_some()
        || cli.s3_prefix.is_some()
        || cli.s3_addressing.is_some();

    // A declared type requires its value flag, and a value flag requires its
    // declared type — checked before any work. S3 parameters are entirely
    // explicit: nothing about the destination may be silently defaulted.
    if source_type_local && cli.local_source.is_none() {
        bail!("--source-type local requires --local-source");
    }
    if !source_type_local && cli.local_source.is_some() {
        bail!("--local-source given but --source-type local is not declared");
    }
    if target_type_local && cli.local_targets.is_empty() {
        bail!("--target-type local requires at least one --local-target");
    }
    if !target_type_local && !cli.local_targets.is_empty() {
        bail!("--local-target given but --target-type local is not declared");
    }
    if target_type_s3 {
        for (flag, present) in [
            ("--s3-endpoint", cli.s3_endpoint.is_some()),
            ("--s3-region", cli.s3_region.is_some()),
            ("--s3-access-key", cli.s3_access_key.is_some()),
            ("--s3-secret-key", cli.s3_secret_key.is_some()),
            ("--s3-bucket", cli.s3_bucket.is_some()),
            ("--s3-prefix", cli.s3_prefix.is_some()),
            ("--s3-addressing", cli.s3_addressing.is_some()),
        ] {
            if !present {
                bail!("--target-type s3 requires {flag}");
            }
        }
    }
    if !target_type_s3 && s3_flags_given {
        bail!("--s3-* flags given but --target-type s3 is not declared");
    }

    let source: PathBuf = cli.local_source.context("local source is required")?;
    let mut targets: Vec<Target> = cli
        .local_targets
        .into_iter()
        .map(|dir| Target::Local { dir })
        .collect();
    if target_type_s3 {
        targets.push(Target::S3(S3Target {
            endpoint: cli.s3_endpoint.context("--s3-endpoint is required")?,
            region: cli.s3_region.context("--s3-region is required")?,
            access_key: cli.s3_access_key.context("--s3-access-key is required")?,
            secret_key: cli.s3_secret_key.context("--s3-secret-key is required")?,
            bucket: cli.s3_bucket.context("--s3-bucket is required")?,
            prefix: cli.s3_prefix.context("--s3-prefix is required")?,
            addressing: cli.s3_addressing.context("--s3-addressing is required")?,
        }));
    }

    let delivered = vaultwarden_backup::run(
        source,
        targets,
        cli.name,
        cli.database_type,
        cli.encryption_type,
        cli.recipients,
    )?;
    for d in &delivered {
        match d {
            Delivered::Local(path) => println!("{}", path.display()),
            Delivered::S3 { bucket, key } => println!("s3://{bucket}/{key}"),
        }
    }
    Ok(())
}
