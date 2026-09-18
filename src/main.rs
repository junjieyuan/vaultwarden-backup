#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Parser;
use vaultwarden_backup::{
    DatabaseType, Delivered, EncryptionType, RetentionPeriod, S3Addressing, S3Target, Target,
};

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
    /// (`https://s3.<region>.example.com`)
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

    /// Retention period for this archive name: `unlimited`, `<N>d` (days) or
    /// `<N>h` (hours), N a positive integer. After a fully successful run,
    /// archives of this name older than the period are removed from every
    /// local target and the S3 prefix; `unlimited` keeps everything.
    #[arg(
        long = "retention-period",
        required = true,
        env = "VWB_RETENTION_PERIOD",
        value_parser = parse_retention_period
    )]
    retention_period: RetentionPeriod,
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

/// A single `--retention-period` value that is not `unlimited`, `<N>d`, or
/// `<N>h`. Clap hands this to the user as `invalid value '<v>' for
/// '--retention-period': <message>`; `Display` therefore only supplies the
/// message. It is a unit struct so no data is needed to reject a value.
#[derive(Debug)]
struct RetentionParseError;

impl std::fmt::Display for RetentionParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "expected 'unlimited', or a positive integer followed by 'd' (days) or 'h' (hours)"
        )
    }
}

impl std::error::Error for RetentionParseError {}

/// Parse one `--retention-period` value: `unlimited`, `<N>d`, or `<N>h` with
/// `N` a positive integer. `value_parser = parse_retention_period` hands clap
/// this fn pointer; a named fn returning `Result<T, E: Into<Box<dyn Error +
/// Send + Sync>>>` implements `TypedValueParser` directly, so the parse
/// failure surfaces as an `invalid value` error that names the flag.
fn parse_retention_period(value: &str) -> Result<RetentionPeriod, RetentionParseError> {
    if value == "unlimited" {
        return Ok(RetentionPeriod::Unlimited);
    }
    // The value is `<N><unit>`: a positive integer followed by exactly one
    // 'd' or 'h'. The final character is the unit; everything before it is
    // the number, which must be one or more ASCII digits — a leading `+` or
    // `-` (Rust parses `"+1"` as `u64`, but `-1` never fits) or a decimal
    // point is not a positive integer, so require all digits explicitly.
    // `strip_suffix` on a `char` keeps this char-safe, so no input panics.
    let unit = value.chars().last().ok_or(RetentionParseError)?;
    let digits = value.strip_suffix(unit).ok_or(RetentionParseError)?;
    if digits.chars().any(|c| !c.is_ascii_digit()) {
        return Err(RetentionParseError);
    }
    let n: u64 = digits.parse().map_err(|_| RetentionParseError)?;
    if n == 0 {
        return Err(RetentionParseError);
    }
    Ok(match unit {
        'd' => RetentionPeriod::Days(n),
        'h' => RetentionPeriod::Hours(n),
        _ => return Err(RetentionParseError),
    })
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
        cli.retention_period,
    )?;
    for d in &delivered {
        match d {
            Delivered::Local(path) => println!("{}", path.display()),
            Delivered::S3 { bucket, key } => println!("s3://{bucket}/{key}"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_retention_period_accepts_valid_forms() {
        assert_eq!(
            parse_retention_period("unlimited").unwrap(),
            RetentionPeriod::Unlimited
        );
        assert_eq!(
            parse_retention_period("7d").unwrap(),
            RetentionPeriod::Days(7)
        );
        assert_eq!(
            parse_retention_period("1h").unwrap(),
            RetentionPeriod::Hours(1)
        );
        assert_eq!(
            parse_retention_period("3650d").unwrap(),
            RetentionPeriod::Days(3650)
        );
    }

    #[test]
    fn parse_retention_period_rejects_invalid_forms() {
        // Zero is not a positive integer; the unit must be 'd' or 'h'; the
        // number must be unsigned digits. Each of these must be rejected.
        for bad in [
            "0d", "0h", "0", "d", "h", "1x", "+1d", "-1d", "abc", "", "1.5d", "d1", "dh",
        ] {
            assert!(
                parse_retention_period(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }
}
