use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Parser;
use vaultwarden_backup::{DatabaseType, EncryptionType};

/// Back up a vaultwarden data directory to a timestamped .tgz archive,
/// delivered to every local target.
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

    /// Target type (possible value: local); repeat or comma-separate when
    /// several destination kinds are declared
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
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let source_type_local = cli.source_type == SourceType::Local;
    let target_type_local = cli.target_types.contains(&TargetType::Local);

    // A declared type requires its value flag, and a value flag requires its
    // declared type — checked before any work.
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

    let source: PathBuf = cli.local_source.context("local source is required")?;
    let targets: Vec<PathBuf> = cli.local_targets;

    let delivered = vaultwarden_backup::run(
        source,
        targets,
        cli.name,
        cli.database_type,
        cli.encryption_type,
        cli.recipients,
    )?;
    for path in &delivered {
        println!("{}", path.display());
    }
    Ok(())
}
