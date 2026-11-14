//! Self-update from GitHub Releases: fetch the latest stable release of
//! this repository, pick the asset for the running binary's compile-time
//! `(arch, libc)` (the release workflow builds exactly four Linux
//! targets), verify the SHA-256 digest GitHub reports for the asset, over
//! TLS (no code signing), and atomically replace the running executable.
//!
//! A newer release whose tag parses as a semver prerelease is refused even
//! if GitHub reports it as latest: only stable releases are installed.
//! Both the compressed download and the decompressed tarball are capped.
//!
//! Exactly one install per cache directory runs at a time: serialized
//! within the process, across processes by an `update.lock` `flock` in the
//! cache directory (kernel-released on holder death, so a killed update
//! cannot wedge the next; a rival using the same cache fails fast).
//!
//! Working files live in an `update/` scratch subdirectory of the cache
//! directory, removed wholesale at install start (a killed earlier run's
//! leftovers) and after a success; the download lands at the tarball's
//! own name, so no scratch name is needed. The executable's directory
//! cannot be removed, so its `<BIN>.<random>.part` scratch files are
//! swept by name.

use std::cmp::Ordering;
use std::fs;
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::io::IntoRawFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use flate2::read::GzDecoder;
use reqwest::blocking::Client;
use semver::Version;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tar::Archive;

/// The repository that publishes the releases.
const REPO: &str = "junjieyuan/vaultwarden-backup";
/// The GitHub REST API base.
const API_BASE: &str = "https://api.github.com";
/// The executable the release tarballs contain (and that this binary is).
const BIN: &str = env!("CARGO_PKG_NAME");
/// Release assets are a few MB; the cap bounds a misbehaving stream so a
/// download can never fill the cache directory past a known size.
const MAX_DOWNLOAD: u64 = 100 * 1024 * 1024;

/// A legitimate decompressed tarball is also a few MB; a stream that
/// expands past this is corrupt or a decompression bomb.
const MAX_UNPACKED: u64 = 256 * 1024 * 1024;

/// Everything the update flow needs; every field is injectable so the
/// whole flow is testable against a local HTTP server and a fake exe.
#[derive(Debug, Clone)]
pub struct Config {
    pub api_base: String,
    pub repo: String,
    /// The running version; `CARGO_PKG_VERSION` for the real binary.
    pub current: String,
    /// The executable to replace; `std::env::current_exe()` for the real one.
    pub exe: PathBuf,
    /// The install scratch parent; `run_with` never reads it when `check`
    /// is true.
    pub cache_dir: PathBuf,
    pub target: String,
}

/// The outcome of an update run; the CLI renders the one-line report from
/// these fields.
#[derive(Debug, Clone)]
pub struct Report {
    /// The latest stable release tag, e.g. `v0.4.2`.
    pub latest: String,
    /// True when `latest` is newer than the running version.
    pub update_available: bool,
    /// True when the executable was actually replaced.
    pub updated: bool,
    /// The executable path resolved before any replacement. It must not be
    /// re-resolved after the rename: the running inode is then unlinked.
    pub exe: PathBuf,
}

/// Run the update with the production configuration: this repository's
/// GitHub releases, the running executable, and the XDG cache directory.
pub fn run(check: bool) -> Result<Report> {
    // A binary outside the release matrix has nothing to install: fail
    // before any work.
    let target = release_target().context(
        "no release artifact exists for this platform; self-update covers the four Linux release targets",
    )?;
    // A check-only run never touches the cache, so it must not fail merely
    // because the path cannot be resolved (no $HOME and no absolute
    // XDG_CACHE_HOME).
    let cache = if check {
        cache_dir().unwrap_or_default()
    } else {
        cache_dir()?
    };
    let cfg = Config {
        api_base: API_BASE.to_string(),
        repo: REPO.to_string(),
        current: env!("CARGO_PKG_VERSION").to_string(),
        exe: std::env::current_exe().context("resolve the running executable")?,
        cache_dir: cache,
        target: target.to_string(),
    };
    run_with(check, &cfg)
}

/// The whole update flow against an explicit `Config`; `check` stops after
/// the version comparison and installs nothing.
pub fn run_with(check: bool, cfg: &Config) -> Result<Report> {
    let client = Client::builder()
        .user_agent(format!("{BIN}/{}", cfg.current))
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(300))
        .build()
        .context("build the HTTP client")?;

    let release = fetch_latest_release(&client, cfg)?;
    let latest_tag = release.tag_name.clone();
    let latest = Version::parse(latest_tag.trim_start_matches('v'))
        .with_context(|| format!("unparsable release tag {latest_tag}"))?;
    let current = Version::parse(&cfg.current)
        .with_context(|| format!("unparsable running version {}", cfg.current))?;

    // Compare precedence, not `Ord`: build metadata must not count as a
    // newer version.
    if latest.cmp_precedence(&current) != Ordering::Greater {
        return Ok(Report {
            latest: latest_tag,
            update_available: false,
            updated: false,
            exe: cfg.exe.clone(),
        });
    }
    // GitHub's latest endpoint skips flagged prereleases; refuse one that
    // slipped through so "latest stable" stays true.
    if !latest.pre.is_empty() {
        bail!(
            "the latest release {latest_tag} is a prerelease; only stable releases are supported"
        );
    }
    if check {
        return Ok(Report {
            latest: latest_tag,
            update_available: true,
            updated: false,
            exe: cfg.exe.clone(),
        });
    }
    if cfg.cache_dir.as_os_str().is_empty() {
        bail!(
            "the update cache directory could not be resolved; set $HOME or an absolute $XDG_CACHE_HOME"
        );
    }

    // Single writer, twice over: serialized in-process, and the
    // kernel-held lock excludes every other process — released when its
    // holder dies, so no stale lock can ever wedge the next install.
    let _serial = install_serial();
    fs::create_dir_all(&cfg.cache_dir)
        .with_context(|| format!("create the cache directory {}", cfg.cache_dir.display()))?;
    #[cfg(unix)]
    let _lock = acquire_install_lock(&cfg.cache_dir)?;

    // Within this cache directory no live writer exists: wipe the scratch
    // directory wholesale (a killed earlier run's leftovers) and sweep the
    // executable's directory by name — it cannot be removed.
    let scratch_dir = cfg.cache_dir.join(SCRATCH_DIR);
    let _ = fs::remove_dir_all(&scratch_dir);
    fs::create_dir_all(&scratch_dir)
        .with_context(|| format!("create the scratch directory {}", scratch_dir.display()))?;
    if let Some(dir) = cfg.exe.parent() {
        sweep_stale_parts(dir);
    }

    let tgz_name = format!("{BIN}-{}.tar.gz", cfg.target);
    let tgz = find_asset(&release.assets, &tgz_name)?;

    // The digest GitHub reports, `sha256:<hex>`: a missing or unsupported
    // digest fails before the multi-megabyte download starts.
    let Some(digest) = tgz.digest.as_deref() else {
        bail!("no digest is reported for release asset {tgz_name}");
    };
    let expected = reported_digest(&tgz_name, digest)?;

    // The asset lands directly at its own name in the scratch directory:
    // with one writer and a wiped directory, no scratch name is needed;
    // a killed run's partial file goes with the directory.
    let cached = scratch_dir.join(&tgz_name);
    download_capped(&client, &tgz.browser_download_url, &cached)?;
    let actual = sha256_file(&cached).with_context(|| format!("hash the downloaded {tgz_name}"))?;
    if !actual.eq_ignore_ascii_case(&expected) {
        // An unverified file never rests in the scratch directory.
        let _ = fs::remove_file(&cached);
        bail!("sha256 mismatch for {tgz_name}: expected {expected}, got {actual}");
    }

    let binary = extract_binary(&cached)?;
    replace_exe(&cfg.exe, &binary)?;
    // The install is the only consumer of the scratch directory, so wipe
    // it wholesale (best effort — the update succeeded either way).
    let _ = fs::remove_dir_all(&scratch_dir);

    Ok(Report {
        latest: latest_tag,
        update_available: true,
        updated: true,
        exe: cfg.exe.clone(),
    })
}

/// The standard cache directory: an absolute `$XDG_CACHE_HOME/vwb`,
/// falling back to `$HOME/.cache/vwb`.
pub fn cache_dir() -> Result<PathBuf> {
    let xdg = std::env::var_os("XDG_CACHE_HOME").map(PathBuf::from);
    let home = std::env::var_os("HOME").map(PathBuf::from);
    cache_dir_from(xdg.as_deref(), home.as_deref())
}

/// XDG resolution with the environment injected, so it is testable without
/// mutating process state.
fn cache_dir_from(xdg: Option<&Path>, home: Option<&Path>) -> Result<PathBuf> {
    // Per the XDG spec, the variable must be absolute; a relative value is
    // invalid and ignored, falling through to the $HOME default. An
    // absolute value needs no $HOME at all.
    if let Some(xdg) = xdg.filter(|x| !x.as_os_str().is_empty())
        && xdg.is_absolute()
    {
        return Ok(xdg.join(BIN));
    }
    let home = home
        .filter(|h| !h.as_os_str().is_empty())
        .with_context(|| "$HOME is required to determine the cache directory")?
        .to_path_buf();
    Ok(home.join(".cache").join(BIN))
}

/// The release asset target of the running binary: its compile-time
/// `(arch, libc)`, or `None` when the pair has no release triple. The four
/// targets are Linux; the pair alone cannot distinguish a non-Linux GNU
/// target.
pub fn release_target() -> Option<&'static str> {
    let arch = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        return None;
    };
    let env = if cfg!(target_env = "musl") {
        "musl"
    } else if cfg!(target_env = "gnu") {
        "gnu"
    } else {
        return None;
    };
    triple_for(arch, env)
}

/// The target-triple table, pure so every cell is testable.
fn triple_for(arch: &str, env: &str) -> Option<&'static str> {
    Some(match (arch, env) {
        ("x86_64", "gnu") => "x86_64-unknown-linux-gnu",
        ("x86_64", "musl") => "x86_64-unknown-linux-musl",
        ("aarch64", "gnu") => "aarch64-unknown-linux-gnu",
        ("aarch64", "musl") => "aarch64-unknown-linux-musl",
        _ => return None,
    })
}

/// Fetch and parse the latest release as GitHub defines it: the newest
/// non-draft, non-prerelease release. `run_with` additionally refuses a tag
/// that parses as a semver prerelease, in case the flag is missing.
fn fetch_latest_release(client: &Client, cfg: &Config) -> Result<Release> {
    let url = format!("{}/repos/{}/releases/latest", cfg.api_base, cfg.repo);
    let resp = client
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .send()
        .with_context(|| format!("fetch {url}"))?;
    let status = resp.status();
    match status.as_u16() {
        200 => Ok(resp
            .json()
            .with_context(|| format!("parse the release JSON from {url}"))?),
        404 => bail!("no releases are published for {}", cfg.repo),
        403 | 429 => bail!("the GitHub API rate limit is exhausted; try again later"),
        other => bail!("the GitHub API answered HTTP {other} for {url}"),
    }
}

/// Find one release asset by exact name; the error lists what the release
/// actually provides, so a renamed asset is diagnosable.
fn find_asset(assets: &[Asset], name: &str) -> Result<Asset> {
    let have = assets
        .iter()
        .map(|a| a.name.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    assets
        .iter()
        .find(|a| a.name == name)
        .cloned()
        .with_context(|| format!("release asset {name} is missing; the release provides: {have}"))
}

/// Stream a download into `dest`, refusing to write more than
/// `MAX_DOWNLOAD` bytes.
fn download_capped(client: &Client, url: &str, dest: &Path) -> Result<()> {
    let mut resp = client
        .get(url)
        .send()
        .with_context(|| format!("download {url}"))?;
    let status = resp.status();
    if !status.is_success() {
        bail!("download {url} answered HTTP {status}");
    }
    let mut f = fs::File::create(dest).with_context(|| format!("create {}", dest.display()))?;
    let mut written = 0u64;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = resp
            .read(&mut buf)
            .with_context(|| format!("read the body of {url}"))?;
        if n == 0 {
            break;
        }
        written += n as u64;
        if written > MAX_DOWNLOAD {
            bail!("download {url} exceeds the 100 MiB cap; aborting");
        }
        f.write_all(&buf[..n])
            .with_context(|| format!("write {}", dest.display()))?;
    }
    f.sync_data()
        .with_context(|| format!("sync {}", dest.display()))?;
    Ok(())
}

/// Hash a file, returning the lowercase hex digest.
fn sha256_file(path: &Path) -> Result<String> {
    let mut f = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    io::copy(&mut f, &mut hasher).with_context(|| format!("hash {}", path.display()))?;
    Ok(format!("{:x}", hasher.finalize()))
}

/// The digest GitHub reports: `<algorithm>:<hex>`. The algorithm is
/// read, not assumed — anything but `sha256` is refused, since we cannot
/// compute it — and the hex must be exactly 64 digits.
fn reported_digest(name: &str, digest: &str) -> Result<String> {
    let (algo, value) = digest
        .split_once(':')
        .with_context(|| format!("read the digest reported for asset {name}"))?;
    if !algo.eq_ignore_ascii_case("sha256") {
        bail!("unsupported digest algorithm {algo:?} for asset {name}; only sha256 is verifiable");
    }
    if value.len() != 64 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("the digest for asset {name} is not 64 hex digits: {digest:?}");
    }
    Ok(value.to_lowercase())
}

/// Unpack the cached tarball: exactly one regular file, named `vwb`, at
/// the archive root; anything else (foreign or repacked) is refused, not
/// silently accepted.
fn extract_binary(tgz: &Path) -> Result<Vec<u8>> {
    extract_binary_with_cap(tgz, MAX_UNPACKED)
}

/// `extract_binary` with the size cap injected for testing. Reading
/// `cap + 1` bytes is enough to reject without letting a bomb expand.
fn extract_binary_with_cap(tgz: &Path, cap: u64) -> Result<Vec<u8>> {
    let bytes = fs::read(tgz).with_context(|| format!("read the cached {}", tgz.display()))?;
    let mut decoded = Vec::new();
    GzDecoder::new(&bytes[..])
        .take(cap.saturating_add(1))
        .read_to_end(&mut decoded)
        .with_context(|| format!("decompress the cached {}", tgz.display()))?;
    if decoded.len() as u64 > cap {
        bail!(
            "the cached {} expands past the {cap}-byte cap; aborting",
            tgz.display()
        );
    }
    let mut found = None;
    for entry in Archive::new(&decoded[..])
        .entries()
        .with_context(|| format!("open the cached {}", tgz.display()))?
    {
        let mut entry = entry.with_context(|| "read an entry of the cached tarball")?;
        let name = entry
            .path()
            .with_context(|| "read the entry name of the cached tarball")?
            .to_string_lossy()
            .to_string();
        if name != BIN {
            bail!(
                "the release tarball contains {name}; expected exactly the bare executable {BIN}"
            );
        }
        if !entry.header().entry_type().is_file() {
            bail!("the release tarball entry {BIN} is not a regular file");
        }
        if found.is_some() {
            bail!("the release tarball contains more than one entry");
        }
        let mut buf = Vec::new();
        entry
            .read_to_end(&mut buf)
            .with_context(|| format!("read {BIN} from the cached tarball"))?;
        found = Some(buf);
    }
    found.context("the release tarball is empty")
}

/// Atomically replace `exe`: write a scratch file in the same directory,
/// rename it over the executable — the rename replaces the directory
/// entry, so it is atomic and stays correct while this process still runs
/// the old inode; the new version takes effect at the next start.
fn replace_exe(exe: &Path, binary: &[u8]) -> Result<()> {
    let dir = exe
        .parent()
        .with_context(|| format!("the executable {} has no parent directory", exe.display()))?;
    // Keep the installed permission bits rather than hardcoding 0755.
    let perms = fs::metadata(exe)
        .with_context(|| format!("read the permissions of {}", exe.display()))?
        .permissions();

    let tmp = tempfile::Builder::new()
        .prefix(SCRATCH_PREFIX)
        .suffix(".part")
        .tempfile_in(dir)
        .with_context(|| format!("create a scratch file next to {}", exe.display()))?;
    let mut f = tmp.as_file();
    f.write_all(binary)
        .with_context(|| format!("write the new executable to {}", tmp.path().display()))?;
    f.sync_data()
        .with_context(|| format!("sync {}", tmp.path().display()))?;
    fs::set_permissions(tmp.path(), perms).with_context(|| {
        format!(
            "apply the installed permissions to {}",
            tmp.path().display()
        )
    })?;
    fs::rename(tmp.path(), exe)
        .with_context(|| format!("replace {} with the new executable", exe.display()))?;
    Ok(())
}

/// The scratch-file prefix, in the executable's directory:
/// `<BIN>.<random>.part`. The random part keeps two installers with
/// different cache directories (e.g. two users on one system binary) from
/// clobbering each other's temp by path.
const SCRATCH_PREFIX: &str = concat!(env!("CARGO_PKG_NAME"), ".");

/// The scratch directory, in the cache directory: every working file of an
/// install lives here; it is removed wholesale at install start and after
/// a success. The `update.lock` marker stays in the cache directory
/// itself, never in a removed path.
const SCRATCH_DIR: &str = "update";

/// Remove every scratch file from `dir` (best effort). Only regular files
/// named `<BIN>.<random>.part` are touched, so this is the cleanup for the
/// executable's directory, which cannot be removed. Runs under the cache
/// lock: no install sharing that cache is live, but a different cache
/// directory is not covered.
fn sweep_stale_parts(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_file() {
            continue;
        }
        let Ok(file_name) = entry.file_name().into_string() else {
            continue;
        };
        let ours = file_name
            .strip_prefix(SCRATCH_PREFIX)
            .and_then(|rest| rest.strip_suffix(".part"))
            .is_some_and(|random| !random.is_empty());
        if ours {
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// The install-lock name, in the cache directory: a `flock` on this file;
/// the kernel releases it on holder death (even `SIGKILL`), so a killed
/// update can never wedge the next.
#[cfg(unix)]
const LOCK_NAME: &str = "update.lock";

/// The install-lock guard: releases the `flock` on drop; the kernel
/// releases it on process death.
#[cfg(unix)]
#[derive(Debug)]
struct InstallLock {
    fd: i32,
}

#[cfg(unix)]
impl Drop for InstallLock {
    fn drop(&mut self) {
        let _ = unsafe { libc::close(self.fd) };
    }
}

/// Serializes installs within this process: at sweep time no sibling
/// thread's scratch can be in flight. Poison recovery is sound: the
/// panicking thread's guard drop already released everything.
static INSTALL_SERIALIZE: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn install_serial() -> std::sync::MutexGuard<'static, ()> {
    std::sync::Mutex::lock(&INSTALL_SERIALIZE).unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Open the cache directory's `update.lock` and take its exclusive
/// `flock`, fail-fast, naming the holder on refusal.
#[cfg(unix)]
fn acquire_install_lock(cache_dir: &Path) -> Result<InstallLock> {
    let path = cache_dir.join(LOCK_NAME);
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .with_context(|| format!("open the install lock file {}", path.display()))?;
    let fd = file.into_raw_fd();
    let rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        let holder = holder_pid(&path);
        let _ = unsafe { libc::close(fd) };
        bail!(
            "another update{holder} is in progress: the install lock {} is held",
            path.display()
        );
    }
    // Record our pid so a rival's error can name us.
    write_holder(fd);
    Ok(InstallLock { fd })
}

/// The holder's pid from the lock file, for the error message; empty when
/// unreadable or not yet written.
#[cfg(unix)]
fn holder_pid(path: &Path) -> String {
    match fs::read_to_string(path) {
        Ok(text) => {
            let pid = text.trim();
            if !pid.is_empty() && pid.chars().all(|c| c.is_ascii_digit()) {
                format!(" (pid {pid})")
            } else {
                String::new()
            }
        }
        Err(_) => String::new(),
    }
}

/// Record this process' pid in the lock file (best effort: the pid is
/// only for the rival's error message).
#[cfg(unix)]
fn write_holder(fd: i32) {
    let pid = format!("{}\n", std::process::id());
    let _ = unsafe { libc::ftruncate(fd, 0) };
    let _ = unsafe { libc::write(fd, pid.as_ptr().cast(), pid.len()) };
}

/// The GitHub API payload this module reads; serde ignores the rest.
#[derive(Deserialize)]
struct Release {
    tag_name: String,
    assets: Vec<Asset>,
}

#[derive(Deserialize, Clone)]
struct Asset {
    name: String,
    browser_download_url: String,
    /// The digest GitHub reports, `<algorithm>:<hex>`; absent on older
    /// API payloads.
    digest: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    const NAME: &str = "vwb-x86_64-unknown-linux-gnu.tar.gz";
    const HEX: &str = "b9325bd53cba67ca17ff851fc8e6143387e46bd58efead724fca1d94618116f8";

    #[test]
    fn reported_digest_accepts_sha256() {
        // The algorithm is matched case-insensitively; the digest comes
        // back lowercased.
        assert_eq!(
            reported_digest(NAME, &format!("sha256:{HEX}")).unwrap(),
            HEX
        );
        assert_eq!(
            reported_digest(NAME, &format!("SHA256:{HEX}")).unwrap(),
            HEX
        );
        assert_eq!(
            reported_digest(NAME, &format!("sha256:{}", HEX.to_uppercase())).unwrap(),
            HEX
        );
    }

    #[test]
    fn reported_digest_rejects_the_rest() {
        let bad: Vec<String> = vec![
            String::new(),
            "sha256".to_string(),
            HEX.to_string(),
            format!("sha256:{}", &HEX[..63]),
            format!("sha256:{HEX}x"),
            format!("sha256:{HEX}:"),
            // A prefix other than sha256 is refused: it names an
            // algorithm this binary cannot verify.
            format!("sha512:{HEX}"),
            format!("md5:{HEX}"),
        ];
        for text in &bad {
            assert!(
                reported_digest(NAME, text).is_err(),
                "{text:?} must be rejected"
            );
        }
    }

    #[test]
    fn cache_dir_from_resolves_per_xdg() {
        // An absolute XDG_CACHE_HOME is used directly and needs no HOME.
        assert_eq!(
            cache_dir_from(Some(Path::new("/var/tmp/cache")), None).unwrap(),
            Path::new("/var/tmp/cache").join(BIN)
        );
        // A relative XDG_CACHE_HOME is invalid per the spec: ignored, so
        // the $HOME fallback (and its HOME requirement) applies.
        assert_eq!(
            cache_dir_from(Some(Path::new("alt")), Some(Path::new("/home/u"))).unwrap(),
            Path::new("/home/u/.cache").join(BIN)
        );
        assert_eq!(
            cache_dir_from(None, Some(Path::new("/home/u"))).unwrap(),
            Path::new("/home/u/.cache").join(BIN)
        );
        // Empty values count as unset.
        assert_eq!(
            cache_dir_from(Some(Path::new("")), Some(Path::new("/home/u"))).unwrap(),
            Path::new("/home/u/.cache").join(BIN)
        );
        assert!(cache_dir_from(None, Some(Path::new(""))).is_err());
        assert!(cache_dir_from(None, None).is_err());
        assert!(cache_dir_from(Some(Path::new("alt")), None).is_err());
        assert!(cache_dir_from(Some(Path::new("")), None).is_err());
    }

    #[test]
    fn extraction_refuses_a_decompressed_stream_over_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        let tgz = dir.path().join("big.tar.gz");
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&vec![0u8; 2 * 1024 * 1024]).unwrap();
        fs::write(&tgz, encoder.finish().unwrap()).unwrap();

        let err = extract_binary_with_cap(&tgz, 1024).unwrap_err().to_string();
        assert!(err.contains("cap"), "{err}");
    }

    #[test]
    fn the_sweep_removes_only_our_scratch_shape() {
        let dir = tempfile::tempdir().unwrap();
        for token in ["a1b2c3d4", "DeAdBeEf"] {
            fs::write(dir.path().join(format!("{BIN}.{token}.part")), b"x").unwrap();
        }
        // Everything else is foreign and must survive: lock marker,
        // cached tarball, near-miss names.
        let foreign = [
            format!("{BIN}.part"),
            format!("{BIN}.a1b2c3d4"),
            format!("{BIN}.a1b2c3d4.part2"),
            "update.lock".to_string(),
            format!("{BIN}-x86_64-unknown-linux-gnu.tar.gz"),
            "something-else.part".to_string(),
        ];
        for name in &foreign {
            fs::write(dir.path().join(name), b"y").unwrap();
        }
        sweep_stale_parts(dir.path());
        for token in ["a1b2c3d4", "DeAdBeEf"] {
            assert!(!dir.path().join(format!("{BIN}.{token}.part")).exists());
        }
        for name in &foreign {
            assert!(dir.path().join(name).exists(), "{name:?}");
        }
    }

    #[test]
    fn triple_for_covers_the_release_matrix() {
        assert_eq!(
            triple_for("x86_64", "gnu"),
            Some("x86_64-unknown-linux-gnu")
        );
        assert_eq!(
            triple_for("x86_64", "musl"),
            Some("x86_64-unknown-linux-musl")
        );
        assert_eq!(
            triple_for("aarch64", "gnu"),
            Some("aarch64-unknown-linux-gnu")
        );
        assert_eq!(
            triple_for("aarch64", "musl"),
            Some("aarch64-unknown-linux-musl")
        );
        assert_eq!(triple_for("x86_64", "unknown"), None);
        assert_eq!(triple_for("riscv64", "gnu"), None);
        assert_eq!(triple_for("", "gnu"), None);
    }

    #[test]
    #[cfg(unix)]
    fn an_install_lock_is_refused_while_held_and_freed_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let lock = acquire_install_lock(dir.path()).unwrap();
        // A second open is refused while the first holds, naming the
        // holder.
        let err = acquire_install_lock(dir.path()).unwrap_err().to_string();
        assert!(err.contains("is in progress"), "{err}");
        assert!(
            err.contains(&format!("pid {}", std::process::id())),
            "{err}"
        );
        drop(lock);
        // Released: the next open takes it.
        let _ = acquire_install_lock(dir.path()).unwrap();
    }
}
