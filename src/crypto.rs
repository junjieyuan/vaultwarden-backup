//! Optional OpenPGP encryption of the finished archive, via the system
//! `gpg`; the plaintext archive is removed once encryption succeeded.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

/// Validate the recipients before any backup work: formats are checked
/// locally; keyring membership needs one `gpg --list-keys`. Only full
/// 40-hex-digit fingerprints are accepted (short keyids are subject to
/// collision attacks), matched case-insensitively against every fingerprint
/// in the keyring — primary keys and subkeys alike, since `gpg --encrypt`
/// accepts both as recipients.
pub fn check_recipients(recipients: &[String]) -> Result<()> {
    for r in recipients {
        validate_recipient(r)?;
    }
    if recipients.is_empty() {
        return Ok(());
    }
    let known: HashSet<String> = list_public_keys()?;
    for r in recipients {
        if !known.contains(&r.to_lowercase()) {
            bail!(
                "no public key {r} in the local gpg keyring; verify the \
                 fingerprint with `gpg --list-keys --fingerprint` and \
                 import the key first (gpg --import)"
            );
        }
    }
    Ok(())
}

/// Encrypt `plain` to `<plain>.gpg` (written as `<plain>.gpg.part` first,
/// then renamed); the plaintext is removed afterwards.
pub fn encrypt(plain: &Path, recipients: &[String]) -> Result<PathBuf> {
    let dir = plain
        .parent()
        .with_context(|| "archive has no parent directory")?;
    let name = plain
        .file_name()
        .with_context(|| "archive has no file name")?
        .to_string_lossy()
        .to_string();
    let final_path = dir.join(format!("{name}.gpg"));
    let part = dir.join(format!("{name}.gpg.part"));

    let mut cmd = Command::new("gpg");
    // The input is already a gzip-compressed `.tgz`: gpg's default zlib
    // compression would only burn CPU re-compressing incompressible data,
    // so disable it (`--compress-algo none` is transparent on decrypt).
    cmd.args([
        "--batch",
        "--no-tty",
        "--quiet",
        "--compress-algo",
        "none",
        "--encrypt",
    ]);
    for r in recipients {
        cmd.arg("--recipient").arg(r);
    }
    cmd.arg("--output").arg(&part).arg(plain);

    let status = cmd.status().with_context(|| "run `gpg --encrypt`")?;
    if !status.success() {
        let _ = fs::remove_file(&part);
        // Never leave a plaintext next to a failed encryption: the caller
        // keeps no copy, so the archive is gone either way.
        let _ = fs::remove_file(plain);
        bail!("gpg --encrypt exited with {status}");
    }

    fs::rename(&part, &final_path)
        .with_context(|| format!("rename {} -> {}", part.display(), final_path.display()))?;
    // Plaintext never lingers next to the ciphertext.
    fs::remove_file(plain).with_context(|| format!("remove plaintext {}", plain.display()))?;

    Ok(final_path)
}

/// Accept only the 40-hex-digit fingerprint (primary keys and subkeys
/// alike — the check is format-only; which key `gpg --encrypt` uses is its
/// own concern).
fn validate_recipient(spec: &str) -> Result<()> {
    let hex_ok = spec.bytes().all(|b| b.is_ascii_hexdigit());
    if spec.len() != 40 || !hex_ok {
        bail!(
            "recipient '{spec}' must be a full 40-hex-digit fingerprint \
             (short keyids are rejected for collision safety); get one with \
             `gpg --list-keys --fingerprint`"
        );
    }
    Ok(())
}

/// Primary-key fingerprints (lowercased) of every public key in the local
/// keyring.
fn list_public_keys() -> Result<HashSet<String>> {
    let out = Command::new("gpg")
        .arg("--list-keys")
        .arg("--with-colons")
        .output()
        .with_context(|| "run `gpg` (is GnuPG installed and in PATH?)")?;
    if !out.status.success() {
        bail!(
            "gpg --list-keys failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.starts_with("fpr:"))
        // fpr: line, 0-based field 9: the 40-hex-digit fingerprint.
        .map(|l| l.split(':').nth(9).unwrap_or_default().to_lowercase())
        .filter(|f| !f.is_empty())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recipient_format_is_checked() {
        let fpr = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678";
        assert!(validate_recipient(fpr).is_ok());
        // Short keyids are rejected outright: only full 40-hex fingerprints.
        assert!(
            validate_recipient(&fpr[..16]).is_err(),
            "16-hex keyid rejected"
        );
        assert!(
            validate_recipient(&fpr[..8]).is_err(),
            "8-hex keyid rejected"
        );
        assert!(validate_recipient("0123456789").is_err());
        // 40 chars but not hex.
        assert!(validate_recipient(&"g".repeat(40)).is_err());
        assert!(validate_recipient("").is_err());
    }
}
