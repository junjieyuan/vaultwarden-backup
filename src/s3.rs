//! Delivery of the finished artifact to an S3-compatible object store.
//!
//! The HTTP/client work is delegated to `object_store` (Apache Arrow). Its
//! API is async, so a single shared tokio runtime is created lazily and every
//! call is wrapped with `block_on`; the rest of the crate stays synchronous.

use std::fs;
use std::io::Read;
use std::path::Path;
use std::sync::OnceLock;

use anyhow::{Context, Result, bail};
use object_store::aws::{AmazonS3, AmazonS3Builder};
use object_store::path::Path as StorePath;
use object_store::{Error as StoreError, ObjectStore, ObjectStoreExt, WriteMultipart};
use time::OffsetDateTime;

use crate::{RetentionPeriod, S3Addressing, S3Target, archive_stamp, should_delete};

/// Shared tokio runtime, created once per process. `run()` stays synchronous
/// and concurrent callers reuse one runtime. The creation `Result` is stored
/// too, so the first caller that hits a runtime failure fails loudly and
/// everyone else sees the same error instead of a panic.
fn runtime() -> Result<&'static tokio::runtime::Runtime> {
    let state = RUNTIME.get_or_init(|| tokio::runtime::Runtime::new().map_err(|e| e.to_string()));
    state
        .as_ref()
        .map_err(|e| anyhow::anyhow!("create tokio runtime: {e}"))
}

fn block_on<T>(future: impl std::future::Future<Output = T>) -> Result<T> {
    let rt = runtime()?;
    Ok(rt.block_on(future))
}

static RUNTIME: OnceLock<Result<tokio::runtime::Runtime, String>> = OnceLock::new();

/// Build the object_store S3 client for `target`. Every value is explicit:
/// the endpoint is required (never an AWS default), the addressing style is
/// set on both branches because the SDK default is path-style, and `http://`
/// endpoints must opt into plain HTTP explicitly.
pub(crate) fn client(target: &S3Target) -> Result<AmazonS3> {
    let mut builder = AmazonS3Builder::new()
        .with_region(&target.region)
        .with_access_key_id(&target.access_key)
        .with_secret_access_key(&target.secret_key)
        .with_bucket_name(&target.bucket)
        .with_endpoint(&target.endpoint)
        .with_virtual_hosted_style_request(matches!(
            target.addressing,
            S3Addressing::VirtualHosted
        ));
    if target.endpoint.starts_with("http://") {
        builder = builder.with_allow_http(true);
    }
    builder
        .build()
        .with_context(|| format!("build S3 client for endpoint '{}'", target.endpoint))
}

/// Object key under `prefix` for `file_name`. `/` and the empty string both
/// mean "bucket root" (the key is the bare file name, no leading slash);
/// any other value gets its leading and trailing slashes trimmed, so
/// `weekly` and `weekly/` produce the same key.
pub(crate) fn join_prefix(prefix: &str, file_name: &str) -> String {
    let prefix = prefix.trim_matches('/');
    if prefix.is_empty() {
        file_name.to_string()
    } else {
        format!("{prefix}/{file_name}")
    }
}

/// Refuse a run when object `key` already exists — the S3 analogue of
/// `deliver::ensure_targets_free`: with a second-precision timestamp, a
/// same-second re-run would otherwise silently overwrite a previous backup.
/// `NotFound` means "free" and is allowed; any other error (missing bucket,
/// auth, unreachable endpoint) is surfaced here, before any backup work.
pub(crate) fn ensure_object_free(client: &AmazonS3, key: &str) -> Result<()> {
    let location = StorePath::from(key);
    let head = block_on(client.head(&location)).with_context(|| format!("head object {key}"))?;
    match head {
        Ok(meta) => bail!("s3 object {key} already exists ({} bytes)", meta.size),
        Err(StoreError::NotFound { .. }) => Ok(()),
        Err(e) => Err(e).with_context(|| format!("check s3 object {key}")),
    }
}

/// Which of the listed object keys must be deleted for `name` under `period`
/// as of `now`. Pure: the caller lists the prefix and feeds every key, and
/// this returns exactly the keys to delete — only this run's own archives
/// (`<name>-<UTC stamp>.tgz[.gpg]`) whose stamp is older than the period.
/// The stamp is parsed from each key's final path segment, the same way the
/// local cleanup parses a file name, so both backends match identical names.
/// The caller lists one level below the prefix, so only the direct archive
/// keys ever reach here.
pub(crate) fn retention_keys_to_delete(
    now: &OffsetDateTime,
    name: &str,
    own_stamp: &str,
    period: &RetentionPeriod,
    keys: &[String],
) -> Vec<String> {
    let mut to_delete = Vec::new();
    for key in keys {
        let file_name = key.rsplit('/').next().unwrap_or(key);
        let Some(stamp) = archive_stamp(file_name, name) else {
            continue;
        };
        if should_delete(own_stamp, &stamp, now, period) {
            to_delete.push(key.clone());
        }
    }
    to_delete
}

/// Best-effort retention cleanup for the S3 prefix: delete this run's own
/// archives older than `period`, one `delete` per expired key. A failure
/// here must never break a successful backup, so this returns `()` and
/// reports problems on stderr. The listing is non-recursive: objects one
/// level below `prefix`; deeper keys arrive in `common_prefixes` and are
/// ignored (retention only ever writes directly under the prefix).
pub(crate) fn cleanup_retention(
    client: &AmazonS3,
    bucket: &str,
    prefix: &str,
    name: &str,
    own_stamp: &str,
    now: OffsetDateTime,
    period: &RetentionPeriod,
) {
    // `/` and the empty string both mean "bucket root" (no list prefix); any
    // other value is trimmed of leading/trailing slashes, exactly as
    // `join_prefix` does when building the object keys.
    let prefix = prefix.trim_matches('/');
    // The listing prefix and the human-readable form are both derived once:
    // `/` and the empty string mean "bucket root" (no prefix, `s3://<bucket>`),
    // any other value is trimmed and shown with a leading slash.
    let list_prefix: Option<StorePath> = if prefix.is_empty() {
        None
    } else {
        Some(StorePath::from(prefix))
    };
    let list_display = match &list_prefix {
        Some(p) => format!("/{}", p.as_ref()),
        None => String::new(),
    };
    // `list_with_delimiter` returns `Result<ListResult, object_store::Error>`;
    // the runtime wrapper from `block_on` adds one more `anyhow` layer, so
    // both are checked — either failure just skips cleanup for this run.
    let inner = match block_on(async { client.list_with_delimiter(list_prefix.as_ref()).await }) {
        Ok(inner) => inner,
        Err(err) => {
            eprintln!(
                "retention: cannot list s3://{}{} for cleanup ({err}); leaving it unchanged",
                bucket, list_display
            );
            return;
        }
    };
    let list = match inner {
        Ok(list) => list,
        Err(err) => {
            eprintln!(
                "retention: cannot list s3://{}{} for cleanup ({err}); leaving it unchanged",
                bucket, list_display
            );
            return;
        }
    };
    let keys: Vec<String> = list
        .objects
        .iter()
        .map(|o| o.location.as_ref().to_string())
        .collect();
    for key in retention_keys_to_delete(&now, name, own_stamp, period, &keys) {
        let location = StorePath::from(key.clone());
        // `delete` returns `Result<(), object_store::Error>`; the runtime
        // wrapper from `block_on` adds one more `anyhow` layer, so both are
        // checked — either failure just keeps the object.
        let inner = match block_on(client.delete(&location)) {
            Ok(inner) => inner,
            Err(err) => {
                eprintln!(
                    "retention: warning: cannot delete s3://{bucket}/{key} ({err}); keeping it"
                );
                continue;
            }
        };
        match inner {
            Ok(()) => eprintln!("retention: removed s3://{bucket}/{key}"),
            Err(err) => eprintln!(
                "retention: warning: cannot delete s3://{bucket}/{key} ({err}); keeping it"
            ),
        }
    }
}

/// Stream `src` (the finished archive, or its encrypted form when openpgp is
/// on) to object `key` with a multipart upload — parts are published
/// atomically by the store on `complete`, so a reader never sees a partial
/// object. The head check is re-run here as a race guard against a
/// concurrent run, the same belt-and-braces the local delivery uses. The
/// file is read in blocks; parts are uploaded in parallel with bounded
/// in-flight count, so memory stays flat for large archives.
pub(crate) fn upload(client: &AmazonS3, src: &Path, key: &str) -> Result<()> {
    ensure_object_free(client, key)?;

    let location = StorePath::from(key);
    block_on(async move {
        let multipart = client
            .put_multipart(&location)
            .await
            .context("initiate multipart upload")?;
        let mut writer = WriteMultipart::new(multipart);
        let mut file =
            fs::File::open(src).with_context(|| format!("open artifact {}", src.display()))?;
        // The writer splits into fixed 5 MiB parts itself; we cap the number
        // of in-flight parts so a huge archive cannot pile up memory.
        let mut buffer = vec![0u8; 8 * 1024 * 1024];
        let read_result: Result<()> = (async {
            loop {
                let n = file
                    .read(&mut buffer)
                    .with_context(|| format!("read artifact {}", src.display()))?;
                if n == 0 {
                    break;
                }
                writer.write(&buffer[..n]);
                writer
                    .wait_for_capacity(4)
                    .await
                    .context("multipart upload backpressure")?;
            }
            Ok(())
        })
        .await;
        if let Err(err) = read_result {
            // Best-effort cleanup of parts uploaded so far: S3 keeps orphan
            // parts when a multipart upload is dropped without abort, so
            // this is the local-delivery "never leave a partial" analogue.
            let _ = writer.abort().await;
            return Err(err);
        }
        // finish() consumes the writer; if it fails, the parts it owns are
        // the store's lifecycle problem (documented S3 behavior).
        writer.finish().await.context("complete multipart upload")?;
        Ok(())
    })?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_prefix_bucket_root_forms() {
        // Both spellings mean "bucket root": the bare file name, no slash.
        assert_eq!(join_prefix("/", "a.tgz"), "a.tgz");
        assert_eq!(join_prefix("", "a.tgz"), "a.tgz");
        assert_eq!(join_prefix("///", "a.tgz"), "a.tgz");
    }

    #[test]
    fn join_prefix_trims_and_joins() {
        assert_eq!(join_prefix("weekly", "a.tgz"), "weekly/a.tgz");
        assert_eq!(join_prefix("weekly/", "a.tgz"), "weekly/a.tgz");
        assert_eq!(join_prefix("/host-a/", "a.tgz"), "host-a/a.tgz");
        assert_eq!(join_prefix("a/b", "a.tgz"), "a/b/a.tgz");
    }

    #[test]
    fn retention_keys_to_delete_selects_only_expired_own_archives() {
        let now = OffsetDateTime::from_unix_timestamp(1_784_718_299).unwrap();
        let period = RetentionPeriod::Days(7);
        // Expired own archive (2020) is deleted; the fresh own archive and
        // the foreign key (different name) are kept. The deep key is parsed
        // from its final segment, which is a foreign name, so it is kept.
        let keys = vec![
            "ret/vault-2020-01-01T00:00:00Z.tgz".to_string(),
            "ret/vault-2026-07-22T10:00:00Z.tgz".to_string(),
            "ret/other-2020-01-01T00:00:00Z.tgz".to_string(),
            "ret/deep/other-2020-01-01T00:00:00Z.tgz".to_string(),
        ];
        let deleted = retention_keys_to_delete(&now, "vault", "irrelevant", &period, &keys);
        assert_eq!(deleted, vec!["ret/vault-2020-01-01T00:00:00Z.tgz"]);
        // This run's own stamp is never deleted, even an old one: the
        // short-circuit beats the age check.
        let own = vec!["ret/vault-2020-01-01T00:00:00Z.tgz".to_string()];
        assert!(
            retention_keys_to_delete(&now, "vault", "2020-01-01T00:00:00Z", &period, &own)
                .is_empty()
        );
    }
}
