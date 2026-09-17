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
use object_store::{Error as StoreError, ObjectStoreExt, WriteMultipart};

use crate::{S3Addressing, S3Target};

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
}
