//! Reads one finished Device RKP Issuer run.
//!
//! The run directory holds `keybox.xml` and the issued chain as `cert_chain.der`. A keybox
//! stops working as soon as any certificate in its chain lapses, so its expiry is the
//! earliest `notAfter` of the whole chain, not only the leaf's.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, anyhow};
use duck_core::Context;
use sha2::{Digest, Sha256};
use x509_cert::{
    Certificate,
    der::{Decode, Reader, SliceReader},
};

use super::coded;

/// The prefix `duck-rkp-device` gives every run directory under `var/outputs`.
const RUN_PREFIX: &str = "rkp-device-";

#[derive(Debug, Clone)]
pub struct Run {
    /// Canonical path of the run directory.
    pub dir: String,
    /// The keybox in the form the keystore manager writes, so digests can be compared.
    pub keybox_xml: String,
    pub not_after_unix: u64,
}

/// The canonical path of an issuer run directly under `var/outputs`, or `invalid_run`.
fn issuer_run_dir(ctx: &Context, run_dir: &str) -> Result<PathBuf> {
    let invalid = |message: String| coded("invalid_run", message);
    let requested = ctx.paths.resolve_in_root(run_dir.trim());
    let dir = fs::canonicalize(&requested)
        .map_err(|error| invalid(format!("{}: {error}", requested.display())))?;
    let outputs = fs::canonicalize(&ctx.paths.outputs_dir).map_err(|error| {
        invalid(format!("{}: {error}", ctx.paths.outputs_dir.display()))
    })?;
    let is_issuer_run = dir.parent() == Some(outputs.as_path())
        && dir
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(RUN_PREFIX));
    if !is_issuer_run || !dir.is_dir() {
        return Err(invalid(format!(
            "{} is not a Device RKP Issuer run directory",
            dir.display()
        )));
    }
    Ok(dir)
}

pub fn load(ctx: &Context, run_dir: &str) -> Result<Run> {
    let invalid = |message: String| coded("invalid_run", message);
    let dir = issuer_run_dir(ctx, run_dir)?;

    let keybox = read(&dir.join("keybox.xml"))?;
    let keybox = String::from_utf8(keybox)
        .map_err(|_| invalid("keybox.xml is not UTF-8 text".into()))?;
    let keybox_xml = duck_tricky_store::keybox::validate::clean(&keybox)
        .map_err(|error| invalid(format!("keybox.xml: {error:#}")))?;
    let chain = read(&dir.join("cert_chain.der"))?;
    let not_after_unix = earliest_not_after(&chain)
        .map_err(|error| invalid(format!("cert_chain.der: {error:#}")))?;

    Ok(Run {
        dir: dir.display().to_string(),
        keybox_xml,
        not_after_unix,
    })
}

/// Deletes a run directory that a renewal replaced, so expired private keys do not pile
/// up. Only issuer run directories qualify; a failure leaves the directory in place.
pub fn remove(ctx: &Context, run_dir: &str) -> Result<()> {
    let dir = issuer_run_dir(ctx, run_dir)?;
    fs::remove_dir_all(&dir).with_context(|| format!("remove {}", dir.display()))
}

fn read(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|error| coded("invalid_run", format!("{}: {error}", path.display())))
}

/// Earliest `notAfter` (Unix seconds) of a concatenated DER certificate chain.
pub fn earliest_not_after(der: &[u8]) -> Result<u64> {
    let mut reader = SliceReader::new(der).map_err(|error| anyhow!("{error}"))?;
    let mut earliest: Option<u64> = None;
    while !reader.is_finished() {
        let certificate =
            Certificate::decode(&mut reader).map_err(|error| anyhow!("parse certificate: {error}"))?;
        let not_after = certificate
            .tbs_certificate()
            .validity()
            .not_after
            .to_unix_duration()
            .as_secs();
        earliest = Some(earliest.map_or(not_after, |current| current.min(not_after)));
    }
    earliest.ok_or_else(|| anyhow!("certificate chain is empty"))
}

pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
