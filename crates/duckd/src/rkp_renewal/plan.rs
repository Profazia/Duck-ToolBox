//! The saved renewal plan and its schedule.
//!
//! One plan tracks one Device RKP Issuer keybox. It lives in
//! `var/rkp-renewal/plan.json`, and every command that changes it holds
//! `var/rkp-renewal/lock` so a background check and a WebUI action never interleave.

use std::{fs, path::PathBuf};

use anyhow::{Context as _, Result, bail};
use duck_core::Context;
use serde::{Deserialize, Serialize};

use super::coded;

/// Renewal starts this long before the earliest certificate in the keybox expires.
pub const RENEW_BEFORE_SECS: u64 = 24 * 60 * 60;
/// The first retry after a failed renewal; each further failure doubles it.
pub const RETRY_BASE_SECS: u64 = 60 * 60;
/// Retries never wait longer than this.
pub const RETRY_MAX_SECS: u64 = 24 * 60 * 60;
/// A renewal never schedules the next one sooner than this, so a short-lived chain or a
/// wrong system clock cannot turn into back-to-back requests to the RKP server.
pub const MIN_REISSUE_SECS: u64 = 6 * 60 * 60;

const PLAN_API: u32 = 1;

/// The issuer's `--protocol` values.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    #[default]
    Auto,
    V1,
    V2,
    #[serde(rename = "v1-native")]
    V1Native,
}

impl Protocol {
    pub fn as_arg(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::V1 => "v1",
            Self::V2 => "v2",
            Self::V1Native => "v1-native",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    pub api: u32,
    /// The issuance options a renewal repeats.
    pub protocol: Protocol,
    pub include_fingerprint: bool,
    /// An explicit fingerprint override. `None` uses the device's own at renewal time.
    pub fingerprint: Option<String>,
    /// The run directory of the tracked keybox.
    pub run_dir: String,
    /// Whether a renewal created `run_dir`. Only those are deleted once replaced; the run
    /// the user issued and enabled stays theirs.
    #[serde(default)]
    pub run_dir_from_renewal: bool,
    /// SHA-256 of the installed keybox. Renewal stops once the keystore holds anything else.
    pub keybox_sha256: String,
    /// Earliest `notAfter` across the tracked keybox's chain (Unix seconds).
    pub not_after_unix: u64,
    pub renew_at_unix: u64,
    /// When the next background check may run the issuance.
    pub next_attempt_unix: u64,
    pub enabled_at_unix: u64,
    pub last_renewed_at_unix: Option<u64>,
    pub last_attempt: Option<Attempt>,
    pub consecutive_failures: u32,
    /// Set once the installed keybox stopped matching; the plan is kept for the WebUI.
    pub superseded_at_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attempt {
    pub at_unix: u64,
    pub ok: bool,
    pub code: Option<String>,
    pub message: Option<String>,
}

impl Plan {
    pub fn new_tracking(
        options: Options,
        run_dir: String,
        keybox_sha256: String,
        not_after_unix: u64,
        now: u64,
    ) -> Self {
        let renew_at_unix = renew_at(not_after_unix);
        Self {
            api: PLAN_API,
            protocol: options.protocol,
            include_fingerprint: options.include_fingerprint,
            fingerprint: options.fingerprint,
            run_dir,
            run_dir_from_renewal: false,
            keybox_sha256,
            not_after_unix,
            renew_at_unix,
            next_attempt_unix: renew_at_unix,
            enabled_at_unix: now,
            last_renewed_at_unix: None,
            last_attempt: None,
            consecutive_failures: 0,
            superseded_at_unix: None,
        }
    }

    /// Tracks a freshly installed renewal and schedules the next one.
    pub fn renewed(&mut self, run_dir: String, keybox_sha256: String, not_after: u64, now: u64) {
        self.run_dir = run_dir;
        self.run_dir_from_renewal = true;
        self.keybox_sha256 = keybox_sha256;
        self.not_after_unix = not_after;
        self.renew_at_unix = renew_at(not_after);
        self.next_attempt_unix = self
            .renew_at_unix
            .max(now.saturating_add(MIN_REISSUE_SECS));
        self.last_renewed_at_unix = Some(now);
        self.last_attempt = Some(Attempt {
            at_unix: now,
            ok: true,
            code: None,
            message: None,
        });
        self.consecutive_failures = 0;
    }

    pub fn failed(&mut self, code: &str, message: String, now: u64) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.next_attempt_unix = now.saturating_add(retry_delay(self.consecutive_failures));
        self.last_attempt = Some(Attempt {
            at_unix: now,
            ok: false,
            code: Some(code.to_owned()),
            message: Some(message),
        });
    }
}

/// The issuance options a plan records.
#[derive(Debug, Clone, Default)]
pub struct Options {
    pub protocol: Protocol,
    pub include_fingerprint: bool,
    pub fingerprint: Option<String>,
}

pub fn renew_at(not_after: u64) -> u64 {
    not_after.saturating_sub(RENEW_BEFORE_SECS)
}

/// 1 h, 2 h, 4 h, 8 h, 16 h, then 24 h.
pub fn retry_delay(failures: u32) -> u64 {
    let doublings = failures.saturating_sub(1).min(5);
    (RETRY_BASE_SECS << doublings).min(RETRY_MAX_SECS)
}

fn dir(ctx: &Context) -> PathBuf {
    ctx.paths.var_dir.join("rkp-renewal")
}

fn plan_path(ctx: &Context) -> PathBuf {
    dir(ctx).join("plan.json")
}

/// Reads the plan without the lock. Writes are atomic, so a reader sees a whole plan.
pub fn load(ctx: &Context) -> Result<Option<Plan>> {
    let path = plan_path(ctx);
    let Some(raw) = duck_core::fs::read_optional(&path)? else {
        return Ok(None);
    };
    let plan: Plan =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
    if plan.api != PLAN_API {
        bail!("unsupported renewal plan: {}", path.display());
    }
    Ok(Some(plan))
}

/// Exclusive access to the plan for the lifetime of the value.
pub struct Store {
    dir: PathBuf,
    path: PathBuf,
    _lock: fs::File,
}

impl Store {
    /// Creates the state directory. Only enabling renewal does this.
    pub fn create(ctx: &Context) -> Result<Self> {
        let dir = dir(ctx);
        fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        }
        Self::lock(ctx, dir)?.context("renewal state directory disappeared")
    }

    /// Locks existing state, or returns `None` without creating anything when renewal
    /// was never turned on or has been turned off.
    pub fn existing(ctx: &Context) -> Result<Option<Self>> {
        Self::lock(ctx, dir(ctx))
    }

    fn lock(ctx: &Context, dir: PathBuf) -> Result<Option<Self>> {
        let lock = match fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(dir.is_dir())
            .truncate(false)
            .open(dir.join("lock"))
        {
            Ok(lock) => lock,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(anyhow::Error::new(error).context("open the renewal lock")),
        };
        match lock.try_lock() {
            Ok(()) => {}
            Err(fs::TryLockError::WouldBlock) => {
                return Err(coded("renewal_busy", "another renewal check is running"));
            }
            Err(fs::TryLockError::Error(error)) => {
                return Err(anyhow::Error::new(error).context("lock the renewal plan"));
            }
        }
        Ok(Some(Self {
            path: plan_path(ctx),
            dir,
            _lock: lock,
        }))
    }

    pub fn save(&self, plan: &Plan) -> Result<()> {
        duck_core::fs::write_string_atomic(&self.path, &serde_json::to_string_pretty(plan)?)?;
        fs::File::open(self.path.parent().context("no plan directory")?)?.sync_all()?;
        Ok(())
    }

    /// Removes the plan and every other file this feature keeps, lock included. The
    /// background check notices the missing plan and exits on its own.
    pub fn remove_all(self) -> Result<()> {
        fs::remove_dir_all(&self.dir)
            .with_context(|| format!("remove {}", self.dir.display()))
    }
}
