//! Renewal decisions, independent of the real issuer and keystore so they can be tested
//! without a device, a network or a root manager.

use anyhow::Result;
use duck_core::{BoxFuture, Context};
use serde::{Deserialize, Serialize};

use super::{
    code_of, coded,
    plan::{self, Options, Plan, Protocol, RENEW_BEFORE_SECS, Store},
    run::{self, digest},
};

/// Runs one Device RKP Issuer provisioning and returns its run directory.
pub trait Issuer {
    fn issue<'a>(&'a self, ctx: &'a Context, options: &'a Options) -> BoxFuture<'a, Result<String>>;
}

/// The active keystore module's keybox.
pub trait Keystore {
    /// The installed bytes, or `None` when no keybox is installed.
    fn installed(&self, ctx: &Context) -> Result<Option<Vec<u8>>>;
    fn install(&self, ctx: &Context, xml: &str) -> Result<()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Off,
    Scheduled,
    Retrying,
    /// A different keybox is installed, so renewal stopped.
    Superseded,
}

#[derive(Debug, Serialize)]
pub struct StatusData {
    pub state: State,
    pub renew_before_secs: u64,
    pub plan: Option<Plan>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// No plan.
    Disabled,
    /// An earlier check found a different keybox installed; nothing to do.
    Stopped,
    /// This check found a different keybox installed and stopped renewal.
    Superseded,
    Waiting,
    /// Another check holds the plan.
    Busy,
    Renewed,
}

#[derive(Debug, Serialize)]
pub struct TickData {
    pub action: Action,
    pub status: StatusData,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnableRequest {
    pub run_dir: String,
    #[serde(default)]
    pub protocol: Protocol,
    #[serde(default)]
    pub include_fingerprint: bool,
    #[serde(default)]
    pub fingerprint: Option<String>,
    /// The same acknowledgement a manual issuance requires; renewals run without the user.
    #[serde(default)]
    pub acknowledge_limitations: bool,
}

pub fn status(ctx: &Context, keystore: &dyn Keystore) -> Result<StatusData> {
    let plan = plan::load(ctx)?;
    // Report a replaced keybox now rather than after the next background check.
    let replaced = plan.as_ref().is_some_and(|plan| {
        plan.superseded_at_unix.is_none()
            && keystore
                .installed(ctx)
                .is_ok_and(|installed| !matches(installed.as_deref(), &plan.keybox_sha256))
    });
    Ok(describe(plan, replaced))
}

fn describe(plan: Option<Plan>, replaced: bool) -> StatusData {
    let state = match &plan {
        None => State::Off,
        Some(plan) if replaced || plan.superseded_at_unix.is_some() => State::Superseded,
        Some(plan) if plan.consecutive_failures > 0 => State::Retrying,
        Some(_) => State::Scheduled,
    };
    StatusData {
        state,
        renew_before_secs: RENEW_BEFORE_SECS,
        plan,
    }
}

pub fn enable(
    ctx: &Context,
    keystore: &dyn Keystore,
    request: EnableRequest,
    now: u64,
) -> Result<StatusData> {
    if !request.acknowledge_limitations {
        return Err(coded(
            "acknowledgement_required",
            "automatic renewal requires the Device RKP Issuer limitations to be acknowledged",
        ));
    }
    let run = run::load(ctx, &request.run_dir)?;
    let installed = keystore.installed(ctx)?;
    if installed.as_deref() != Some(run.keybox_xml.as_bytes()) {
        return Err(coded(
            "keybox_not_installed",
            "install this keybox through the Tricky Store manager before enabling renewal",
        ));
    }
    // State is created only once the request is known to be valid.
    let store = Store::create(ctx)?;
    let options = Options {
        protocol: request.protocol,
        include_fingerprint: request.include_fingerprint,
        fingerprint: request
            .fingerprint
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty()),
    };
    let plan = Plan::new_tracking(
        options,
        run.dir,
        digest(run.keybox_xml.as_bytes()),
        run.not_after_unix,
        now,
    );
    store.save(&plan)?;
    Ok(describe(Some(plan), false))
}

pub fn disable(ctx: &Context) -> Result<StatusData> {
    if let Some(store) = Store::existing(ctx)? {
        store.remove_all()?;
    }
    Ok(describe(None, false))
}

/// One background check. `force` runs a due-or-not renewal now (the WebUI's "Renew now"),
/// and reports every reason it could not as an error instead of a quiet outcome.
pub async fn tick(
    ctx: &Context,
    issuer: &dyn Issuer,
    keystore: &dyn Keystore,
    now: u64,
    force: bool,
) -> Result<TickData> {
    let disabled = || {
        if force {
            return Err(coded("renewal_disabled", "automatic renewal is not enabled"));
        }
        Ok(TickData {
            action: Action::Disabled,
            status: describe(None, false),
        })
    };
    // Without a plan, a check reads one path and creates nothing.
    let Some(unlocked) = plan::load(ctx)? else {
        return disabled();
    };
    let store = match Store::existing(ctx) {
        Ok(Some(store)) => store,
        Ok(None) => return disabled(),
        Err(error) if !force && code_of(&error) == "renewal_busy" => {
            return Ok(idle(Action::Busy, unlocked));
        }
        Err(error) => return Err(error),
    };
    let Some(mut plan) = plan::load(ctx)? else {
        return disabled();
    };
    if plan.superseded_at_unix.is_some() {
        if force {
            return Err(superseded_error());
        }
        return Ok(idle(Action::Stopped, plan));
    }
    // A cheap check on every tick, so a replaced keybox stops renewal promptly. A keystore
    // that cannot be read is retried as a failed renewal once one is due.
    if let Ok(installed) = keystore.installed(ctx)
        && !matches(installed.as_deref(), &plan.keybox_sha256)
    {
        return supersede(&store, plan, now, force);
    }
    if !force && now < plan.next_attempt_unix {
        return Ok(idle(Action::Waiting, plan));
    }

    match renew(ctx, issuer, keystore, &plan).await {
        Ok(Renewal::Installed(run)) => {
            let replaced = plan.run_dir_from_renewal.then(|| plan.run_dir.clone());
            let sha = digest(run.keybox_xml.as_bytes());
            plan.renewed(run.dir, sha, run.not_after_unix, now);
            plan.superseded_at_unix = None;
            store.save(&plan)?;
            // The replaced keybox is about to expire; keeping its private key serves nothing.
            if let Some(replaced) = replaced {
                let _ = run::remove(ctx, &replaced);
            }
            Ok(idle(Action::Renewed, plan))
        }
        Ok(Renewal::Superseded) => supersede(&store, plan, now, force),
        Err(error) => {
            plan.failed(code_of(&error), format!("{error:#}"), now);
            store.save(&plan)?;
            Err(error)
        }
    }
}

enum Renewal {
    Installed(run::Run),
    /// The installed keybox changed before the new one could be installed.
    Superseded,
}

async fn renew(
    ctx: &Context,
    issuer: &dyn Issuer,
    keystore: &dyn Keystore,
    plan: &Plan,
) -> Result<Renewal> {
    let still_tracked = |keystore: &dyn Keystore| -> Result<bool> {
        Ok(matches(
            keystore.installed(ctx)?.as_deref(),
            &plan.keybox_sha256,
        ))
    };
    if !still_tracked(keystore)? {
        return Ok(Renewal::Superseded);
    }
    let options = Options {
        protocol: plan.protocol,
        include_fingerprint: plan.include_fingerprint,
        fingerprint: plan.fingerprint.clone(),
    };
    let run_dir = issuer.issue(ctx, &options).await?;
    let run = run::load(ctx, &run_dir)?;
    // Issuance takes seconds to minutes; never replace a keybox installed meanwhile.
    if !still_tracked(keystore)? {
        return Ok(Renewal::Superseded);
    }
    keystore.install(ctx, &run.keybox_xml)?;
    if keystore.installed(ctx)?.as_deref() != Some(run.keybox_xml.as_bytes()) {
        return Err(coded(
            "keybox_install_failed",
            "the keystore does not hold the renewed keybox after installation",
        ));
    }
    Ok(Renewal::Installed(run))
}

fn supersede(store: &Store, mut plan: Plan, now: u64, force: bool) -> Result<TickData> {
    plan.superseded_at_unix = Some(now);
    store.save(&plan)?;
    if force {
        return Err(superseded_error());
    }
    Ok(idle(Action::Superseded, plan))
}

fn superseded_error() -> anyhow::Error {
    coded(
        "keybox_changed",
        "the installed keybox is no longer the one renewal tracks; enable renewal for the new keybox",
    )
}

fn idle(action: Action, plan: Plan) -> TickData {
    TickData {
        action,
        status: describe(Some(plan), false),
    }
}

fn matches(installed: Option<&[u8]>, sha256: &str) -> bool {
    installed.is_some_and(|bytes| digest(bytes) == sha256)
}

/// Background checks that changed nothing are not worth a line in the command log.
pub fn quiet(data: &serde_json::Value) -> bool {
    matches!(
        data["action"].as_str(),
        Some("disabled" | "stopped" | "waiting" | "busy")
    )
}
