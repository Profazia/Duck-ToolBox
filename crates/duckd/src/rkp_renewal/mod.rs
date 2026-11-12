//! Application composition: automatic renewal of a Device RKP Issuer keybox.
//!
//! RKP certificates expire after a few weeks. A plan tracks the keybox the user installed;
//! a background check re-runs the same issuance a day before the earliest certificate in
//! the chain expires and installs the result through the keystore manager. The issuer and
//! the keystore manager stay independent features: renewal replays `rkp-device provision`
//! through its own CLI contract and installs through `duck-tricky-store`'s keybox API.

mod plan;
mod run;
mod service;
#[cfg(test)]
mod tests;

use std::io::Read as _;

use anyhow::{Context as _, Result, bail};
use clap::{Args, Subcommand};
use duck_core::{
    BoxFuture, ClapFeature, CommandResult, Context, Feature, FeatureInfo, IntoCommandResult,
    unix_now,
};

pub use service::quiet;

pub static FEATURE: ClapFeature<Command> = ClapFeature::new(
    FeatureInfo {
        id: "rkp-renewal",
        summary: "Automatic renewal of a Device RKP Issuer keybox before it expires",
        contract: 1,
    },
    dispatch,
);

/// The `rkp-device` contract whose `provision` output this feature reads.
const ISSUER_CONTRACT: u32 = 7;

#[derive(Debug, Subcommand)]
pub enum Command {
    /// The saved plan and when the tracked keybox renews.
    Status,
    /// Track an installed Device RKP Issuer keybox (JSON on stdin).
    Enable(StdinArgs),
    /// Stop renewing and forget the plan. Issued keyboxes are kept.
    Disable,
    /// Renew the tracked keybox if it is due (run periodically after boot).
    Tick {
        /// Renew now even if the keybox is not due, and report why it could not as an error.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Debug, Args)]
pub struct StdinArgs {
    #[arg(long = "stdin-json")]
    stdin_json: bool,
}

fn dispatch<'a>(command: Command, ctx: &'a Context) -> BoxFuture<'a, CommandResult> {
    Box::pin(async move {
        match command {
            Command::Status => {
                service::status(ctx, &TrickyKeystore).into_command("rkp-renewal.status", code_of)
            }
            Command::Enable(args) => read_request(&args)
                .and_then(|request| service::enable(ctx, &TrickyKeystore, request, unix_now()))
                .inspect(|_| start_background_check(ctx))
                .into_command("rkp-renewal.enable", code_of),
            Command::Disable => service::disable(ctx).into_command("rkp-renewal.disable", code_of),
            Command::Tick { force } => {
                service::tick(ctx, &DeviceIssuer, &TrickyKeystore, unix_now(), force)
                    .await
                    .into_command("rkp-renewal.tick", code_of)
            }
        }
    })
}

/// Starts `rkp-renewal.sh` now rather than at the next boot. It runs detached so the
/// WebUI's command returns at once, and exits by itself if one is already running.
fn start_background_check(ctx: &Context) {
    let script = ctx.paths.root.join("rkp-renewal.sh");
    if !script.is_file() {
        return;
    }
    let mut command = std::process::Command::new("sh");
    command
        .arg(&script)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    // A check that fails to start is retried by the next boot; enabling still succeeded.
    let _ = command.spawn();
}

fn read_request(args: &StdinArgs) -> Result<service::EnableRequest> {
    if !args.stdin_json {
        bail!("this command requires `--stdin-json`");
    }
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)
        .context("read JSON from stdin")?;
    if bytes.len() > 64 * 1024 {
        bail!("input exceeds 64 KiB");
    }
    serde_json::from_slice(&bytes).context("parse JSON from stdin")
}

/// An error with a stable code for the JSON envelope.
#[derive(Debug)]
struct Coded {
    code: &'static str,
    message: String,
}

impl std::fmt::Display for Coded {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for Coded {}

fn coded(code: &'static str, message: impl Into<String>) -> anyhow::Error {
    Coded {
        code,
        message: message.into(),
    }
    .into()
}

fn code_of(error: &anyhow::Error) -> &'static str {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<Coded>())
        .map_or("internal_error", |coded| coded.code)
}

/// `rkp-device provision` with the plan's options, exactly as the WebUI sends it.
fn provision_args(options: &plan::Options) -> Vec<String> {
    let mut args = vec![
        "rkp-device".to_owned(),
        "provision".to_owned(),
        "--acknowledge-limitations".to_owned(),
        "--protocol".to_owned(),
        options.protocol.as_arg().to_owned(),
        "--include-fingerprint".to_owned(),
        options.include_fingerprint.to_string(),
    ];
    if let Some(fingerprint) = &options.fingerprint {
        args.extend(["--fingerprint".to_owned(), fingerprint.clone()]);
    }
    args
}

struct DeviceIssuer;

impl service::Issuer for DeviceIssuer {
    fn issue<'a>(
        &'a self,
        ctx: &'a Context,
        options: &'a plan::Options,
    ) -> BoxFuture<'a, Result<String>> {
        Box::pin(async move {
            let feature = &duck_rkp_device::FEATURE;
            if feature.info().contract != ISSUER_CONTRACT {
                return Err(coded(
                    "contract_mismatch",
                    format!(
                        "rkp-device contract {} is not the expected {ISSUER_CONTRACT}",
                        feature.info().contract
                    ),
                ));
            }
            let matches = feature
                .command()
                .try_get_matches_from(provision_args(options))
                .map_err(|error| coded("contract_mismatch", error.render().to_string()))?;
            match feature.run(&matches, ctx).await {
                Ok(output) => output.data["artifacts"]["run_dir"]
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| coded("contract_mismatch", "issuer omitted its run directory")),
                Err(failure) => Err(coded(failure.code, failure.message)),
            }
        })
    }
}

struct TrickyKeystore;

impl service::Keystore for TrickyKeystore {
    fn installed(&self, ctx: &Context) -> Result<Option<Vec<u8>>> {
        duck_tricky_store::keybox::active(ctx)
            .map(|keybox| keybox.content)
            .map_err(|error| coded("keystore_unavailable", format!("{error:#}")))
    }

    fn install(&self, ctx: &Context, xml: &str) -> Result<()> {
        duck_tricky_store::keybox::install(ctx, xml, "rkp-renewal")
            .map(|_| ())
            .map_err(|error| coded("keybox_install_failed", format!("{error:#}")))
    }
}
