use std::{
    cell::{Cell, RefCell},
    fs,
};

use anyhow::Result;
use duck_core::{AppPaths, BoxFuture, Context, Sysroot};
use rcgen::{CertificateParams, CertifiedIssuer, KeyPair, PKCS_ECDSA_P256_SHA256, date_time_ymd};

use super::{
    code_of, coded,
    plan::{self, MIN_REISSUE_SECS, Options, Protocol, RENEW_BEFORE_SECS, retry_delay},
    provision_args,
    run::{digest, earliest_not_after},
    service::{self, Action, EnableRequest, Issuer, Keystore, State},
};

/// 2030-01-01T00:00:00Z.
const NOW: u64 = 1_893_456_000;

struct Fixture {
    _temp: tempfile::TempDir,
    ctx: Context,
}

fn fixture() -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let paths = AppPaths::for_root(temp.path(), temp.path());
    fs::create_dir_all(&paths.outputs_dir).unwrap();
    Fixture {
        ctx: Context {
            paths,
            sysroot: Sysroot::default(),
        },
        _temp: temp,
    }
}

/// `(year, month, day)` to Unix seconds at midnight UTC.
fn unix(year: i32, month: u8, day: u8) -> u64 {
    date_time_ymd(year, month, day).unix_timestamp() as u64
}

/// A two-certificate chain in DER: a leaf expiring on `leaf`, signed by a root expiring
/// on `root`.
fn chain(leaf: (i32, u8, u8), root: (i32, u8, u8)) -> Vec<u8> {
    let params = |not_after: (i32, u8, u8)| {
        let mut params = CertificateParams::default();
        params.not_before = date_time_ymd(2029, 1, 1);
        params.not_after = date_time_ymd(not_after.0, not_after.1, not_after.2);
        params
    };
    let mut root_params = params(root);
    root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let issuer = CertifiedIssuer::self_signed(
        root_params,
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap(),
    )
    .unwrap();
    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let leaf = params(leaf).signed_by(&leaf_key, &issuer).unwrap();
    [leaf.der().as_ref(), issuer.der().as_ref()].concat()
}

/// Writes an issuer run directory the way `duck-rkp-device` lays it out.
fn write_run(ctx: &Context, name: &str, leaf: (i32, u8, u8)) -> String {
    let dir = ctx.paths.outputs_dir.join(format!("rkp-device-{name}"));
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("keybox.xml"),
        format!(
            "<?xml version=\"1.0\"?>\n<!-- issued -->\n<AndroidAttestation><Keybox DeviceID=\"{name}\"/></AndroidAttestation>"
        ),
    )
    .unwrap();
    fs::write(dir.join("cert_chain.der"), chain(leaf, (2040, 1, 1))).unwrap();
    dir.display().to_string()
}

/// Mirrors the Tricky Store manager: it writes the cleaned form of whatever it installs.
#[derive(Default)]
struct FakeKeystore {
    content: RefCell<Option<Vec<u8>>>,
    unavailable: Cell<bool>,
}

impl FakeKeystore {
    fn install_run(&self, ctx: &Context, run_dir: &str) {
        let xml = fs::read_to_string(format!("{run_dir}/keybox.xml")).unwrap();
        self.install(ctx, &xml).unwrap();
    }

    fn replace(&self, bytes: &[u8]) {
        *self.content.borrow_mut() = Some(bytes.to_vec());
    }
}

impl Keystore for FakeKeystore {
    fn installed(&self, _ctx: &Context) -> Result<Option<Vec<u8>>> {
        if self.unavailable.get() {
            return Err(coded("keystore_unavailable", "no keystore module"));
        }
        Ok(self.content.borrow().clone())
    }

    fn install(&self, _ctx: &Context, xml: &str) -> Result<()> {
        let cleaned = duck_tricky_store::keybox::validate::clean(xml)?;
        *self.content.borrow_mut() = Some(cleaned.into_bytes());
        Ok(())
    }
}

/// Issues a new run whose leaf expires on `leaf`, or fails with `failure`.
struct FakeIssuer<'k> {
    leaf: (i32, u8, u8),
    failure: Option<&'static str>,
    runs: Cell<u32>,
    /// Installs this keybox while "issuing", as a user acting meanwhile would.
    replace_during_issue: Option<(&'k FakeKeystore, &'static [u8])>,
    options: RefCell<Vec<Options>>,
}

impl FakeIssuer<'_> {
    fn new(leaf: (i32, u8, u8)) -> Self {
        Self {
            leaf,
            failure: None,
            runs: Cell::new(0),
            replace_during_issue: None,
            options: RefCell::new(Vec::new()),
        }
    }
}

impl Issuer for FakeIssuer<'_> {
    fn issue<'a>(&'a self, ctx: &'a Context, options: &'a Options) -> BoxFuture<'a, Result<String>> {
        Box::pin(async move {
            self.runs.set(self.runs.get() + 1);
            self.options.borrow_mut().push(options.clone());
            if let Some(code) = self.failure {
                return Err(coded(code, "the RKP server rejected the request"));
            }
            if let Some((keystore, bytes)) = self.replace_during_issue {
                keystore.replace(bytes);
            }
            Ok(write_run(ctx, &format!("renewed-{}", self.runs.get()), self.leaf))
        })
    }
}

fn request(run_dir: &str) -> EnableRequest {
    EnableRequest {
        run_dir: run_dir.to_owned(),
        protocol: Protocol::V2,
        include_fingerprint: true,
        fingerprint: Some("  google/husky/husky:15/AP3A/1:user/release-keys ".into()),
        acknowledge_limitations: true,
    }
}

/// Enables a plan for a run whose leaf expires on 2030-01-20.
fn enabled(fixture: &Fixture, keystore: &FakeKeystore) -> plan::Plan {
    let run = write_run(&fixture.ctx, "1", (2030, 1, 20));
    keystore.install_run(&fixture.ctx, &run);
    service::enable(&fixture.ctx, keystore, request(&run), NOW)
        .unwrap()
        .plan
        .unwrap()
}

#[test]
fn expiry_is_the_earliest_certificate_in_the_chain() {
    let leaf_first = chain((2030, 2, 1), (2040, 1, 1));
    assert_eq!(earliest_not_after(&leaf_first).unwrap(), unix(2030, 2, 1));
    // A root that lapses first makes the whole keybox unusable.
    let root_first = chain((2031, 1, 1), (2030, 3, 1));
    assert_eq!(earliest_not_after(&root_first).unwrap(), unix(2030, 3, 1));
    assert!(earliest_not_after(&[]).is_err());
    assert!(earliest_not_after(&leaf_first[..40]).is_err());
}

#[test]
fn retries_back_off_from_one_hour_to_a_day() {
    let hours: Vec<u64> = (1..=8).map(|n| retry_delay(n) / 3600).collect();
    assert_eq!(hours, [1, 2, 4, 8, 16, 24, 24, 24]);
}

#[test]
fn enabling_records_the_options_and_renews_a_day_before_expiry() {
    let fixture = fixture();
    let keystore = FakeKeystore::default();
    let plan = enabled(&fixture, &keystore);

    assert_eq!(plan.protocol, Protocol::V2);
    assert!(plan.include_fingerprint);
    assert_eq!(
        plan.fingerprint.as_deref(),
        Some("google/husky/husky:15/AP3A/1:user/release-keys")
    );
    assert_eq!(plan.not_after_unix, unix(2030, 1, 20));
    assert_eq!(plan.renew_at_unix, unix(2030, 1, 19));
    assert_eq!(plan.next_attempt_unix, plan.renew_at_unix);
    assert_eq!(
        plan.keybox_sha256,
        digest(keystore.installed(&fixture.ctx).unwrap().unwrap().as_slice())
    );
    let status = service::status(&fixture.ctx, &keystore).unwrap();
    assert_eq!(status.state, State::Scheduled);
    assert_eq!(status.renew_before_secs, RENEW_BEFORE_SECS);
}

#[test]
fn enabling_requires_acknowledgement_and_the_installed_keybox() {
    let fixture = fixture();
    let keystore = FakeKeystore::default();
    let run = write_run(&fixture.ctx, "1", (2030, 1, 20));

    let mut unacknowledged = request(&run);
    unacknowledged.acknowledge_limitations = false;
    let error = service::enable(&fixture.ctx, &keystore, unacknowledged, NOW).unwrap_err();
    assert_eq!(code_of(&error), "acknowledgement_required");

    let error = service::enable(&fixture.ctx, &keystore, request(&run), NOW).unwrap_err();
    assert_eq!(code_of(&error), "keybox_not_installed");

    keystore.replace(b"<AndroidAttestation/>\n");
    let error = service::enable(&fixture.ctx, &keystore, request(&run), NOW).unwrap_err();
    assert_eq!(code_of(&error), "keybox_not_installed");
    assert!(plan::load(&fixture.ctx).unwrap().is_none());
}

#[test]
fn enabling_accepts_only_issuer_run_directories() {
    let fixture = fixture();
    let keystore = FakeKeystore::default();
    let outside = tempfile::tempdir().unwrap();
    let foreign = fixture.ctx.paths.outputs_dir.join("rkp-import-1");
    fs::create_dir_all(&foreign).unwrap();
    let nested = fixture.ctx.paths.outputs_dir.join("x/rkp-device-1");
    fs::create_dir_all(&nested).unwrap();
    for dir in [
        outside.path().display().to_string(),
        foreign.display().to_string(),
        nested.display().to_string(),
        format!("{}/missing", fixture.ctx.paths.outputs_dir.display()),
    ] {
        let error = service::enable(&fixture.ctx, &keystore, request(&dir), NOW).unwrap_err();
        assert_eq!(code_of(&error), "invalid_run", "{dir}");
    }
}

#[tokio::test]
async fn a_check_before_the_renewal_time_waits() {
    let fixture = fixture();
    let keystore = FakeKeystore::default();
    let plan = enabled(&fixture, &keystore);
    let issuer = FakeIssuer::new((2030, 2, 20));

    let tick = service::tick(&fixture.ctx, &issuer, &keystore, plan.renew_at_unix - 1, false)
        .await
        .unwrap();
    assert_eq!(tick.action, Action::Waiting);
    assert_eq!(issuer.runs.get(), 0);
    assert!(super::quiet(&serde_json::to_value(&tick).unwrap()));
}

#[tokio::test]
async fn a_due_check_issues_and_installs_a_new_keybox() {
    let fixture = fixture();
    let keystore = FakeKeystore::default();
    let plan = enabled(&fixture, &keystore);
    let issuer = FakeIssuer::new((2030, 2, 18));
    let now = plan.renew_at_unix + 60;

    let tick = service::tick(&fixture.ctx, &issuer, &keystore, now, false)
        .await
        .unwrap();
    assert_eq!(tick.action, Action::Renewed);
    assert!(!super::quiet(&serde_json::to_value(&tick).unwrap()));
    assert_eq!(issuer.runs.get(), 1);

    // The same options are replayed, and the new keybox is the one tracked and installed.
    let replayed = &issuer.options.borrow()[0];
    assert_eq!(replayed.protocol, plan.protocol);
    assert_eq!(replayed.fingerprint, plan.fingerprint);
    let renewed = plan::load(&fixture.ctx).unwrap().unwrap();
    assert!(renewed.run_dir.ends_with("rkp-device-renewed-1"));
    assert_eq!(renewed.not_after_unix, unix(2030, 2, 18));
    assert_eq!(renewed.renew_at_unix, unix(2030, 2, 17));
    assert_eq!(renewed.next_attempt_unix, renewed.renew_at_unix);
    assert_eq!(renewed.last_renewed_at_unix, Some(now));
    assert!(renewed.last_attempt.unwrap().ok);
    let installed = keystore.installed(&fixture.ctx).unwrap().unwrap();
    assert_eq!(renewed.keybox_sha256, digest(&installed));
    assert!(String::from_utf8(installed).unwrap().contains("renewed-1"));

    // Nothing more to do until the new renewal time.
    let tick = service::tick(&fixture.ctx, &issuer, &keystore, now + 60, false)
        .await
        .unwrap();
    assert_eq!(tick.action, Action::Waiting);
    assert_eq!(issuer.runs.get(), 1);
}

#[tokio::test]
async fn a_short_lived_chain_never_causes_back_to_back_requests() {
    let fixture = fixture();
    let keystore = FakeKeystore::default();
    let plan = enabled(&fixture, &keystore);
    // Already inside the renewal window when issued, as with a wrong system clock.
    let issuer = FakeIssuer::new((2030, 1, 19));
    let now = plan.renew_at_unix;

    service::tick(&fixture.ctx, &issuer, &keystore, now, false)
        .await
        .unwrap();
    let renewed = plan::load(&fixture.ctx).unwrap().unwrap();
    assert_eq!(renewed.next_attempt_unix, now + MIN_REISSUE_SECS);
    let tick = service::tick(&fixture.ctx, &issuer, &keystore, now + 60, false)
        .await
        .unwrap();
    assert_eq!(tick.action, Action::Waiting);
    assert_eq!(issuer.runs.get(), 1);
}

#[tokio::test]
async fn failures_keep_the_keybox_and_back_off() {
    let fixture = fixture();
    let keystore = FakeKeystore::default();
    let plan = enabled(&fixture, &keystore);
    let before = keystore.installed(&fixture.ctx).unwrap();
    let mut issuer = FakeIssuer::new((2030, 2, 18));
    issuer.failure = Some("rkp_server_error");
    let now = plan.renew_at_unix;

    let error = service::tick(&fixture.ctx, &issuer, &keystore, now, false)
        .await
        .unwrap_err();
    assert_eq!(code_of(&error), "rkp_server_error");
    let failed = plan::load(&fixture.ctx).unwrap().unwrap();
    assert_eq!(failed.consecutive_failures, 1);
    assert_eq!(failed.next_attempt_unix, now + 3600);
    let attempt = failed.last_attempt.unwrap();
    assert!(!attempt.ok);
    assert_eq!(attempt.code.as_deref(), Some("rkp_server_error"));
    assert_eq!(keystore.installed(&fixture.ctx).unwrap(), before);
    assert_eq!(
        service::status(&fixture.ctx, &keystore).unwrap().state,
        State::Retrying
    );

    // The retry waits for its delay, then doubles it on another failure.
    let tick = service::tick(&fixture.ctx, &issuer, &keystore, now + 3599, false)
        .await
        .unwrap();
    assert_eq!(tick.action, Action::Waiting);
    service::tick(&fixture.ctx, &issuer, &keystore, now + 3600, false)
        .await
        .unwrap_err();
    let failed = plan::load(&fixture.ctx).unwrap().unwrap();
    assert_eq!(failed.consecutive_failures, 2);
    assert_eq!(failed.next_attempt_unix, now + 3600 + 2 * 3600);

    // A later success resets the backoff.
    issuer.failure = None;
    let tick = service::tick(&fixture.ctx, &issuer, &keystore, now + 3 * 3600, false)
        .await
        .unwrap();
    assert_eq!(tick.action, Action::Renewed);
    assert_eq!(plan::load(&fixture.ctx).unwrap().unwrap().consecutive_failures, 0);
}

#[tokio::test]
async fn an_unreadable_keystore_is_a_failure_only_once_renewal_is_due() {
    let fixture = fixture();
    let keystore = FakeKeystore::default();
    let plan = enabled(&fixture, &keystore);
    let issuer = FakeIssuer::new((2030, 2, 18));
    keystore.unavailable.set(true);

    let tick = service::tick(&fixture.ctx, &issuer, &keystore, NOW, false)
        .await
        .unwrap();
    assert_eq!(tick.action, Action::Waiting);
    let error = service::tick(&fixture.ctx, &issuer, &keystore, plan.renew_at_unix, false)
        .await
        .unwrap_err();
    assert_eq!(code_of(&error), "keystore_unavailable");
    assert_eq!(issuer.runs.get(), 0);
    assert_eq!(plan::load(&fixture.ctx).unwrap().unwrap().consecutive_failures, 1);
}

#[tokio::test]
async fn a_different_installed_keybox_stops_renewal_without_overwriting_it() {
    let fixture = fixture();
    let keystore = FakeKeystore::default();
    let plan = enabled(&fixture, &keystore);
    let issuer = FakeIssuer::new((2030, 2, 18));
    keystore.replace(b"<AndroidAttestation>chosen elsewhere</AndroidAttestation>\n");

    assert_eq!(
        service::status(&fixture.ctx, &keystore).unwrap().state,
        State::Superseded
    );
    let tick = service::tick(&fixture.ctx, &issuer, &keystore, plan.renew_at_unix, false)
        .await
        .unwrap();
    assert_eq!(tick.action, Action::Superseded);
    assert!(!super::quiet(&serde_json::to_value(&tick).unwrap()));
    assert_eq!(issuer.runs.get(), 0);
    let stopped = plan::load(&fixture.ctx).unwrap().unwrap();
    assert_eq!(stopped.superseded_at_unix, Some(plan.renew_at_unix));

    // Later checks stay quiet, and forcing reports why instead of renewing.
    let tick = service::tick(&fixture.ctx, &issuer, &keystore, plan.renew_at_unix + 60, false)
        .await
        .unwrap();
    assert_eq!(tick.action, Action::Stopped);
    assert!(super::quiet(&serde_json::to_value(&tick).unwrap()));
    let error = service::tick(&fixture.ctx, &issuer, &keystore, NOW, true)
        .await
        .unwrap_err();
    assert_eq!(code_of(&error), "keybox_changed");
    assert_eq!(issuer.runs.get(), 0);
    assert_eq!(
        keystore.installed(&fixture.ctx).unwrap().unwrap(),
        b"<AndroidAttestation>chosen elsewhere</AndroidAttestation>\n"
    );
}

#[tokio::test]
async fn a_keybox_installed_during_issuance_is_kept() {
    const MANUAL: &[u8] = b"<AndroidAttestation>manual</AndroidAttestation>\n";
    let fixture = fixture();
    let keystore = FakeKeystore::default();
    let plan = enabled(&fixture, &keystore);
    let mut issuer = FakeIssuer::new((2030, 2, 18));
    issuer.replace_during_issue = Some((&keystore, MANUAL));

    let tick = service::tick(&fixture.ctx, &issuer, &keystore, plan.renew_at_unix, false)
        .await
        .unwrap();
    assert_eq!(tick.action, Action::Superseded);
    assert_eq!(issuer.runs.get(), 1);
    assert_eq!(keystore.installed(&fixture.ctx).unwrap().as_deref(), Some(MANUAL));
}

#[tokio::test]
async fn forcing_renews_early_but_never_without_a_plan() {
    let fixture = fixture();
    let keystore = FakeKeystore::default();
    let issuer = FakeIssuer::new((2030, 2, 18));
    let error = service::tick(&fixture.ctx, &issuer, &keystore, NOW, true)
        .await
        .unwrap_err();
    assert_eq!(code_of(&error), "renewal_disabled");
    let tick = service::tick(&fixture.ctx, &issuer, &keystore, NOW, false)
        .await
        .unwrap();
    assert_eq!(tick.action, Action::Disabled);
    assert!(super::quiet(&serde_json::to_value(&tick).unwrap()));

    enabled(&fixture, &keystore);
    let tick = service::tick(&fixture.ctx, &issuer, &keystore, NOW, true)
        .await
        .unwrap();
    assert_eq!(tick.action, Action::Renewed);
    assert_eq!(issuer.runs.get(), 1);
}

#[tokio::test]
async fn a_held_plan_is_busy_and_disabling_forgets_it() {
    let fixture = fixture();
    let keystore = FakeKeystore::default();
    enabled(&fixture, &keystore);
    let issuer = FakeIssuer::new((2030, 2, 18));
    {
        let _held = plan::Store::existing(&fixture.ctx).unwrap().unwrap();
        let tick = service::tick(&fixture.ctx, &issuer, &keystore, NOW, false)
            .await
            .unwrap();
        assert_eq!(tick.action, Action::Busy);
        let error = service::tick(&fixture.ctx, &issuer, &keystore, NOW, true)
            .await
            .unwrap_err();
        assert_eq!(code_of(&error), "renewal_busy");
        assert_eq!(code_of(&service::disable(&fixture.ctx).unwrap_err()), "renewal_busy");
    }
    let status = service::disable(&fixture.ctx).unwrap();
    assert_eq!(status.state, State::Off);
    assert!(plan::load(&fixture.ctx).unwrap().is_none());
    // The issued keybox stays where it was.
    assert!(fixture.ctx.paths.outputs_dir.join("rkp-device-1/keybox.xml").is_file());
}

#[test]
fn renewal_replays_the_issuer_cli_contract() {
    use duck_core::Feature as _;
    assert_eq!(duck_rkp_device::FEATURE.info().contract, super::ISSUER_CONTRACT);
    for protocol in [Protocol::Auto, Protocol::V1, Protocol::V2, Protocol::V1Native] {
        for fingerprint in [None, Some("vendor/device:16/ID/1:user/release-keys".to_owned())] {
            let args = provision_args(&Options {
                protocol,
                include_fingerprint: fingerprint.is_some(),
                fingerprint,
            });
            duck_rkp_device::FEATURE
                .command()
                .try_get_matches_from(&args)
                .unwrap_or_else(|error| panic!("{args:?}: {error}"));
        }
    }
}

#[path = "tests_state.rs"]
mod state;
