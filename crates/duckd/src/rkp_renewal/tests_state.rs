//! What renewal leaves on disk: nothing without a plan, and no stale key material.

use std::fs;

use duck_core::Context;

use super::{FakeIssuer, FakeKeystore, NOW, enabled, fixture, request, write_run};
use crate::rkp_renewal::{
    plan,
    service::{self, Action},
};

/// Every file and directory under the data root, relative to it.
fn tree(ctx: &Context) -> Vec<String> {
    fn walk(dir: &std::path::Path, base: &std::path::Path, out: &mut Vec<String>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            out.push(path.strip_prefix(base).unwrap().display().to_string());
            if path.is_dir() {
                walk(&path, base, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(&ctx.paths.data_root, &ctx.paths.data_root, &mut out);
    out.sort();
    out
}

#[tokio::test]
async fn without_a_plan_nothing_is_written() {
    let fixture = fixture();
    let keystore = FakeKeystore::default();
    let issuer = FakeIssuer::new((2030, 2, 18));
    let before = tree(&fixture.ctx);

    service::status(&fixture.ctx, &keystore).unwrap();
    service::tick(&fixture.ctx, &issuer, &keystore, NOW, false)
        .await
        .unwrap();
    service::tick(&fixture.ctx, &issuer, &keystore, NOW, true)
        .await
        .unwrap_err();
    service::disable(&fixture.ctx).unwrap();
    // A rejected request creates no state either.
    let run = write_run(&fixture.ctx, "1", (2030, 1, 20));
    service::enable(&fixture.ctx, &keystore, request(&run), NOW).unwrap_err();
    let mut expected = before;
    expected.extend(
        ["", "/cert_chain.der", "/keybox.xml"]
            .map(|file| format!("var/outputs/rkp-device-1{file}")),
    );
    expected.sort();
    assert_eq!(tree(&fixture.ctx), expected);
}

#[tokio::test]
async fn turning_renewal_off_removes_all_of_its_state() {
    let fixture = fixture();
    let keystore = FakeKeystore::default();
    enabled(&fixture, &keystore);
    let state = fixture.ctx.paths.var_dir.join("rkp-renewal");
    assert!(state.join("plan.json").is_file());
    fs::write(state.join("check.pid"), "1").unwrap();

    service::disable(&fixture.ctx).unwrap();
    assert!(!state.exists());
    let issuer = FakeIssuer::new((2030, 2, 18));
    let tick = service::tick(&fixture.ctx, &issuer, &keystore, NOW, false)
        .await
        .unwrap();
    assert_eq!(tick.action, Action::Disabled);
    assert!(!state.exists());
}

#[tokio::test]
async fn renewal_deletes_only_the_runs_it_created() {
    let fixture = fixture();
    let keystore = FakeKeystore::default();
    let original = enabled(&fixture, &keystore).run_dir;
    let outputs = &fixture.ctx.paths.outputs_dir;
    let issuer = FakeIssuer::new((2030, 2, 18));

    for _ in 0..3 {
        service::tick(&fixture.ctx, &issuer, &keystore, NOW, true)
            .await
            .unwrap();
    }
    let mut runs: Vec<String> = fs::read_dir(outputs)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    runs.sort();
    // The run the user issued stays; of the renewals, only the tracked one remains.
    assert_eq!(runs, ["rkp-device-1", "rkp-device-renewed-3"]);
    assert!(std::path::Path::new(&original).is_dir());
    let plan = plan::load(&fixture.ctx).unwrap().unwrap();
    assert!(plan.run_dir.ends_with("rkp-device-renewed-3"));
    assert!(plan.run_dir_from_renewal);
}
