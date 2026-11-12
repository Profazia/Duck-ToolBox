#![cfg(all(unix, feature = "rkp-renewal"))]
//! Renewal through the real `duckd` binary: the Tricky Store manager's own keybox
//! validation and install, and the `rkp-device provision` replay up to its device gate.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, date_time_ymd};
use serde_json::{Value, json};

struct Env {
    _temp: tempfile::TempDir,
    root: PathBuf,
    data: PathBuf,
    sysroot: PathBuf,
}

impl Env {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("module");
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::write(root.join("module.prop"), "id=duck-toolbox\n").unwrap();
        let sysroot = temp.path().join("sys");
        let backend = sysroot.join("data/adb/modules/tricky_store");
        fs::create_dir_all(&backend).unwrap();
        fs::write(
            backend.join("module.prop"),
            "id=tricky_store\nname=Tricky Store\nversionCode=246\n",
        )
        .unwrap();
        Self {
            data: temp.path().join("data"),
            root,
            sysroot,
            _temp: temp,
        }
    }

    fn installed(&self) -> PathBuf {
        self.sysroot.join("data/adb/tricky_store/keybox.xml")
    }

    /// Returns the envelope and whether the command succeeded.
    fn run(&self, args: &[&str], stdin: Option<&Value>) -> (Value, bool) {
        let mut child = Command::new(env!("CARGO_BIN_EXE_duckd"))
            .env("DUCK_TOOLBOX_ROOT", &self.root)
            .env("DUCK_TOOLBOX_DATA_ROOT", &self.data)
            .env("DUCK_TOOLBOX_SYSROOT", &self.sysroot)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        if let Some(stdin) = stdin {
            input.write_all(stdin.to_string().as_bytes()).unwrap();
        }
        drop(input);
        let output = child.wait_with_output().unwrap();
        let envelope = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!("{args:?}: {error}: {}", String::from_utf8_lossy(&output.stdout))
        });
        (envelope, output.status.success())
    }

    fn ok(&self, args: &[&str], stdin: Option<&Value>) -> Value {
        let (envelope, ok) = self.run(args, stdin);
        assert!(ok, "{args:?}: {envelope}");
        envelope["data"].clone()
    }

    fn fails(&self, args: &[&str], stdin: Option<&Value>) -> String {
        let (envelope, ok) = self.run(args, stdin);
        assert!(!ok, "{args:?} succeeded: {envelope}");
        envelope["error"]["code"].as_str().unwrap().to_owned()
    }

    /// Installs a run's keybox by content. The data root is not under the test sysroot,
    /// so a path would not resolve for the keystore manager the way it does on a device.
    fn install_run_keybox(&self, run: &Path) {
        let content = fs::read_to_string(run.join("keybox.xml")).unwrap();
        self.ok(
            &["tricky-store", "keybox", "import", "--stdin-json"],
            Some(&json!({ "content": content })),
        );
    }

    fn logged(&self, command: &str) -> Vec<Value> {
        fs::read_to_string(self.data.join("var/logs/duckd.log"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|entry| entry["command"] == command)
            .collect()
    }

    /// A Device RKP Issuer run directory holding the bundled AOSP keybox, so the real
    /// keystore manager accepts it, and a chain whose leaf expires on 2030-01-20.
    fn issuer_run(&self) -> PathBuf {
        let dir = self.data.join("var/outputs/rkp-device-1700000000000-abc");
        fs::create_dir_all(&dir).unwrap();
        let aosp = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../duck-tricky-store/assets/aosp-keybox.xml");
        fs::copy(aosp, dir.join("keybox.xml")).unwrap();
        let mut params = CertificateParams::default();
        params.not_before = date_time_ymd(2029, 1, 1);
        params.not_after = date_time_ymd(2030, 1, 20);
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let certificate = params.self_signed(&key).unwrap();
        fs::write(dir.join("cert_chain.der"), certificate.der().as_ref()).unwrap();
        dir
    }
}

fn enable_request(run_dir: &Path) -> Value {
    json!({
        "run_dir": run_dir.display().to_string(),
        "protocol": "auto",
        "include_fingerprint": false,
        "acknowledge_limitations": true,
    })
}

#[test]
fn renewal_tracks_the_installed_keybox_and_replays_the_issuer() {
    let env = Env::new();
    let status = env.ok(&["rkp-renewal", "status"], None);
    assert_eq!(status["state"], "off");
    assert!(status["plan"].is_null());
    assert_eq!(status["renew_before_secs"], 86_400);

    let run = env.issuer_run();
    let enable = ["rkp-renewal", "enable", "--stdin-json"];
    let mut request = enable_request(&run);
    request["acknowledge_limitations"] = json!(false);
    assert_eq!(env.fails(&enable, Some(&request)), "acknowledgement_required");
    assert_eq!(
        env.fails(&enable, Some(&enable_request(&run))),
        "keybox_not_installed"
    );

    env.install_run_keybox(&run);
    let enabled = env.ok(&enable, Some(&enable_request(&run)));
    assert_eq!(enabled["state"], "scheduled");
    let plan = &enabled["plan"];
    assert_eq!(plan["protocol"], "auto");
    assert!(plan["fingerprint"].is_null());
    // 2030-01-20 and the day before it.
    assert_eq!(plan["not_after_unix"], 1_895_097_600_u64);
    assert_eq!(plan["renew_at_unix"], 1_895_011_200_u64);
    assert_eq!(
        plan["run_dir"],
        fs::canonicalize(&run).unwrap().display().to_string()
    );

    // Not due until 2030, so a background check does nothing and stays out of the log.
    let tick = env.ok(&["rkp-renewal", "tick"], None);
    assert_eq!(tick["action"], "waiting");
    assert!(env.logged("rkp-renewal.tick").is_empty());

    // Forcing replays `rkp-device provision`, which stops at the device gate on a host.
    let before = fs::read(env.installed()).unwrap();
    assert_eq!(
        env.fails(&["rkp-renewal", "tick", "--force"], None),
        "unsupported_device"
    );
    assert_eq!(fs::read(env.installed()).unwrap(), before);
    let retrying = env.ok(&["rkp-renewal", "status"], None);
    assert_eq!(retrying["state"], "retrying");
    assert_eq!(retrying["plan"]["consecutive_failures"], 1);
    assert_eq!(
        retrying["plan"]["last_attempt"]["code"],
        "unsupported_device"
    );
    let logged = env.logged("rkp-renewal.tick");
    assert_eq!(logged.len(), 1);
    assert_eq!(logged[0]["code"], "unsupported_device");
    // The log never records data payloads, so nothing from the plan reaches it.
    let log = fs::read_to_string(env.data.join("var/logs/duckd.log")).unwrap();
    assert!(!log.contains(plan["keybox_sha256"].as_str().unwrap()));
}

#[test]
fn installing_another_keybox_stops_renewal() {
    let env = Env::new();
    let run = env.issuer_run();
    env.install_run_keybox(&run);
    env.ok(
        &["rkp-renewal", "enable", "--stdin-json"],
        Some(&enable_request(&run)),
    );

    env.ok(&["tricky-store", "keybox", "generate"], None);
    assert_eq!(env.ok(&["rkp-renewal", "status"], None)["state"], "superseded");
    let generated = fs::read(env.installed()).unwrap();
    assert_eq!(env.ok(&["rkp-renewal", "tick"], None)["action"], "superseded");
    assert_eq!(env.ok(&["rkp-renewal", "tick"], None)["action"], "stopped");
    assert_eq!(
        env.fails(&["rkp-renewal", "tick", "--force"], None),
        "keybox_changed"
    );
    assert_eq!(fs::read(env.installed()).unwrap(), generated);

    let disabled = env.ok(&["rkp-renewal", "disable"], None);
    assert_eq!(disabled["state"], "off");
    assert_eq!(env.ok(&["rkp-renewal", "tick"], None)["action"], "disabled");
    assert!(run.join("keybox.xml").is_file());
}

#[test]
fn enabling_rejects_paths_outside_issuer_runs() {
    let env = Env::new();
    let outputs = env.data.join("var/outputs");
    fs::create_dir_all(outputs.join("rkp-import-1")).unwrap();
    for run_dir in [
        env.root.clone(),
        outputs.join("rkp-import-1"),
        outputs.join("rkp-device-missing"),
    ] {
        assert_eq!(
            env.fails(
                &["rkp-renewal", "enable", "--stdin-json"],
                Some(&enable_request(&run_dir))
            ),
            "invalid_run"
        );
    }
}

#[test]
fn enabling_starts_one_detached_check_and_turning_off_removes_its_state() {
    let env = Env::new();
    // The shipped check script, with its one-minute waits shortened for the test.
    let module = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../module");
    for script in ["rkp-renewal.sh", "util_functions.sh", "identity.sh"] {
        let body = fs::read_to_string(module.join(script)).unwrap();
        fs::write(env.root.join(script), body.replace("    sleep 60", "    sleep 0.2")).unwrap();
    }
    let ticks = env.root.join("ticks");
    fs::write(
        env.root.join("bin/duckctl.sh"),
        format!(
            "#!/bin/sh\necho \"$@\" >> '{}'\nexec '{}' \"$@\"\n",
            ticks.display(),
            env!("CARGO_BIN_EXE_duckd")
        ),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        let wrapper = env.root.join("bin/duckctl.sh");
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let run = env.issuer_run();
    env.install_run_keybox(&run);
    let state = env.data.join("var/rkp-renewal");

    let started = std::time::Instant::now();
    env.ok(
        &["rkp-renewal", "enable", "--stdin-json"],
        Some(&enable_request(&run)),
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(5), "enable waited on the check");
    let pid = wait_for(|| fs::read_to_string(state.join("check.pid")).ok());
    // The check ran once right away; renewal is not due, so it waits without renewing.
    wait_for(|| fs::read_to_string(&ticks).ok().filter(|log| log.contains("rkp-renewal tick")));
    assert!(Path::new(&format!("/proc/{}", pid.trim())).exists());

    env.ok(&["rkp-renewal", "disable"], None);
    assert!(!state.exists());
    wait_for(|| (!Path::new(&format!("/proc/{}/cmdline", pid.trim())).exists()
        || !fs::read_to_string(format!("/proc/{}/cmdline", pid.trim()))
            .unwrap_or_default()
            .contains("rkp-renewal.sh"))
    .then_some(()));
    assert!(!state.exists(), "the exiting check recreated state");
}

fn wait_for<T>(mut probe: impl FnMut() -> Option<T>) -> T {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if let Some(value) = probe() {
            return value;
        }
        assert!(std::time::Instant::now() < deadline, "timed out");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}
