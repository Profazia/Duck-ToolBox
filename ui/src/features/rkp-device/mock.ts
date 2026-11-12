import type { MockModule } from "@/core/mock"
import { MockFailure } from "@/core/mock"

import type { DeviceStatus, Protocol, Provision } from "./api"
import type { RenewalStatus } from "./renewal"

const OUT = "/data/adb/duck-toolbox/var/outputs/rkp-device-1750000000000"

function deviceStatus(): DeviceStatus {
  const status: DeviceStatus = {
    prerequisites_met: true,
    android_arm64: true,
    root: true,
    library_present: true,
    device_present: true,
    v1_available: true,
    v1_native_available: true,
    v2_available: true,
    aidl_apk: "/apex/com.android.rkpd/priv-app/rkpd/rkpdapp.apk",
    qualcomm_soc: true,
    mediatek_soc: false,
    library_path: "/vendor/lib64/libkeymasterdeviceutils.so",
    device_path: "/dev/smcinvoke",
    fingerprint: "google/husky/husky:15/AP3A.241005.015/1234567:user/release-keys",
    soc_manufacturer: "QTI",
    soc_detection: {
      state: "qualcomm",
      model: "SM8650",
      evidence: [
        { source: "ro.soc.manufacturer", value: "QTI", vendor: "qualcomm" },
        { source: "ro.hardware", value: "qcom", vendor: "qualcomm" },
      ],
    },
    limitations: ["partial_device_support", "rkp_only"],
    blockers: [],
  }
  const scenario = new URLSearchParams(location.search).get("soc")
  if (new URLSearchParams(location.search).get("rkp") === "v1-only") {
    status.library_present = false
    status.device_present = false
    status.v2_available = false
    status.v1_native_available = false
  } else if (new URLSearchParams(location.search).get("rkp") === "v2-only") {
    status.v1_available = false
    status.aidl_apk = null
  }
  if (scenario === "unknown") {
    status.soc_manufacturer = ""
    status.soc_detection = { state: "unknown", model: "", evidence: [] }
  } else if (scenario === "fallback") {
    status.soc_manufacturer = ""
    status.soc_detection = {
      state: "qualcomm",
      model: "PINEAPPLE",
      evidence: [{ source: "/sys/devices/soc0/family", value: "Snapdragon", vendor: "qualcomm" }],
    }
  } else if (scenario === "mediatek") {
    status.library_present = false
    status.device_present = false
    status.v2_available = false
    status.v1_native_available = false
    status.soc_manufacturer = "MediaTek"
    status.soc_detection = {
      state: "media_tek",
      model: "MT6878",
      evidence: [{ source: "ro.soc.manufacturer", value: "MediaTek", vendor: "media_tek" }],
    }
  } else if (scenario === "other" || scenario === "conflict") {
    status.soc_manufacturer = scenario === "other" ? "Samsung" : "MediaTek"
    status.soc_detection = {
      state: scenario === "other" ? "other" : "conflicting",
      model: scenario === "other" ? "Exynos 2400" : "SM8650",
      evidence: [
        {
          source: "ro.soc.manufacturer",
          value: scenario === "other" ? "Samsung" : "MediaTek",
          vendor: scenario === "other" ? "other" : "media_tek",
        },
      ],
    }
    if (scenario === "conflict")
      status.soc_detection.evidence.push({
        source: "ro.hardware",
        value: "qcom",
        vendor: "qualcomm",
      })
  }
  const blocker = {
    qualcomm: null,
    media_tek: null,
    other: "qualcomm_soc_required",
    unknown: "soc_vendor_unknown",
    conflicting: "soc_vendor_conflict",
  }[status.soc_detection.state]
  status.qualcomm_soc = status.soc_detection.state === "qualcomm"
  status.mediatek_soc = status.soc_detection.state === "media_tek"
  if (!status.qualcomm_soc) {
    status.v2_available = false
    status.v1_native_available = false
  }
  status.blockers = blocker ? [blocker] : []
  if (!status.v1_available && !status.v2_available) status.blockers.push("v1_unavailable")
  status.prerequisites_met = status.blockers.length === 0
  return status
}

const DAY = 24 * 60 * 60
type Plan = NonNullable<RenewalStatus["plan"]>
let renewalPlan: Plan | null = null

function renewalStatus(): RenewalStatus {
  const state = !renewalPlan
    ? "off"
    : renewalPlan.superseded_at_unix !== null
      ? "superseded"
      : renewalPlan.consecutive_failures > 0
        ? "retrying"
        : "scheduled"
  return { state, renew_before_secs: DAY, plan: renewalPlan }
}

/** A run whose leaf certificate expires `days` from now, as the backend would track it. */
function trackedPlan(runDir: string, input: Record<string, unknown>, days = 30): Plan {
  const now = Math.floor(Date.now() / 1000)
  const notAfter = now + days * DAY
  return {
    api: 1,
    protocol: (input.protocol as Plan["protocol"] | undefined) ?? "auto",
    include_fingerprint: input.include_fingerprint === true,
    fingerprint: typeof input.fingerprint === "string" ? input.fingerprint : null,
    run_dir: runDir,
    keybox_sha256: "4f1c".repeat(16),
    not_after_unix: notAfter,
    renew_at_unix: notAfter - DAY,
    next_attempt_unix: notAfter - DAY,
    enabled_at_unix: now,
    last_renewed_at_unix: null,
    last_attempt: null,
    consecutive_failures: 0,
    superseded_at_unix: null,
  }
}

// `?renewal=scheduled|retrying|superseded` starts with a tracked keybox.
const initialRenewal = new URLSearchParams(location.search).get("renewal")
if (initialRenewal) {
  renewalPlan = trackedPlan(`${OUT}-earlier`, {}, 12)
  if (initialRenewal === "retrying") {
    renewalPlan.consecutive_failures = 2
    renewalPlan.last_attempt = {
      at_unix: Math.floor(Date.now() / 1000) - 3600,
      ok: false,
      code: "rkp_server_error",
      message: "The RKP server returned HTTP 503",
    }
  } else if (initialRenewal === "superseded") {
    renewalPlan.superseded_at_unix = Math.floor(Date.now() / 1000)
  }
}

const mock: MockModule = {
  feature: [
    { id: "rkp-device", contract: 7 },
    { id: "rkp-renewal", contract: 1 },
  ],
  handlers: {
    "rkp-renewal.status": renewalStatus,
    "rkp-renewal.enable": (_args, _flags, input) => {
      const request = (input ?? {}) as Record<string, unknown>
      if (request.acknowledge_limitations !== true)
        throw new MockFailure("acknowledgement_required", "The limitations were not acknowledged")
      if (typeof request.run_dir !== "string" || !request.run_dir.startsWith(OUT))
        throw new MockFailure("invalid_run", "This is not a Device RKP Issuer run directory")
      renewalPlan = trackedPlan(request.run_dir, request)
      return renewalStatus()
    },
    "rkp-renewal.disable": () => {
      renewalPlan = null
      return renewalStatus()
    },
    "rkp-renewal.tick": (_args, flags) => {
      if (!renewalPlan) {
        if (flags.force === true)
          throw new MockFailure("renewal_disabled", "automatic renewal is not enabled")
        return { action: "disabled", status: renewalStatus() }
      }
      if (renewalPlan.superseded_at_unix !== null) {
        if (flags.force === true)
          throw new MockFailure("keybox_changed", "the installed keybox changed")
        return { action: "stopped", status: renewalStatus() }
      }
      if (flags.force !== true) return { action: "waiting", status: renewalStatus() }
      const now = Math.floor(Date.now() / 1000)
      renewalPlan = {
        ...trackedPlan(`${OUT}-renewed`, renewalPlan),
        enabled_at_unix: renewalPlan.enabled_at_unix,
        last_renewed_at_unix: now,
        last_attempt: { at_unix: now, ok: true, code: null, message: null },
      }
      return { action: "renewed", status: renewalStatus() }
    },
    "rkp-device.status": deviceStatus,
    "rkp-device.provision": (_args, flags) => {
      const protocol = flags.protocol ?? "auto"
      if (!["auto", "v1", "v2", "v1-native"].includes(protocol as string)) {
        throw new MockFailure("usage_error", "Invalid RKP protocol")
      }
      if (flags["acknowledge-limitations"] !== true) {
        throw new MockFailure("acknowledgement_required", "The limitations were not acknowledged")
      }
      if (
        flags["include-fingerprint"] !== undefined &&
        !["true", "false"].includes(String(flags["include-fingerprint"]))
      ) {
        throw new MockFailure("usage_error", "Invalid fingerprint inclusion value")
      }
      const status = deviceStatus()
      if (
        !status.prerequisites_met ||
        (protocol === "v1" && !status.v1_available) ||
        (protocol === "v1-native" && !status.v1_native_available) ||
        (protocol === "v2" && !status.v2_available)
      )
        throw new MockFailure("unsupported_device", "Prerequisites are missing")
      type Method = Exclude<Protocol, "auto">
      const available: Record<Method, boolean> = {
        v2: status.v2_available,
        v1: status.v1_available,
        "v1-native": status.v1_native_available,
      }
      const methods =
        protocol === "auto"
          ? (["v2", "v1", "v1-native"] as const).filter((method) => available[method])
          : [protocol as Method]
      const failures = new URLSearchParams(location.search).get("rkp_fail")?.split(",") ?? []
      const attempts: Provision["attempts"] = []
      let selected: Method | undefined
      for (const method of methods) {
        const error = failures.includes(method)
          ? { code: "ta_rejected", message: `${method} rejected the request` }
          : null
        attempts.push({ method, error })
        if (error === null) {
          selected = method
          break
        }
        if (protocol !== "auto") throw new MockFailure(error.code, error.message)
      }
      if (!selected)
        throw new MockFailure(
          "all_methods_failed",
          attempts
            .map(
              (attempt) => `${attempt.method} [${attempt.error?.code}]: ${attempt.error?.message}`,
            )
            .join("; "),
        )
      const v1 = selected !== "v2"
      return {
        acknowledged_limitations: true,
        limitations: status.limitations,
        mode: "device-ta-oracle",
        csr_protocol: v1 ? "v1" : "v2",
        csr_backend: selected === "v1" ? "aidl" : "native",
        attempts,
        fingerprint: String(flags.fingerprint ?? status.fingerprint).trim(),
        include_fingerprint: flags["include-fingerprint"] === "true",
        challenge_hex: "9f2c1d4b6a8e0f3c5b7d9a1e2f4c6b8d0a2e4f6c8b0d2e4f6a8c0e2f4b6d8a0c",
        csr_len: 1284,
        local_verify: v1
          ? null
          : {
              version: 1,
              dice_entries: 3,
              uds_pub_hex: "e63af59f0c1d2e3f40516a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f70819",
              signature_valid: true,
              csr_version: 3,
              cert_type: "keymint",
              brand: "google",
              keys_to_sign: 1,
              unverified_fingerprint:
                flags["include-fingerprint"] === "true"
                  ? String(flags.fingerprint ?? status.fingerprint).trim()
                  : null,
            },
        chain: {
          certificates: 4,
          subjects: ["CN=5f8e3c…,O=TEE", "CN=Droid CA3", "CN=Droid CA2", "CN=Key Attestation CA1"],
        },
        device_id: "Qualcomm-7c1f9a3b2d40",
        keybox_xml: '<?xml version="1.0"?>\n<AndroidAttestation>…</AndroidAttestation>',
        artifacts: {
          run_dir: OUT,
          keybox_path: `${OUT}/keybox.xml`,
          csr_path: `${OUT}/csr.cbor`,
          cert_chain_path: `${OUT}/cert_chain.der`,
          private_key_path: `${OUT}/private_key.pem`,
        },
        prerequisites: status,
      }
    },
  },
}

export default mock
