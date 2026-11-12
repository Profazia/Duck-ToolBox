// @vitest-environment node
import { afterEach, describe, expect, it } from "vitest"

import { featureManifest, isDuckError } from "@/core/duckd"
import type { Host } from "@/core/testing/host"
import { CONTRACT, DEVICE_PROPS, hasDuckd, installHost } from "@/core/testing/host"

import { RENEWAL_FEATURE, renewalApi } from "./renewal"

let host: Host | undefined
afterEach(() => host?.dispose())

describe.skipIf(!hasDuckd)("automatic renewal API against the real duckd", CONTRACT, () => {
  it("is compiled in with the contract the card expects", async () => {
    host = installHost({ props: DEVICE_PROPS })
    const manifest = await featureManifest()
    expect(manifest.features.find((feature) => feature.id === RENEWAL_FEATURE.id)?.contract).toBe(
      RENEWAL_FEATURE.contract,
    )
  })

  it("starts off and treats a background check as a quiet no-op", async () => {
    host = installHost({ props: DEVICE_PROPS })
    expect(await renewalApi.status()).toEqual({
      state: "off",
      renew_before_secs: 86_400,
      plan: null,
    })
    expect((await renewalApi.disable()).state).toBe("off")
  })

  it("reports a forced check without a plan, and refuses foreign run directories", async () => {
    host = installHost({ props: DEVICE_PROPS })
    const forced = await renewalApi.renewNow().catch((caught: unknown) => caught)
    expect(isDuckError(forced)).toBe(true)
    expect(forced).toMatchObject({ code: "renewal_disabled" })

    const enabled = await renewalApi
      .enable({
        runDir: "/data/adb/duck-toolbox/var/outputs/rkp-device-missing",
        protocol: "auto",
        includeFingerprint: false,
        fingerprint: "",
      })
      .catch((caught: unknown) => caught)
    expect(isDuckError(enabled)).toBe(true)
    expect(enabled).not.toMatchObject({ code: "contract_mismatch" })
    expect(enabled).toMatchObject({ code: "invalid_run" })
  })
})
