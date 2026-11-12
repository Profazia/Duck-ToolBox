import { z } from "zod"

import { duckd } from "@/core/duckd"

import type { Protocol } from "./api"

/** Backend contract of `duckd rkp-renewal`, composed in `duckd` rather than a feature crate. */
export const RENEWAL_FEATURE = { id: "rkp-renewal", contract: 1 } as const
export const RENEWAL_STATUS_KEY = ["rkp-renewal.status"] as const

const attemptSchema = z.object({
  at_unix: z.number(),
  ok: z.boolean(),
  code: z.string().nullable(),
  message: z.string().nullable(),
})

const planSchema = z.object({
  api: z.literal(1),
  protocol: z.enum(["auto", "v1", "v2", "v1-native"]),
  include_fingerprint: z.boolean(),
  fingerprint: z.string().nullable(),
  run_dir: z.string(),
  keybox_sha256: z.string(),
  not_after_unix: z.number(),
  renew_at_unix: z.number(),
  next_attempt_unix: z.number(),
  enabled_at_unix: z.number(),
  last_renewed_at_unix: z.number().nullable(),
  last_attempt: attemptSchema.nullable(),
  consecutive_failures: z.number(),
  superseded_at_unix: z.number().nullable(),
})

const statusSchema = z
  .object({
    state: z.enum(["off", "scheduled", "retrying", "superseded"]),
    renew_before_secs: z.number(),
    plan: planSchema.nullable(),
  })
  .refine((data) => (data.state === "off") === (data.plan === null), {
    message: "Renewal state disagrees with the saved plan",
  })
export type RenewalStatus = z.infer<typeof statusSchema>

const tickSchema = z.object({
  action: z.enum(["disabled", "stopped", "superseded", "waiting", "busy", "renewed"]),
  status: statusSchema,
})

export interface RenewalOptions {
  runDir: string
  protocol: Protocol
  includeFingerprint: boolean
  fingerprint: string
}

export const renewalApi = {
  status: () => duckd(["rkp-renewal", "status"], { schema: statusSchema }),
  /** Sends the issuer's acknowledgement: renewals later run without the user present. */
  enable: (options: RenewalOptions) => {
    const fingerprint = options.fingerprint.trim()
    return duckd(["rkp-renewal", "enable"], {
      input: {
        run_dir: options.runDir,
        protocol: options.protocol,
        include_fingerprint: options.includeFingerprint,
        fingerprint: fingerprint || null,
        acknowledge_limitations: true,
      },
      schema: statusSchema.refine(
        (data) =>
          data.plan?.protocol === options.protocol &&
          data.plan.include_fingerprint === options.includeFingerprint &&
          data.plan.fingerprint === (fingerprint || null),
        { message: "Saved renewal plan disagrees with the requested issuance options" },
      ),
    })
  },
  disable: () => duckd(["rkp-renewal", "disable"], { schema: statusSchema }),
  renewNow: () => duckd(["rkp-renewal", "tick", "--force"], { schema: tickSchema }),
}
