<script setup lang="ts">
import { useMutation, useQuery, useQueryClient } from "@tanstack/vue-query"
import { CalendarClock, RotateCw, TriangleAlert } from "@lucide/vue"
import { computed, ref } from "vue"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Spinner } from "@/components/ui/spinner"
import ConfirmDialog from "@/core/components/ConfirmDialog.vue"
import KeyValueList from "@/core/components/KeyValueList.vue"
import SectionCard from "@/core/components/SectionCard.vue"
import { bridge } from "@/core/bridge"
import { featureManifest, isDuckError } from "@/core/duckd"
import { formatDateTime } from "@/core/format"
import { errorTitle, notifyError, notifySuccess } from "@/core/notify"

import type { Protocol, Provision } from "../api"
import { useRkpDeviceI18n } from "../i18n"
import { RENEWAL_FEATURE, RENEWAL_STATUS_KEY, renewalApi } from "../renewal"
import type { RenewalStatus } from "../renewal"

const props = defineProps<{
  /** The keybox issued on this page, which renewal can start tracking. */
  result: Provision | null
  protocol: Protocol
  includeFingerprint: boolean
  fingerprint: string
}>()

const { t, dynamic } = useRkpDeviceI18n()
const queryClient = useQueryClient()

// The same cached manifest the home page reads; renewal needs a backend that has it.
const manifest = useQuery({
  queryKey: ["features"],
  queryFn: featureManifest,
  enabled: bridge().available,
  staleTime: Number.POSITIVE_INFINITY,
})
const supported = computed(() =>
  manifest.data.value?.features.some(
    (feature) => feature.id === RENEWAL_FEATURE.id && feature.contract === RENEWAL_FEATURE.contract,
  ),
)
const status = useQuery({
  queryKey: RENEWAL_STATUS_KEY,
  queryFn: renewalApi.status,
  enabled: supported,
  staleTime: 0,
})
const plan = computed(() => status.data.value?.plan ?? null)
const state = computed(() => status.data.value?.state ?? "off")

function store(data: RenewalStatus) {
  queryClient.setQueryData(RENEWAL_STATUS_KEY, data)
}

function failed(error: unknown) {
  void status.refetch()
  notifyError(
    error,
    isDuckError(error) ? dynamic(`errors.${error.code}`, errorTitle(error)) : errorTitle(error),
  )
}

const confirmOpen = ref(false)
const enable = useMutation({
  mutationFn: () =>
    renewalApi.enable({
      runDir: props.result!.artifacts.run_dir,
      protocol: props.protocol,
      includeFingerprint: props.includeFingerprint,
      fingerprint: props.fingerprint,
    }),
  onSuccess: (data) => {
    store(data)
    notifySuccess(t("renewal.enabled"))
  },
  onError: failed,
})
const disable = useMutation({
  mutationFn: renewalApi.disable,
  onSuccess: (data) => {
    store(data)
    notifySuccess(t("renewal.disabled"))
  },
  onError: failed,
})
const renewNow = useMutation({
  mutationFn: renewalApi.renewNow,
  onSuccess: (data) => {
    store(data.status)
    notifySuccess(t("renewal.renewed"))
  },
  onError: failed,
})
const busy = computed(
  () => enable.isPending.value || disable.isPending.value || renewNow.isPending.value,
)

const tracking = computed(() => state.value === "scheduled" || state.value === "retrying")
/** This page's keybox can become the tracked one: nothing is tracked, or another is. */
const canTrackResult = computed(
  () =>
    !!props.result && (!tracking.value || plan.value?.run_dir !== props.result.artifacts.run_dir),
)

const badge = computed(
  () =>
    ({
      off: null,
      scheduled: { label: t("renewal.scheduled"), variant: "secondary" as const },
      retrying: { label: t("renewal.retrying"), variant: "destructive" as const },
      superseded: { label: t("renewal.superseded"), variant: "outline" as const },
    })[state.value],
)

const rows = computed(() => {
  const data = plan.value
  if (!data || state.value === "superseded") return []
  const never = t("renewal.never")
  const attempt = data.last_attempt
  return [
    { label: t("renewal.expires"), value: formatDateTime(data.not_after_unix) },
    { label: t("renewal.nextAttempt"), value: formatDateTime(data.next_attempt_unix) },
    {
      label: t("renewal.lastRenewed"),
      value: data.last_renewed_at_unix ? formatDateTime(data.last_renewed_at_unix) : never,
    },
    ...(attempt && !attempt.ok
      ? [{ label: t("renewal.lastError"), value: `[${attempt.code}] ${attempt.message}` }]
      : []),
    {
      label: t("run.protocol"),
      value: { auto: t("run.auto"), v1: "V1 AIDL", v2: "CSR_V2", "v1-native": "V1 Native" }[
        data.protocol
      ],
    },
    { label: t("renewal.runDir"), value: data.run_dir, mono: true, copy: true },
  ]
})
</script>

<template>
  <SectionCard
    v-if="supported && status.data.value"
    :title="t('renewal.title')"
    :description="t('renewal.description')"
  >
    <template v-if="badge" #action>
      <Badge :variant="badge.variant">{{ badge.label }}</Badge>
    </template>

    <div class="flex flex-col gap-4">
      <Alert v-if="state === 'superseded'">
        <TriangleAlert />
        <AlertTitle>{{ t("renewal.supersededTitle") }}</AlertTitle>
        <AlertDescription>{{ t("renewal.supersededBody") }}</AlertDescription>
      </Alert>

      <KeyValueList v-if="rows.length" :rows="rows" />

      <p v-if="!result && !plan" class="text-muted-foreground text-sm">
        {{ t("renewal.issueFirst") }}
      </p>

      <template v-if="canTrackResult">
        <p class="text-muted-foreground text-sm">{{ t("renewal.installFirst") }}</p>
        <Button size="lg" :disabled="busy" @click="confirmOpen = true">
          <Spinner v-if="enable.isPending.value" class="size-6" />
          <CalendarClock v-else />
          {{ plan ? t("renewal.trackThis") : t("renewal.enable") }}
        </Button>
      </template>

      <div v-if="plan" class="flex flex-col gap-2">
        <Button
          v-if="tracking"
          variant="outline"
          size="lg"
          :disabled="busy"
          @click="renewNow.mutate()"
        >
          <Spinner v-if="renewNow.isPending.value" class="size-6" />
          <RotateCw v-else />
          {{ t("renewal.renewNow") }}
        </Button>
        <Button variant="ghost" size="lg" :disabled="busy" @click="disable.mutate()">
          <Spinner v-if="disable.isPending.value" class="size-6" />
          {{ t("renewal.disable") }}
        </Button>
      </div>
    </div>

    <ConfirmDialog
      v-model:open="confirmOpen"
      :title="t('renewal.confirmTitle')"
      :description="t('renewal.confirmBody')"
      :confirm-label="t('renewal.enable')"
      @confirm="enable.mutate()"
    />
  </SectionCard>
</template>
