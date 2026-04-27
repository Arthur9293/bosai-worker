import Link from "next/link";
import { headers } from "next/headers";

export const dynamic = "force-dynamic";

type JsonRecord = Record<string, unknown>;

type PageProps = {
  params:
    | Promise<{
        id: string;
      }>
    | {
        id: string;
      };
  searchParams?:
    | Promise<Record<string, string | string[] | undefined>>
    | Record<string, string | string[] | undefined>;
};

function asRecord(value: unknown): JsonRecord {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value as JsonRecord;
  }

  return {};
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function stringValue(value: unknown, fallback = "—"): string {
  if (typeof value === "string" && value.trim()) return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return fallback;
}

function boolLabel(value: unknown): string {
  return value === true ? "TRUE" : value === false ? "FALSE" : "—";
}

function firstParam(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) return value[0];
  return value;
}

function getNested(record: JsonRecord, path: string[]): unknown {
  let current: unknown = record;

  for (const part of path) {
    if (!current || typeof current !== "object" || Array.isArray(current)) {
      return undefined;
    }

    current = (current as JsonRecord)[part];
  }

  return current;
}

function getBaseUrlFromHeaders(requestHeaders: Headers): string {
  const host =
    requestHeaders.get("x-forwarded-host") ||
    requestHeaders.get("host") ||
    process.env.VERCEL_URL ||
    "localhost:3000";

  const protocol =
    requestHeaders.get("x-forwarded-proto") ||
    (host.includes("localhost") ? "http" : "https");

  return `${protocol}://${host}`;
}

function badgeClass(kind: "green" | "cyan" | "amber" | "red" | "neutral") {
  const base =
    "inline-flex items-center rounded-full border px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.18em]";

  if (kind === "green") {
    return `${base} border-emerald-400/30 bg-emerald-400/10 text-emerald-200`;
  }

  if (kind === "cyan") {
    return `${base} border-cyan-400/30 bg-cyan-400/10 text-cyan-200`;
  }

  if (kind === "amber") {
    return `${base} border-amber-400/30 bg-amber-400/10 text-amber-200`;
  }

  if (kind === "red") {
    return `${base} border-red-400/30 bg-red-400/10 text-red-200`;
  }

  return `${base} border-white/10 bg-white/[0.04] text-zinc-300`;
}

function statusKind(status: unknown): "green" | "cyan" | "amber" | "red" | "neutral" {
  const value = stringValue(status, "").toUpperCase();

  if (value.includes("READY") || value.includes("CONFIRMED") || value.includes("VALIDATED")) {
    return "green";
  }

  if (value.includes("REVIEW") || value.includes("DRY_RUN") || value.includes("DRY-RUN")) {
    return "cyan";
  }

  if (value.includes("UNSUPPORTED") || value.includes("NOT_VERIFIED")) {
    return "amber";
  }

  if (
    value.includes("FAILED") ||
    value.includes("MISSING") ||
    value.includes("NOT_FOUND") ||
    value.includes("NOT_SAFE") ||
    value.includes("NOT_OK")
  ) {
    return "red";
  }

  return "neutral";
}

function Badge({
  children,
  kind = "neutral",
}: {
  children: React.ReactNode;
  kind?: "green" | "cyan" | "amber" | "red" | "neutral";
}) {
  return <span className={badgeClass(kind)}>{children}</span>;
}

function Section({
  title,
  eyebrow,
  children,
  tone = "neutral",
}: {
  title: string;
  eyebrow?: string;
  children: React.ReactNode;
  tone?: "green" | "cyan" | "amber" | "red" | "neutral";
}) {
  const border =
    tone === "green"
      ? "border-emerald-400/20"
      : tone === "cyan"
        ? "border-cyan-400/20"
        : tone === "amber"
          ? "border-amber-400/20"
          : tone === "red"
            ? "border-red-400/20"
            : "border-white/10";

  return (
    <section className={`rounded-[28px] border ${border} bg-zinc-950/70 p-5 shadow-2xl shadow-black/20`}>
      {eyebrow ? (
        <p className="mb-2 text-[11px] font-semibold uppercase tracking-[0.22em] text-zinc-500">
          {eyebrow}
        </p>
      ) : null}

      <h2 className="text-lg font-semibold text-white">{title}</h2>

      <div className="mt-5">{children}</div>
    </section>
  );
}

function KeyValue({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: unknown;
  mono?: boolean;
}) {
  return (
    <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
      <div className="text-[11px] font-semibold uppercase tracking-[0.18em] text-zinc-500">
        {label}
      </div>
      <div
        className={`mt-2 break-all text-sm text-zinc-100 ${
          mono ? "font-mono" : ""
        }`}
      >
        {stringValue(value)}
      </div>
    </div>
  );
}

function BooleanRow({ label, value }: { label: string; value: unknown }) {
  const isTrue = value === true;

  return (
    <div className="flex items-center justify-between gap-4 rounded-2xl border border-white/10 bg-white/[0.03] px-4 py-3">
      <span className="break-all text-sm text-zinc-300">{label}</span>
      <span
        className={
          isTrue
            ? "rounded-full border border-emerald-400/25 bg-emerald-400/10 px-3 py-1 text-xs font-semibold text-emerald-200"
            : "rounded-full border border-red-400/25 bg-red-400/10 px-3 py-1 text-xs font-semibold text-red-200"
        }
      >
        {boolLabel(value)}
      </span>
    </div>
  );
}

function JsonBlock({ value }: { value: unknown }) {
  return (
    <div className="overflow-x-auto rounded-2xl border border-white/10 bg-black/50 p-4">
      <pre className="min-w-full whitespace-pre-wrap break-all font-mono text-xs leading-relaxed text-zinc-300">
        {JSON.stringify(value, null, 2)}
      </pre>
    </div>
  );
}

function Grid({ children }: { children: React.ReactNode }) {
  return <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">{children}</div>;
}

function NavigationLinks({
  incidentId,
  workspaceId,
}: {
  incidentId: string;
  workspaceId: string;
}) {
  const suffix = `?workspace_id=${encodeURIComponent(workspaceId)}`;

  const links = [
    ["Retour incident", `/incidents/${encodeURIComponent(incidentId)}${suffix}`],
    [
      "Retour V5.25 gated post run persistence",
      `/incidents/${encodeURIComponent(incidentId)}/gated-post-run-persistence${suffix}`,
    ],
    [
      "Retour V5.24 controlled post run preview",
      `/incidents/${encodeURIComponent(incidentId)}/controlled-post-run-preview${suffix}`,
    ],
    [
      "Retour V5.23 run draft review",
      `/incidents/${encodeURIComponent(incidentId)}/run-draft-review-surface${suffix}`,
    ],
    [
      "Retour V5.22 gated run draft persistence",
      `/incidents/${encodeURIComponent(incidentId)}/gated-run-draft-persistence${suffix}`,
    ],
    [
      "Retour V5.21 run creation preview",
      `/incidents/${encodeURIComponent(incidentId)}/run-creation-preview${suffix}`,
    ],
    [
      "Retour V5.20 operational queue review",
      `/incidents/${encodeURIComponent(incidentId)}/operational-queue-review-after-persistence${suffix}`,
    ],
    [
      "Retour V5.19 gated operational queue persistence",
      `/incidents/${encodeURIComponent(incidentId)}/gated-operational-queue-persistence${suffix}`,
    ],
    [
      "Retour V5.18 operational queue transition preview",
      `/incidents/${encodeURIComponent(incidentId)}/operational-queue-transition-preview${suffix}`,
    ],
    [
      "Retour V5.17 operational queue readiness",
      `/incidents/${encodeURIComponent(incidentId)}/operational-queue-readiness-review${suffix}`,
    ],
    [
      "Retour V5.16 gated queue persistence",
      `/incidents/${encodeURIComponent(incidentId)}/gated-command-queue-persistence${suffix}`,
    ],
    [
      "Retour V5.15 controlled queue preview",
      `/incidents/${encodeURIComponent(incidentId)}/controlled-command-queue-preview${suffix}`,
    ],
    [
      "Retour V5.14 command draft review",
      `/incidents/${encodeURIComponent(incidentId)}/command-draft-review${suffix}`,
    ],
    [
      "Retour V5.13 command draft persistence",
      `/incidents/${encodeURIComponent(incidentId)}/gated-command-draft-persistence${suffix}`,
    ],
    [
      "Retour V5.12 command draft preview",
      `/incidents/${encodeURIComponent(incidentId)}/operator-approved-command-draft-preview${suffix}`,
    ],
    [
      "Retour V5.11 approval persistence",
      `/incidents/${encodeURIComponent(incidentId)}/gated-operator-approval-persistence${suffix}`,
    ],
    [
      "Retour V5.10 approval draft",
      `/incidents/${encodeURIComponent(incidentId)}/operator-approval-draft${suffix}`,
    ],
    [
      "Retour V5.9 intent review",
      `/incidents/${encodeURIComponent(incidentId)}/operator-intent-review${suffix}`,
    ],
    [
      "Retour V5.8 gated persistence",
      `/incidents/${encodeURIComponent(incidentId)}/gated-audited-intent-persistence${suffix}`,
    ],
  ];

  return (
    <div className="grid gap-3 md:grid-cols-2">
      {links.map(([label, href]) => (
        <Link
          key={href}
          href={href}
          className="rounded-2xl border border-white/10 bg-white/[0.03] px-4 py-3 text-sm text-zinc-300 transition hover:border-cyan-400/30 hover:bg-cyan-400/10 hover:text-cyan-100"
        >
          {label}
        </Link>
      ))}
    </div>
  );
}

export default async function PostRunDryRunResultReviewPage(props: PageProps) {
  const params = await props.params;
  const searchParams = props.searchParams ? await props.searchParams : {};

  const incidentId = params.id;
  const workspaceId = firstParam(searchParams.workspace_id) || "default";

  const requestHeaders = await headers();
  const baseUrl = getBaseUrlFromHeaders(requestHeaders);

  const apiUrl = `${baseUrl}/api/incidents/${encodeURIComponent(
    incidentId
  )}/post-run-dry-run-result-review?workspace_id=${encodeURIComponent(
    workspaceId
  )}`;

  const response = await fetch(apiUrl, {
    method: "GET",
    cache: "no-store",
  });

  const payload = asRecord(await response.json().catch(() => ({})));

  const status = stringValue(payload.status);
  const workerResult = asRecord(payload.worker_dry_run_result);
  const check = asRecord(payload.dry_run_result_review_check);
  const interpretation = asRecord(payload.interpretation);
  const externalReview = asRecord(payload.external_execution_review);
  const guardrails = asRecord(payload.guardrails);
  const persistedRunSnapshot = asRecord(payload.persisted_run_snapshot);
  const persistedCommandSnapshot = asRecord(payload.persisted_command_snapshot);

  return (
    <main className="min-h-screen bg-[radial-gradient(circle_at_top,_rgba(34,211,238,0.14),_transparent_30%),linear-gradient(180deg,_#020617,_#050505)] px-4 py-6 text-zinc-100 md:px-8 lg:px-12">
      <div className="mx-auto flex w-full max-w-7xl flex-col gap-6">
        <section className="rounded-[32px] border border-cyan-400/20 bg-zinc-950/80 p-6 shadow-2xl shadow-cyan-950/20">
          <div className="flex flex-col gap-5">
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-cyan-300/80">
                BOSAI Control Plane · Incident Detail V5.26
              </p>
              <h1 className="mt-3 text-3xl font-semibold tracking-tight text-white md:text-5xl">
                Review résultat POST /run dry-run
              </h1>
              <p className="mt-4 max-w-3xl text-sm leading-6 text-zinc-400">
                Surface read-only. Relit le résultat dry-run persisté par V5.25.1.
                Aucun nouveau POST /run. Aucun appel worker depuis cette page. Aucune
                mutation Airtable.
              </p>
            </div>

            <div className="flex flex-wrap gap-2">
              <Badge kind="cyan">Incident Detail V5.26</Badge>
              <Badge kind={statusKind(status)}>{status}</Badge>
              <Badge kind="green">REVIEW ONLY</Badge>
              <Badge kind="cyan">DRY-RUN SENT</Badge>
              <Badge kind="green">WORKER 200</Badge>
              <Badge kind="amber">NO REAL RUN</Badge>
            </div>

            <button
              disabled
              className="w-full rounded-2xl border border-amber-400/20 bg-amber-400/10 px-4 py-3 text-sm font-semibold text-amber-200 opacity-80 md:w-fit"
            >
              Real execution future non activée
            </button>
          </div>
        </section>

        <Section title="Previous Layer Validated" tone="green">
          <Grid>
            <KeyValue label="Layer" value="Incident Detail V5.25.1" />
            <KeyValue
              label="Alignment"
              value="Strict Worker RunRequest Body Alignment validée"
            />
            <KeyValue label="Worker POST /run dry-run" value="Envoyé" />
            <KeyValue label="Worker response" value="HTTP 200" />
            <KeyValue label="Real execution" value="No real execution" />
            <KeyValue label="Next diagnostic" value="Unsupported command" />
          </Grid>
        </Section>

        <Section title="Dashboard Run Draft" tone="cyan">
          <Grid>
            <KeyValue label="Run Record ID" value={payload.run_record_id} mono />
            <KeyValue label="Run Draft ID" value={payload.run_draft_id} mono />
            <KeyValue label="Run Idempotency Key" value={payload.run_idempotency_key} mono />
            <KeyValue label="Run Status" value={persistedRunSnapshot.status} />
            <KeyValue label="Run Status_select" value={persistedRunSnapshot.status_select} />
            <KeyValue label="Command Record ID" value={payload.command_record_id} mono />
            <KeyValue label="Command ID" value={payload.command_id} mono />
            <KeyValue label="Workspace ID" value={payload.workspace_id} mono />
            <KeyValue label="Incident ID" value={payload.incident_id} mono />
          </Grid>
        </Section>

        <Section title="Worker Dry-run Result" tone="green">
          <Grid>
            <KeyValue label="Worker" value={workerResult.worker} />
            <KeyValue label="Worker Run ID" value={workerResult.worker_run_id} mono />
            <KeyValue
              label="Worker Airtable Record ID"
              value={workerResult.worker_airtable_record_id}
              mono
            />
            <KeyValue label="HTTP Status" value={workerResult.http_status} />
            <KeyValue label="Capability" value={workerResult.capability} mono />
            <KeyValue label="Workspace" value={workerResult.workspace_id} mono />
            <KeyValue label="Selection mode" value={workerResult.selection_mode} />
            <KeyValue label="View" value={workerResult.view} />
            <KeyValue
              label="Usage Ledger Record ID"
              value={workerResult.usage_ledger_record_id}
              mono
            />
          </Grid>
        </Section>

        <Section title="Command Scan Summary" tone="amber">
          <Grid>
            <KeyValue label="Scanned" value={workerResult.scanned} />
            <KeyValue label="Executed" value={workerResult.executed} />
            <KeyValue label="Succeeded" value={workerResult.succeeded} />
            <KeyValue label="Failed" value={workerResult.failed} />
            <KeyValue label="Blocked" value={workerResult.blocked} />
            <KeyValue label="Unsupported" value={workerResult.unsupported} />
            <KeyValue label="Errors count" value={workerResult.errors_count} />
          </Grid>

          <div className="mt-4">
            <JsonBlock value={workerResult.commands_record_ids ?? []} />
          </div>
        </Section>

        <Section title="Dry-run Result Review Check" tone="green">
          <div className="grid gap-3 md:grid-cols-2">
            {Object.entries(check).map(([key, value]) => (
              <BooleanRow key={key} label={key} value={value} />
            ))}
          </div>
        </Section>

        <Section title="Interpretation" tone="amber">
          <div className="grid gap-3">
            <KeyValue label="Summary" value={interpretation.summary} />
            <KeyValue label="Result meaning" value={interpretation.result_meaning} />
            <BooleanRow
              label="unsupported_is_blocking_for_real_execution"
              value={interpretation.unsupported_is_blocking_for_real_execution}
            />
            <BooleanRow
              label="unsupported_fix_required_before_real_execution"
              value={interpretation.unsupported_fix_required_before_real_execution}
            />
          </div>

          <div className="mt-5 grid gap-3 md:grid-cols-2 lg:grid-cols-4">
            <Badge kind="green">transport OK</Badge>
            <Badge kind="green">auth OK</Badge>
            <Badge kind="green">strict body OK</Badge>
            <Badge kind="green">workspace routing OK</Badge>
            <Badge kind="green">worker response OK</Badge>
            <Badge kind="green">command scanned OK</Badge>
            <Badge kind="amber">unsupported = prochain diagnostic</Badge>
            <Badge kind="red">pas d’exécution réelle</Badge>
          </div>
        </Section>

        <Section title="External Execution Boundary" tone="cyan">
          <Grid>
            <KeyValue
              label="previous_worker_dry_run_call"
              value={externalReview.previous_worker_dry_run_call}
            />
            <KeyValue
              label="post_run_from_this_surface"
              value={externalReview.post_run_from_this_surface}
            />
            <KeyValue
              label="worker_call_from_this_surface"
              value={externalReview.worker_call_from_this_surface}
            />
            <KeyValue
              label="external_worker_execution"
              value={externalReview.external_worker_execution}
            />
            <KeyValue
              label="external_scheduler_effect"
              value={externalReview.external_scheduler_effect}
            />
          </Grid>

          <div className="mt-4">
            <KeyValue label="Note" value={externalReview.note} />
          </div>
        </Section>

        <Section title="Future Requirements" tone="neutral">
          <div className="grid gap-3">
            {asArray(payload.future_requirements).map((item, index) => (
              <div
                key={`${String(item)}-${index}`}
                className="rounded-2xl border border-white/10 bg-white/[0.03] px-4 py-3 text-sm text-zinc-300"
              >
                {String(item)}
              </div>
            ))}
          </div>
        </Section>

        <Section title="Execution Lock" tone="red">
          <div className="flex flex-wrap gap-2">
            <Badge kind="green">REVIEW ONLY</Badge>
            <Badge kind="cyan">DRY-RUN RESULT</Badge>
            <Badge kind="amber">NO NEW POST /RUN</Badge>
            <Badge kind="amber">NO WORKER CALL FROM THIS SURFACE</Badge>
            <Badge kind="red">NO REAL RUN</Badge>
            <Badge kind="green">NO SECRET EXPOSURE</Badge>
            <Badge kind="amber">UNSUPPORTED DIAGNOSIS NEXT</Badge>
          </div>

          <div className="mt-5 grid gap-3 md:grid-cols-2">
            {Object.entries(guardrails).map(([key, value]) => (
              <KeyValue key={key} label={key} value={value} />
            ))}
          </div>
        </Section>

        <Section title="Queued Command Source" tone="neutral">
          <Grid>
            <KeyValue
              label="Command Record ID"
              value={payload.command_record_id}
              mono
            />
            <KeyValue
              label="Command ID"
              value={persistedCommandSnapshot.command_id}
              mono
            />
            <KeyValue
              label="Command Status"
              value={persistedCommandSnapshot.status}
            />
            <KeyValue
              label="Command Status_select"
              value={persistedCommandSnapshot.status_select}
            />
            <KeyValue
              label="Capability"
              value={persistedCommandSnapshot.capability}
              mono
            />
            <KeyValue
              label="Source Layer"
              value={persistedCommandSnapshot.source_layer}
            />
          </Grid>
        </Section>

        <Section title="Read-only Dry-run Result Review Payload" tone="cyan">
          <JsonBlock value={payload} />
        </Section>

        <Section title="Navigation" tone="neutral">
          <NavigationLinks incidentId={incidentId} workspaceId={workspaceId} />
        </Section>
      </div>
    </main>
  );
}
