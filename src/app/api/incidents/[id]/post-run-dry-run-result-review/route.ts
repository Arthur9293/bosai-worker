import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

type RouteContext = {
  params:
    | Promise<{
        id: string;
      }>
    | {
        id: string;
      };
};

type JsonRecord = Record<string, unknown>;

type AirtableRecord = {
  id: string;
  fields: JsonRecord;
};

type AirtableReadResult = {
  http_status: number | null;
  record_id: string | null;
  record: AirtableRecord | null;
  error: string | null;
};

const VERSION = "Incident Detail V5.26";
const SOURCE = "dashboard_incident_detail_v5_26_post_run_dry_run_result_review";
const MODE = "POST_RUN_DRY_RUN_RESULT_REVIEW_ONLY";

function jsonResponse(payload: JsonRecord, status = 200) {
  return NextResponse.json(payload, {
    status,
    headers: {
      "Cache-Control": "no-store",
    },
  });
}

function getEnv(name: string): string {
  return process.env[name]?.trim() ?? "";
}

function getAirtableConfig() {
  const token =
    getEnv("AIRTABLE_API_KEY") ||
    getEnv("AIRTABLE_TOKEN") ||
    getEnv("AIRTABLE_PAT");

  return {
    baseId: getEnv("AIRTABLE_BASE_ID"),
    token,
    operatorIntentsTable:
      getEnv("AIRTABLE_OPERATOR_INTENTS_TABLE") || "Operator_Intents",
    operatorApprovalsTable:
      getEnv("AIRTABLE_OPERATOR_APPROVALS_TABLE") || "Operator_Approvals",
    commandsTable: getEnv("AIRTABLE_COMMANDS_TABLE") || "Commands",
    runsTable:
      getEnv("AIRTABLE_SYSTEM_RUNS_TABLE") ||
      getEnv("AIRTABLE_RUNS_TABLE") ||
      "System_Runs",
  };
}

function airtableConfigPublic(config: ReturnType<typeof getAirtableConfig>) {
  return {
    base_id: config.baseId ? "CONFIGURED" : "MISSING",
    operator_intents_table: config.operatorIntentsTable,
    operator_approvals_table: config.operatorApprovalsTable,
    commands_table: config.commandsTable,
    runs_table: config.runsTable,
    token: config.token ? "CONFIGURED" : "MISSING",
    token_value: "SERVER_SIDE_ONLY_NOT_EXPOSED",
  };
}

function escapeFormulaValue(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
}

function airtableUrl(baseId: string, tableName: string): string {
  return `https://api.airtable.com/v0/${encodeURIComponent(
    baseId
  )}/${encodeURIComponent(tableName)}`;
}

function airtableHeaders(token: string) {
  return {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
  };
}

function safeParseJson(value: unknown): unknown {
  if (typeof value !== "string") return null;

  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function asRecord(value: unknown): JsonRecord {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value as JsonRecord;
  }

  return {};
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function stringField(fields: JsonRecord, names: string[], fallback = ""): string {
  for (const name of names) {
    const value = fields[name];

    if (typeof value === "string") return value;
    if (typeof value === "number" || typeof value === "boolean") {
      return String(value);
    }
  }

  return fallback;
}

function booleanField(
  fields: JsonRecord,
  names: string[],
  fallback = false
): boolean {
  for (const name of names) {
    const value = fields[name];

    if (typeof value === "boolean") return value;

    if (typeof value === "string") {
      const normalized = value.trim().toLowerCase();
      if (["true", "1", "yes", "on"].includes(normalized)) return true;
      if (["false", "0", "no", "off"].includes(normalized)) return false;
    }
  }

  return fallback;
}

function numberFrom(value: unknown, fallback = 0): number {
  if (typeof value === "number" && Number.isFinite(value)) return value;

  if (typeof value === "string") {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }

  return fallback;
}

function nestedValue(record: JsonRecord, path: string[]): unknown {
  let current: unknown = record;

  for (const part of path) {
    if (!current || typeof current !== "object" || Array.isArray(current)) {
      return undefined;
    }

    current = (current as JsonRecord)[part];
  }

  return current;
}

function nestedRecord(record: JsonRecord, path: string[]): JsonRecord {
  return asRecord(nestedValue(record, path));
}

function nestedString(record: JsonRecord, path: string[], fallback = ""): string {
  const value = nestedValue(record, path);

  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);

  return fallback;
}

function nestedBoolean(
  record: JsonRecord,
  path: string[],
  fallback = false
): boolean {
  const value = nestedValue(record, path);

  if (typeof value === "boolean") return value;

  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (["true", "1", "yes", "on"].includes(normalized)) return true;
    if (["false", "0", "no", "off"].includes(normalized)) return false;
  }

  return fallback;
}

function sanitizeErrorText(value: unknown): string {
  if (typeof value === "string") {
    return value
      .replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [REDACTED]")
      .replace(/"apiKey"\s*:\s*"[^"]+"/gi, '"apiKey":"[REDACTED]"')
      .replace(/"token"\s*:\s*"[^"]+"/gi, '"token":"[REDACTED]"')
      .slice(0, 4000);
  }

  if (value instanceof Error) {
    return value.message.slice(0, 4000);
  }

  try {
    return JSON.stringify(value).slice(0, 4000);
  } catch {
    return "Unknown error";
  }
}

function sanitizeObject(value: unknown, depth = 0): unknown {
  if (depth > 10) return "[MAX_DEPTH_REDACTED]";

  if (Array.isArray(value)) {
    return value.map((item) => sanitizeObject(item, depth + 1));
  }

  if (value && typeof value === "object") {
    const output: JsonRecord = {};

    for (const [key, raw] of Object.entries(value as JsonRecord)) {
      if (/secret|token|authorization|password|credential|api[_-]?key/i.test(key)) {
        output[key] = "SERVER_SIDE_ONLY_NOT_EXPOSED";
      } else {
        output[key] = sanitizeObject(raw, depth + 1);
      }
    }

    return output;
  }

  if (typeof value === "string") {
    return value.slice(0, 12000);
  }

  return value;
}

function parseInputJson(fields: JsonRecord): JsonRecord {
  const raw = stringField(fields, ["Input_JSON", "input_json"]);
  return asRecord(safeParseJson(raw));
}

function buildIds(workspaceId: string, incidentId: string) {
  return {
    intentId: `operator-intent:v5.4:${workspaceId}:${incidentId}`,
    intentIdempotencyKey: `dashboard:v5.8:gated-audited-intent-persistence:${workspaceId}:${incidentId}`,

    approvalId: `operator-approval:v5.11:${workspaceId}:${incidentId}`,
    approvalIdempotencyKey: `dashboard:v5.11:gated-operator-approval-persistence:${workspaceId}:${incidentId}`,

    commandDraftId: `command-draft:v5.13:${workspaceId}:${incidentId}`,
    commandIdempotencyKey: `dashboard:v5.13:gated-command-draft-persistence:${workspaceId}:${incidentId}`,

    operationalQueueTransitionId: `operational-queue-transition:v5.19:${workspaceId}:${incidentId}`,
    operationalQueueTransitionIdempotencyKey: `dashboard:v5.19:gated-operational-queue-persistence:${workspaceId}:${incidentId}`,

    runDraftId: `run-draft:v5.22:${workspaceId}:${incidentId}`,
    runIdempotencyKey: `dashboard:v5.22:gated-run-draft-persistence:${workspaceId}:${incidentId}`,
  };
}

function getWorkspaceId(request: Request): string {
  const url = new URL(request.url);

  return (
    url.searchParams.get("workspace_id") ||
    url.searchParams.get("workspaceId") ||
    "default"
  ).trim();
}

async function findRecordByIdempotencyKey(args: {
  baseId: string;
  token: string;
  tableName: string;
  idempotencyKey: string;
}): Promise<AirtableReadResult> {
  const formula = `{Idempotency_Key}='${escapeFormulaValue(args.idempotencyKey)}'`;

  const url = `${airtableUrl(
    args.baseId,
    args.tableName
  )}?maxRecords=1&filterByFormula=${encodeURIComponent(formula)}`;

  try {
    const response = await fetch(url, {
      method: "GET",
      headers: airtableHeaders(args.token),
      cache: "no-store",
    });

    const text = await response.text();
    const parsed = asRecord(safeParseJson(text));

    if (!response.ok) {
      return {
        http_status: response.status,
        record_id: null,
        record: null,
        error: sanitizeErrorText(text),
      };
    }

    const records = Array.isArray(parsed.records)
      ? (parsed.records as AirtableRecord[])
      : [];

    const record = records[0] ?? null;

    return {
      http_status: response.status,
      record_id: record?.id ?? null,
      record,
      error: null,
    };
  } catch (error) {
    return {
      http_status: null,
      record_id: null,
      record: null,
      error: sanitizeErrorText(error),
    };
  }
}

export async function GET(request: Request, context: RouteContext) {
  const params = await context.params;
  const incidentId = params.id;
  const workspaceId = getWorkspaceId(request);

  const ids = buildIds(workspaceId, incidentId);
  const airtable = getAirtableConfig();

  const configMissing = !airtable.baseId || !airtable.token;

  const emptyRead: AirtableReadResult = {
    http_status: null,
    record_id: null,
    record: null,
    error: configMissing ? "Airtable config missing" : null,
  };

  let intentRead = emptyRead;
  let approvalRead = emptyRead;
  let commandRead = emptyRead;
  let runRead = emptyRead;

  if (!configMissing) {
    [intentRead, approvalRead, commandRead, runRead] = await Promise.all([
      findRecordByIdempotencyKey({
        baseId: airtable.baseId,
        token: airtable.token,
        tableName: airtable.operatorIntentsTable,
        idempotencyKey: ids.intentIdempotencyKey,
      }),
      findRecordByIdempotencyKey({
        baseId: airtable.baseId,
        token: airtable.token,
        tableName: airtable.operatorApprovalsTable,
        idempotencyKey: ids.approvalIdempotencyKey,
      }),
      findRecordByIdempotencyKey({
        baseId: airtable.baseId,
        token: airtable.token,
        tableName: airtable.commandsTable,
        idempotencyKey: ids.commandIdempotencyKey,
      }),
      findRecordByIdempotencyKey({
        baseId: airtable.baseId,
        token: airtable.token,
        tableName: airtable.runsTable,
        idempotencyKey: ids.runIdempotencyKey,
      }),
    ]);
  }

  const intentFields = intentRead.record?.fields ?? {};
  const approvalFields = approvalRead.record?.fields ?? {};
  const commandFields = commandRead.record?.fields ?? {};
  const runFields = runRead.record?.fields ?? {};

  const commandInputJson = parseInputJson(commandFields);
  const runInputJson = parseInputJson(runFields);

  const commandStatus = stringField(commandFields, ["Status", "status"]);
  const commandStatusSelect = stringField(commandFields, [
    "Status_select",
    "status_select",
  ]);

  const runStatus = stringField(runFields, ["Status", "status"]);
  const runStatusSelect = stringField(runFields, ["Status_select", "status_select"]);

  const previousPostRunStatus = nestedString(runInputJson, ["post_run_status"]);
  const previousWorkerCallStatus = nestedString(runInputJson, [
    "worker_call_status",
  ]);
  const previousRunExecutionStatus = nestedString(runInputJson, [
    "run_execution_status",
  ]);

  const workerResponseSanitized = nestedRecord(runInputJson, [
    "worker_response_sanitized",
  ]);
  const workerResponseBody = nestedRecord(workerResponseSanitized, ["body"]);
  const workerResult = nestedRecord(workerResponseBody, ["result"]);
  const usageLedgerWrite = nestedRecord(workerResult, ["usage_ledger_write"]);

  const commandsRecordIds = asArray(workerResult.commands_record_ids)
    .filter((item): item is string => typeof item === "string")
    .map((item) => item.trim())
    .filter(Boolean);

  const commandRecordId = commandRead.record_id ?? "";
  const runRecordId = runRead.record_id ?? "";

  const workerHttpStatus = numberFrom(workerResponseSanitized.http_status, 0);
  const workerBodyOk = workerResponseBody.ok === true;
  const workerResponseOk = workerResponseSanitized.ok === true;

  const scanned = numberFrom(workerResult.scanned, 0);
  const executed = numberFrom(workerResult.executed, 0);
  const succeeded = numberFrom(workerResult.succeeded, 0);
  const failed = numberFrom(workerResult.failed, 0);
  const blocked = numberFrom(workerResult.blocked, 0);
  const unsupported = numberFrom(workerResult.unsupported, 0);
  const errorsCount = numberFrom(workerResult.errors_count, 0);

  const persistedIntentSnapshot = intentRead.record
    ? {
        record_id: intentRead.record.id,
        idempotency_key: stringField(intentFields, ["Idempotency_Key"]),
        intent_id: stringField(intentFields, ["Intent_ID"], ids.intentId),
        workspace_id: stringField(intentFields, ["Workspace_ID"], workspaceId),
        incident_id: stringField(intentFields, ["Incident_ID"], incidentId),
        source_layer: stringField(intentFields, ["Source_Layer"], "Incident Detail V5.8"),
      }
    : null;

  const persistedApprovalSnapshot = approvalRead.record
    ? {
        record_id: approvalRead.record.id,
        idempotency_key: stringField(approvalFields, ["Idempotency_Key"]),
        approval_id: stringField(approvalFields, ["Approval_ID"], ids.approvalId),
        operator_identity: stringField(approvalFields, ["Operator_Identity"], "Arthur"),
        approval_status: stringField(approvalFields, ["Approval_Status"], "Approved"),
        operator_decision: stringField(approvalFields, ["Operator_Decision"]),
        approved_for_command_draft: booleanField(
          approvalFields,
          ["Approved_For_Command_Draft"],
          true
        ),
        source_layer: stringField(approvalFields, ["Source_Layer"], "Incident Detail V5.11"),
      }
    : null;

  const persistedCommandSnapshot = commandRead.record
    ? {
        record_id: commandRead.record.id,
        idempotency_key: stringField(commandFields, ["Idempotency_Key"]),
        command_id: stringField(commandFields, ["Command_ID"], ids.commandDraftId),
        workspace_id: stringField(commandFields, ["Workspace_ID"], workspaceId),
        incident_id: stringField(commandFields, ["Incident_ID"], incidentId),
        intent_id: stringField(commandFields, ["Intent_ID"], ids.intentId),
        intent_record_id: stringField(
          commandFields,
          ["Intent_Record_ID"],
          intentRead.record_id ?? ""
        ),
        approval_id: stringField(commandFields, ["Approval_ID"], ids.approvalId),
        approval_record_id: stringField(
          commandFields,
          ["Approval_Record_ID"],
          approvalRead.record_id ?? ""
        ),
        capability: stringField(commandFields, ["Capability"], "command_orchestrator"),
        status: commandStatus,
        status_select: commandStatusSelect,
        target_mode: stringField(commandFields, ["Target_Mode"], "dry_run_only"),
        dry_run: booleanField(commandFields, ["Dry_Run"], true),
        operator_identity: stringField(commandFields, ["Operator_Identity"], "Arthur"),
        queue_allowed: booleanField(commandFields, ["Queue_Allowed"], true),
        run_creation_allowed: booleanField(
          commandFields,
          ["Run_Creation_Allowed"],
          false
        ),
        worker_call_allowed: booleanField(
          commandFields,
          ["Worker_Call_Allowed"],
          false
        ),
        real_run: stringField(commandFields, ["Real_Run"], "Forbidden"),
        secret_exposure: "SERVER_SIDE_ONLY_REDACTED",
        source_layer: stringField(commandFields, ["Source_Layer"], "Incident Detail V5.19"),
      }
    : null;

  const persistedRunSnapshot = runRead.record
    ? {
        record_id: runRead.record.id,
        idempotency_key: stringField(runFields, ["Idempotency_Key"]),
        run_id: stringField(runFields, ["Run_ID"], ids.runDraftId),
        workspace_id: stringField(runFields, ["Workspace_ID"], workspaceId),
        incident_id: stringField(runFields, ["Incident_ID"], incidentId),
        command_id: stringField(runFields, ["Command_ID"], ids.commandDraftId),
        command_record_id: stringField(runFields, ["Command_Record_ID"], commandRecordId),
        intent_id: stringField(runFields, ["Intent_ID"], ids.intentId),
        intent_record_id: stringField(
          runFields,
          ["Intent_Record_ID"],
          intentRead.record_id ?? ""
        ),
        approval_id: stringField(runFields, ["Approval_ID"], ids.approvalId),
        approval_record_id: stringField(
          runFields,
          ["Approval_Record_ID"],
          approvalRead.record_id ?? ""
        ),
        operational_queue_transition_id: stringField(
          runFields,
          ["Operational_Queue_Transition_ID"],
          ids.operationalQueueTransitionId
        ),
        capability: stringField(runFields, ["Capability"], "command_orchestrator"),
        status: runStatus,
        status_select: runStatusSelect,
        dry_run: booleanField(runFields, ["Dry_Run"], true),
        operator_identity: stringField(runFields, ["Operator_Identity"], "Arthur"),
        run_persistence: stringField(runFields, ["Run_Persistence"], "Draft"),
        post_run_allowed: booleanField(runFields, ["Post_Run_Allowed"], false),
        worker_call_allowed: booleanField(runFields, ["Worker_Call_Allowed"], false),
        real_run: stringField(runFields, ["Real_Run"], "Forbidden"),
        secret_exposure: "SERVER_SIDE_ONLY_REDACTED",
        source_layer: stringField(runFields, ["Source_Layer"], "Incident Detail V5.25.1"),
      }
    : null;

  const workerDryRunResult = {
    http_status: workerHttpStatus || null,
    ok: workerResponseOk,
    worker: nestedString(workerResponseBody, ["worker"]),
    capability: nestedString(workerResponseBody, ["capability"]),
    worker_run_id: nestedString(workerResponseBody, ["run_id"]),
    worker_airtable_record_id: nestedString(workerResponseBody, [
      "airtable_record_id",
    ]),
    selection_mode: nestedString(workerResult, ["selection_mode"]),
    view: nestedString(workerResult, ["view"]),
    scanned,
    executed,
    succeeded,
    failed,
    blocked,
    unsupported,
    errors_count: errorsCount,
    workspace_id: nestedString(workerResult, ["workspace_id"], workspaceId),
    commands_record_ids: commandsRecordIds,
    usage_ledger_record_id: stringField(usageLedgerWrite, ["record_id"]),
  };

  const reviewCheck = {
    intent_found: Boolean(intentRead.record),
    approval_found: Boolean(approvalRead.record),
    command_found: Boolean(commandRead.record),
    run_found: Boolean(runRead.record),
    run_status_is_draft: runStatus === "Draft",
    command_status_is_queued: commandStatus === "Queued",
    post_run_status_is_sent: previousPostRunStatus === "POST_RUN_DRY_RUN_SENT",
    worker_call_status_is_sent: previousWorkerCallStatus === "DRY_RUN_CALL_SENT",
    run_execution_status_is_dry_run_only:
      previousRunExecutionStatus === "DRY_RUN_ONLY",
    worker_response_exists: Object.keys(workerResponseSanitized).length > 0,
    worker_response_http_200: workerHttpStatus === 200,
    worker_response_ok: workerResponseOk && workerBodyOk,
    worker_capability_is_command_orchestrator:
      nestedString(workerResponseBody, ["capability"]) === "command_orchestrator",
    worker_scanned_at_least_one_command: scanned >= 1,
    worker_command_record_seen: commandRecordId
      ? commandsRecordIds.includes(commandRecordId)
      : false,
    worker_executed_zero: executed === 0,
    worker_unsupported_one: unsupported === 1,
    worker_errors_zero: errorsCount === 0,
    real_run_forbidden: true,
    secret_exposure_disabled: true,
    no_post_run_by_this_surface: true,
    no_worker_called_by_this_surface: true,
    no_airtable_mutation_by_this_surface: true,
  };

  let status = "POST_RUN_DRY_RUN_RESULT_REVIEW_READY";

  if (configMissing) {
    status = "POST_RUN_DRY_RUN_RESULT_REVIEW_CONFIG_MISSING";
  } else if (
    intentRead.error ||
    approvalRead.error ||
    commandRead.error ||
    runRead.error
  ) {
    status = "POST_RUN_DRY_RUN_RESULT_REVIEW_READ_FAILED";
  } else if (!intentRead.record) {
    status = "OPERATOR_INTENT_DRAFT_NOT_FOUND";
  } else if (!approvalRead.record) {
    status = "OPERATOR_APPROVAL_NOT_FOUND";
  } else if (!commandRead.record) {
    status = "COMMAND_NOT_FOUND";
  } else if (!runRead.record) {
    status = "RUN_DRAFT_NOT_FOUND";
  } else if (
    previousPostRunStatus !== "POST_RUN_DRY_RUN_SENT" ||
    previousWorkerCallStatus !== "DRY_RUN_CALL_SENT" ||
    previousRunExecutionStatus !== "DRY_RUN_ONLY"
  ) {
    status = "POST_RUN_DRY_RUN_NOT_SENT";
  } else if (!reviewCheck.worker_response_exists) {
    status = "WORKER_RESPONSE_NOT_FOUND";
  } else if (!reviewCheck.worker_response_http_200 || !reviewCheck.worker_response_ok) {
    status = "WORKER_RESPONSE_NOT_OK";
  } else if (
    !reviewCheck.run_status_is_draft ||
    !reviewCheck.command_status_is_queued ||
    !reviewCheck.worker_capability_is_command_orchestrator ||
    !reviewCheck.worker_scanned_at_least_one_command ||
    !reviewCheck.worker_command_record_seen ||
    !reviewCheck.worker_executed_zero ||
    !reviewCheck.worker_unsupported_one ||
    !reviewCheck.worker_errors_zero
  ) {
    status = "POST_RUN_DRY_RUN_RESULT_REVIEW_NOT_SAFE";
  }

  return jsonResponse({
    ok: true,
    version: VERSION,
    source: SOURCE,
    status,
    mode: MODE,
    method: "GET",
    incident_id: incidentId,
    workspace_id: workspaceId,
    dry_run: true,

    intent_id: ids.intentId,
    intent_record_id: intentRead.record_id,
    approval_id: ids.approvalId,
    approval_record_id: approvalRead.record_id,

    command_record_id: commandRead.record_id,
    command_id: ids.commandDraftId,
    command_idempotency_key: ids.commandIdempotencyKey,

    operational_queue_transition_id: ids.operationalQueueTransitionId,
    operational_queue_transition_idempotency_key:
      ids.operationalQueueTransitionIdempotencyKey,

    run_draft_id: ids.runDraftId,
    run_record_id: runRead.record_id,
    run_idempotency_key: ids.runIdempotencyKey,

    previous_post_run_status: previousPostRunStatus || null,
    previous_worker_call_status: previousWorkerCallStatus || null,
    previous_run_execution_status: previousRunExecutionStatus || null,

    current_run_status: runStatus || null,
    current_run_status_select: runStatusSelect || null,
    current_command_status: commandStatus || null,
    current_command_status_select: commandStatusSelect || null,

    post_run_from_this_surface: "DISABLED",
    worker_call_from_this_surface: "DISABLED",
    previous_worker_dry_run_call:
      previousWorkerCallStatus === "DRY_RUN_CALL_SENT" ? "CONFIRMED" : "NOT_CONFIRMED",
    real_run_execution: "FORBIDDEN",
    external_worker_execution: "NOT_VERIFIED_FROM_THIS_SURFACE",
    external_scheduler_effect: "NOT_VERIFIED_FROM_THIS_SURFACE",

    previous_layer: {
      version: "Incident Detail V5.25.1",
      status: "POST_RUN_DRY_RUN_SENT",
      strict_worker_runrequest_body_alignment: "VALIDATED",
      execution_policy: "SERVER_SIDE_DRY_RUN_ONLY",
    },

    airtable_config: airtableConfigPublic(airtable),

    intent_read: {
      http_status: intentRead.http_status,
      record_id: intentRead.record_id,
      error: intentRead.error,
    },
    approval_read: {
      http_status: approvalRead.http_status,
      record_id: approvalRead.record_id,
      error: approvalRead.error,
    },
    command_read: {
      http_status: commandRead.http_status,
      record_id: commandRead.record_id,
      error: commandRead.error,
    },
    run_read: {
      http_status: runRead.http_status,
      record_id: runRead.record_id,
      error: runRead.error,
    },

    persisted_intent_snapshot: persistedIntentSnapshot,
    persisted_approval_snapshot: persistedApprovalSnapshot,
    persisted_command_snapshot: persistedCommandSnapshot,
    persisted_run_snapshot: persistedRunSnapshot,

    run_input_json:
      Object.keys(runInputJson).length > 0 ? sanitizeObject(runInputJson) : null,

    worker_dry_run_result: workerDryRunResult,

    dry_run_result_review_check: reviewCheck,

    interpretation: {
      summary:
        "The previous V5.25.1 dry-run POST /run reached the worker successfully. The worker scanned the queued command but did not execute it because it was unsupported in the current worker execution path.",
      result_meaning:
        "Dry-run transport, auth, strict body, workspace routing, and worker response are validated. Capability execution remains a separate future step.",
      unsupported_is_blocking_for_real_execution: true,
      unsupported_fix_required_before_real_execution: true,
    },

    external_execution_review: {
      previous_worker_dry_run_call:
        previousWorkerCallStatus === "DRY_RUN_CALL_SENT"
          ? "CONFIRMED"
          : "NOT_CONFIRMED",
      post_run_from_this_surface: "DISABLED",
      worker_call_from_this_surface: "DISABLED",
      external_worker_execution: "NOT_VERIFIED_FROM_THIS_SURFACE",
      external_scheduler_effect: "NOT_VERIFIED_FROM_THIS_SURFACE",
      note:
        "This surface reviews the previously persisted dry-run result only. It does not call the worker and does not inspect external scheduler activity.",
    },

    future_requirements: [
      "Review why command_orchestrator returned unsupported for the queued command",
      "Verify the command capability and worker allowlist before any real execution",
      "Keep real execution behind a separate feature gate",
      "Keep POST /run server-side only",
      "Keep worker secret server-side only",
      "Require explicit operator confirmation before any non-dry-run execution",
      "Add rollback or safe cancellation path before real execution",
      "Do not enable real run while unsupported remains unresolved",
    ],

    guardrails: {
      client_fetch: "DISABLED",
      airtable_mutation: "DISABLED",
      dashboard_airtable_mutation: "DISABLED",
      command_mutation: "DISABLED",
      run_mutation: "DISABLED",
      run_execution: "DISABLED",
      post_run: "DISABLED_FROM_THIS_SURFACE",
      worker_call: "DISABLED_FROM_THIS_SURFACE",
      real_run: "FORBIDDEN",
      secret_exposure: "DISABLED",
      review_only: true,
    },

    error:
      status === "POST_RUN_DRY_RUN_RESULT_REVIEW_READY"
        ? null
        : "Dry-run result review is not ready. Check status and read sections.",
    next_step:
      "V5.27 may introduce Unsupported Command Diagnosis, still without real execution.",
  });
}
