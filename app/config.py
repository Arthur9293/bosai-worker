import os


# ============================================================
# Application
# ============================================================

APP_NAME = os.getenv("APP_NAME", "bosai-worker").strip()
APP_VERSION = os.getenv("APP_VERSION", "2.5.5-rebuild").strip()
WORKER_NAME = os.getenv("WORKER_NAME", "bosai-worker-01").strip()


# ============================================================
# Airtable configuration
# ============================================================

AIRTABLE_API_KEY = os.getenv("AIRTABLE_API_KEY", "").strip()
AIRTABLE_BASE_ID = os.getenv("AIRTABLE_BASE_ID", "").strip()

SYSTEM_RUNS_TABLE_NAME = os.getenv("SYSTEM_RUNS_TABLE_NAME", "System_Runs").strip()
COMMANDS_TABLE_NAME = os.getenv("COMMANDS_TABLE_NAME", "Commands").strip()
EVENTS_TABLE_NAME = os.getenv("EVENTS_TABLE_NAME", "Events").strip()
LOGS_ERRORS_TABLE_NAME = os.getenv("LOGS_ERRORS_TABLE_NAME", "Logs_Erreurs").strip()
STATE_TABLE_NAME = os.getenv("STATE_TABLE_NAME", "State").strip()


# ============================================================
# Views
# ============================================================

SYSTEM_RUNS_VIEW_NAME = os.getenv("SYSTEM_RUNS_VIEW_NAME", "Grid view").strip()
COMMANDS_VIEW_NAME = os.getenv("COMMANDS_VIEW_NAME", "Queue").strip()
EVENTS_VIEW_NAME = os.getenv("EVENTS_VIEW_NAME", "Queue").strip()
LOGS_ERRORS_VIEW_NAME = os.getenv("LOGS_ERRORS_VIEW_NAME", "Active").strip()


# ============================================================
# Timeouts / runtime
# ============================================================

RUN_MAX_SECONDS = float(os.getenv("RUN_MAX_SECONDS", "30"))
HTTP_TIMEOUT_SECONDS = float(os.getenv("HTTP_TIMEOUT_SECONDS", "20"))

RUN_LOCK_TTL_SECONDS = int(os.getenv("RUN_LOCK_TTL_SECONDS", "600"))
COMMAND_LOCK_TTL_MIN = int(os.getenv("COMMAND_LOCK_TTL_MIN", "10"))


# ============================================================
# Security
# ============================================================

RUN_SHARED_SECRET = os.getenv("RUN_SHARED_SECRET", "").strip()
SCHEDULER_SECRET = os.getenv("SCHEDULER_SECRET", "").strip()


# ============================================================
# SLA
# ============================================================

SLA_WARNING_THRESHOLD_MIN = float(os.getenv("SLA_WARNING_THRESHOLD_MIN", "60"))


# ============================================================
# Status constants
# ============================================================

SLA_STATUS_OK = "OK"
SLA_STATUS_WARNING = "Warning"
SLA_STATUS_BREACHED = "Breached"
SLA_STATUS_ESCALATED = "Escalated"

STATE_LOCK_ACTIVE = "Active"
STATE_LOCK_RELEASED = "Released"
STATE_LOCK_EXPIRED = "Expired"
