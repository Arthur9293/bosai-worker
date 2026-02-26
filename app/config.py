import os

def env(name: str, default: str | None = None) -> str:
    v = os.getenv(name)
    if v is None or v.strip() == "":
        if default is None:
            raise RuntimeError(f"Missing required env var: {name}")
        return default
    return v.strip()

APP_NAME = env("APP_NAME", "bosai-worker")
WORKER_NAME = env("WORKER_NAME", "bosai-worker-01")
APP_VERSION = env("APP_VERSION", "2.0.0")
ENV_NAME = env("ENV_NAME", "local")

AIRTABLE_TOKEN = env("AIRTABLE_TOKEN", "")
AIRTABLE_BASE_ID = env("AIRTABLE_BASE_ID", "")
AIRTABLE_TABLE_SYSTEM_RUNS = env("AIRTABLE_TABLE_SYSTEM_RUNS", "System_Runs")
AIRTABLE_TABLE_COMMANDS = env("AIRTABLE_TABLE_COMMANDS", "Commands")

CHAOS_GUARD_COOLDOWN_SECONDS = int(env("CHAOS_GUARD_COOLDOWN_SECONDS", "30"))
RUN_MAX_SECONDS = int(env("RUN_MAX_SECONDS", "20"))

# Airtable API
AIRTABLE_API_BASE = "https://api.airtable.com/v0"
