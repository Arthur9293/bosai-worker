from typing import Any, Callable, Dict

from app.make_client import MakeClient
from app.airtable_client import AirtableClient


IntentFn = Callable[[Dict[str, Any]], Any]


def build_registry(make: MakeClient, airtable: AirtableClient) -> Dict[str, IntentFn]:
    return {
        # Airtable
        "airtable.ping": lambda args: airtable.ping(),

        # Make (dot + underscore aliases)

# GET SCENARIO
"make.get.scenario": lambda args: make.get_scenario(str(args["scenario_id"])),
"make.get_scenario": lambda args: make.get_scenario(str(args["scenario_id"])),

# GET BLUEPRINT
"make.get.blueprint": lambda args: make.get_blueprint(str(args["scenario_id"])),
"make.get_blueprint": lambda args: make.get_blueprint(str(args["scenario_id"])),

# PAUSE
"make.pause.scenario": lambda args: make.pause_scenario(str(args["scenario_id"])),
"make.pause_scenario": lambda args: make.pause_scenario(str(args["scenario_id"])),

# RESUME
"make.resume.scenario": lambda args: make.resume_scenario(str(args["scenario_id"])),
"make.resume_scenario": lambda args: make.resume_scenario(str(args["scenario_id"])),

# CLONE
"make.clone.scenario": lambda args: make.clone_scenario(
    str(args["scenario_id"]),
    str(args["new_name"])
),
"make.clone_scenario": lambda args: make.clone_scenario(
    str(args["scenario_id"]),
    str(args["new_name"])
),

# UPDATE
"make.update.scenario": lambda args: make.update_scenario(
    str(args["scenario_id"]),
    dict(args.get("patch", {}))
),
"make.update_scenario": lambda args: make.update_scenario(
    str(args["scenario_id"]),
    dict(args.get("patch", {}))
),

}
