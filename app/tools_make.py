# tools_make.py
# Tool definitions for OpenAI Responses API function calling (strict JSON schema).

MAKE_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "make.get_scenario",
            "description": "Get Make scenario details (metadata). Does NOT include blueprint.",
            "strict": True,
            "parameters": {
                "type": "object",
                "additionalProperties": False,
                "required": ["make_base_url", "scenario_id"],
                "properties": {
                    "make_base_url": {
                        "type": "string",
                        "description": "Make API base URL, e.g. https://eu1.make.com/api/v2"
                    },
                    "scenario_id": {"type": "integer", "minimum": 1},
                    "cols": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional cols[] query param to limit returned fields"
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "make.get_blueprint",
            "description": "Get Make scenario blueprint JSON for a given scenarioId.",
            "strict": True,
            "parameters": {
                "type": "object",
                "additionalProperties": False,
                "required": ["make_base_url", "scenario_id"],
                "properties": {
                    "make_base_url": {
                        "type": "string",
                        "description": "Make API base URL, e.g. https://eu1.make.com/api/v2"
                    },
                    "scenario_id": {"type": "integer", "minimum": 1}
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "make.clone_scenario",
            "description": "Clone a Make scenario. Requires organizationId (query) + teamId/name/states (body).",
            "strict": True,
            "parameters": {
                "type": "object",
                "additionalProperties": False,
                "required": ["make_base_url", "scenario_id", "organization_id", "team_id", "name", "states"],
                "properties": {
                    "make_base_url": {
                        "type": "string",
                        "description": "Make API base URL, e.g. https://eu1.make.com/api/v2"
                    },
                    "scenario_id": {"type": "integer", "minimum": 1},
                    "organization_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "organizationId query parameter"
                    },
                    "team_id": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "teamId in request body"
                    },
                    "name": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 120
                    },
                    "states": {
                        "type": "boolean",
                        "description": "true = clone module states; false = reset states"
                    },
                    "confirmed": {
                        "type": "boolean",
                        "description": "Optional query param when custom app/function needs confirmation"
                    },
                    "not_analyze": {
                        "type": "boolean",
                        "description": "Optional query param to suppress blueprint analysis (use with caution)"
                    },
                    "entity_map": {
                        "type": "object",
                        "additionalProperties": False,
                        "description": "Optional entity mapping objects when cloning across teams/org contexts.",
                        "properties": {
                            "account": {"type": "object", "additionalProperties": True},
                            "key": {"type": "object", "additionalProperties": True},
                            "hook": {"type": "object", "additionalProperties": True},
                            "device": {"type": "object", "additionalProperties": True},
                            "udt": {"type": "object", "additionalProperties": True},
                            "datastore": {"type": "object", "additionalProperties": True}
                        }
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "make.update_scenario",
            "description": "Update a Make scenario: supports blueprint string, scheduling string, folderId, name. Writes are guarded by your runtime policies.",
            "strict": True,
            "parameters": {
                "type": "object",
                "additionalProperties": False,
                "required": ["make_base_url", "scenario_id", "patch"],
                "properties": {
                    "make_base_url": {
                        "type": "string",
                        "description": "Make API base URL, e.g. https://eu1.make.com/api/v2"
                    },
                    "scenario_id": {"type": "integer", "minimum": 1},
                    "confirmed": {
                        "type": "boolean",
                        "description": "Optional query param to confirm installing first-time app in org"
                    },
                    "patch": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "blueprint": {
                                "type": "string",
                                "description": "Scenario blueprint as STRING (Make API format)."
                            },
                            "scheduling": {
                                "type": "string",
                                "description": "Scenario scheduling as STRING (Make API format)."
                            },
                            "folderId": {"type": "integer", "minimum": 1},
                            "name": {"type": "string", "minLength": 1, "maxLength": 120}
                        }
                    },
                    "cols": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional cols[] query param"
                    }
                }
            }
        }
    }
]
