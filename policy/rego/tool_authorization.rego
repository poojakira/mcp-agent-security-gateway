# METADATA
# title: MCP Tool Authorization
# description: |
#   Default-deny authorization for MCP `tools/call` requests.
#   Denies dangerous/destructive tools outright and enforces a server allowlist.
#   Deny always wins over allow.
#
# This policy is kept in parity with the Python PDP at
# src/mcp_monitor/policy/policy_engine.py. The Python PDP is the verified path
# in this repo; this Rego is verifiable with `opa test` where the OPA binary is
# available (see policy/rego/README.md).
package mcp.authz

import rego.v1

# ---------------------------------------------------------------------------
# Configuration (data documents). In production these come from data.json or an
# external data source; defaults here keep the policy self-contained/testable.
# ---------------------------------------------------------------------------

default allowed_servers := {"filesystem", "search", "calculator"}

default dangerous_tools := {
	"shell_exec",
	"exec",
	"run_command",
	"delete_file",
	"rm",
	"drop_database",
	"write_iam_policy",
	"assume_role",
	"disable_logging",
	"modify_firewall",
}

# ---------------------------------------------------------------------------
# Decision: default deny.
# ---------------------------------------------------------------------------

default allow := false

allow if {
	not deny_dangerous_tool
	not deny_server_not_allowed
	input.tool_name
	input.server_id
}

# ---------------------------------------------------------------------------
# Deny rules (deny wins). Each populates a reason set for explainability.
# ---------------------------------------------------------------------------

deny_dangerous_tool if {
	dangerous_tools[input.tool_name]
}

deny_server_not_allowed if {
	not allowed_servers[input.server_id]
}

# Aggregate structured reasons, mirroring the Python ReasonCode values.
reasons contains "DENY_DANGEROUS_TOOL" if deny_dangerous_tool

reasons contains "DENY_SERVER_NOT_ALLOWED" if deny_server_not_allowed

reasons contains "ALLOWED" if allow

decision := {
	"allowed": allow,
	"reasons": reasons,
}
