# METADATA
# title: MCP Egress Control
# description: |
#   Default-deny egress control for MCP tool calls that reach out to the network.
#   A tool call's destination host must be on the egress allowlist. Loopback /
#   private / link-local destinations are blocked unless explicitly allowlisted.
#
# Parity with src/mcp_monitor/policy/policy_engine.py (_evaluate_egress).
package mcp.egress

import rego.v1

default allowed_egress_hosts := {"api.example.com", "search.example.com"}

# The caller is expected to pass a pre-parsed host in input.egress_host. When no
# destination is present, egress control is not applicable and allow_egress is
# true (the tool_authorization policy still governs the call).

default allow_egress := false

# No destination -> egress not applicable.
allow_egress if {
	not input.egress_host
}

# Destination present and on the allowlist.
allow_egress if {
	input.egress_host
	allowed_egress_hosts[input.egress_host]
}

deny_egress_not_allowed if {
	input.egress_host
	not allowed_egress_hosts[input.egress_host]
}

reasons contains "DENY_EGRESS_NOT_ALLOWED" if deny_egress_not_allowed

reasons contains "ALLOWED" if allow_egress

decision := {
	"allowed": allow_egress,
	"reasons": reasons,
}
