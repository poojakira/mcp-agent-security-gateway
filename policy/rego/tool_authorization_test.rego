# Unit tests for the MCP tool authorization policy.
# Run with:  opa test policy/rego -v
# UNVERIFIED here — requires the opa binary (not installed in this environment).
package mcp.authz_test

import data.mcp.authz
import rego.v1

test_allow_authorized_tool_on_allowed_server if {
	authz.allow with input as {"tool_name": "search_web", "server_id": "search"}
}

test_deny_dangerous_tool if {
	not authz.allow with input as {"tool_name": "shell_exec", "server_id": "search"}
}

test_deny_dangerous_tool_even_on_allowed_server if {
	not authz.allow with input as {"tool_name": "delete_file", "server_id": "filesystem"}
}

test_deny_server_not_on_allowlist if {
	not authz.allow with input as {"tool_name": "search_web", "server_id": "rogue-server"}
}

test_default_deny_on_empty_input if {
	not authz.allow with input as {}
}

test_reason_contains_dangerous_tool if {
	authz.reasons["DENY_DANGEROUS_TOOL"] with input as {
		"tool_name": "rm",
		"server_id": "filesystem",
	}
}

test_reason_contains_server_not_allowed if {
	authz.reasons["DENY_SERVER_NOT_ALLOWED"] with input as {
		"tool_name": "search_web",
		"server_id": "rogue-server",
	}
}

test_decision_allowed_true_for_valid_call if {
	authz.decision.allowed == true with input as {
		"tool_name": "add",
		"server_id": "calculator",
	}
}
