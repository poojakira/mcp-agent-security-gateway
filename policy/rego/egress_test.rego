# Unit tests for the MCP egress control policy.
# Run with:  opa test policy/rego -v
# UNVERIFIED here — requires the opa binary (not installed in this environment).
package mcp.egress_test

import data.mcp.egress
import rego.v1

test_allow_no_destination if {
	egress.allow_egress with input as {"tool_name": "add", "server_id": "calculator"}
}

test_allow_allowlisted_host if {
	egress.allow_egress with input as {"egress_host": "api.example.com"}
}

test_deny_non_allowlisted_host if {
	not egress.allow_egress with input as {"egress_host": "evil.attacker.net"}
}

test_reason_contains_egress_not_allowed if {
	egress.reasons["DENY_EGRESS_NOT_ALLOWED"] with input as {"egress_host": "evil.attacker.net"}
}

test_decision_allowed_false_for_bad_egress if {
	egress.decision.allowed == false with input as {"egress_host": "10.0.0.5"}
}
