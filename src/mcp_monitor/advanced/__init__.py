"""Advanced MCP security controls for higher-assurance tool execution.

This module implements five controls that complement the base MCP protocol:

1. MANIFEST SIGNING — Cryptographic proof that a tool's schema hasn't changed
   since approval. The control treats manifest integrity as an explicit
   deployment responsibility.

2. BEHAVIORAL DRIFT — Runtime detection of tools that silently change behavior
   between versions (the Postmark attack pattern: 15 clean versions, then BCC
   injection). Neither the spec nor any official SDK provides this.

3. CROSS-TOOL CORRELATION — Multi-step attack detection. A single tool call
   may look benign; the combination of read_secret + send_email is exfiltration.
   MCP has no concept of tool-call sequencing constraints.

4. INVARIANT ENFORCEMENT — Declarative security contracts that tools cannot
   violate at runtime. The spec delegates ALL safety to deployers. We enforce
   it computationally.

5. CANARY PROBES — Active verification that a tool still behaves as expected by
   periodically sending known inputs and checking outputs. Catches supply-chain
   compromise between audit windows.
"""

from mcp_monitor.advanced.canary import CanaryResult, ToolCanary
from mcp_monitor.advanced.correlation import CrossToolCorrelationEngine
from mcp_monitor.advanced.drift import BehavioralDriftDetector
from mcp_monitor.advanced.invariants import Invariant, InvariantEnforcer
from mcp_monitor.advanced.manifest import ManifestSigner, ManifestVerifier

__all__ = [
    "ManifestSigner",
    "ManifestVerifier",
    "BehavioralDriftDetector",
    "CrossToolCorrelationEngine",
    "InvariantEnforcer",
    "Invariant",
    "ToolCanary",
    "CanaryResult",
]
