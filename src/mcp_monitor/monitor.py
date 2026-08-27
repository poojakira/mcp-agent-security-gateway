"""MCPSecurityMonitor — orchestrator for all MCP tool-call detectors.

Runs prompt-injection, PII, shadow-server, and exfiltration detectors against
every tool call, logs decisions to the hash-chained audit log, and returns a
verdict with risk score and findings.
"""

from __future__ import annotations

import logging
import uuid
from enum import Enum
from typing import Any

from mcp_monitor.audit.log import AuditLog
from mcp_monitor.detectors.exfiltration import ExfiltrationDetector
from mcp_monitor.detectors.pii_detector import PIIDetector
from mcp_monitor.detectors.prompt_injection import PromptInjectionDetector
from mcp_monitor.detectors.shadow_server import ShadowServerDetector


logger = logging.getLogger(__name__)


class Decision(Enum):
    """Explicit security enforcement decision.

    ALLOW    - All detectors passed, request is safe.
    BLOCK    - At least one detector found a threat.
    INDETERMINATE - Detector failure/timeout/unavailable; fail-closed in enforcement mode.
    """

    ALLOW = "allow"
    BLOCK = "block"
    INDETERMINATE = "indeterminate"


class DetectorFailure(Exception):
    """Raised when a detector fails to produce a result.

    Includes the detector name and original exception for debugging.
    """

    def __init__(self, detector_name: str, original_exception: Exception) -> None:
        self.detector_name = detector_name
        self.original_exception = original_exception
        super().__init__(f"Detector '{detector_name}' failed: {original_exception}")


class MCPSecurityMonitor:
    """Orchestrates all security detectors for MCP tool calls.

    Security invariants:
    - Any detector exception => INDETERMINATE
    - In enforcement mode (shadow_mode=False): INDETERMINATE => BLOCK
    - In shadow mode (shadow_mode=True): INDETERMINATE => ALLOW (logged only)
    """

    def __init__(
        self,
        allowed_servers: set[str],
        audit_log: AuditLog,
        *,
        max_payload_kb: float = 100.0,
        shadow_mode: bool = False,
    ) -> None:
        self.audit_log = audit_log
        self.shadow_mode = shadow_mode
        self.injection_detector = PromptInjectionDetector()
        self.pii_detector = PIIDetector()
        self.shadow_detector = ShadowServerDetector(allowed_servers)
        self.exfiltration_detector = ExfiltrationDetector(max_payload_kb=max_payload_kb)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def inspect_call(self, tool_call: dict[str, Any]) -> dict[str, Any]:
        """Run all detectors against an inbound tool call.

        Parameters
        ----------
        tool_call:
            Dict with ``name``, ``server_id``, and ``arguments`` fields.

        Returns
        -------
        dict with keys: decision, allowed, risk_score, findings, call_id, detector_errors
        """
        call_id = str(uuid.uuid4())
        findings: list[str] = []
        risk_scores: list[int] = []
        detector_errors: list[str] = []
        decision = Decision.ALLOW
        is_shadow = False

        # 1. Prompt injection
        try:
            injected, patterns = self.injection_detector.detect(tool_call)
            if injected:
                for p in patterns:
                    findings.append(f"prompt_injection:{p}")
                risk_scores.append(self.injection_detector.risk_score(tool_call))
        except Exception as exc:
            logger.exception("Prompt injection detector failed")
            detector_errors.append(f"prompt_injection: {exc}")
            decision = Decision.INDETERMINATE

        # 2. PII detection
        try:
            has_pii, pii_findings = self.pii_detector.scan_tool_call(tool_call)
            if has_pii:
                for pii_type, values in pii_findings.items():
                    findings.append(f"pii:{pii_type}:{len(values)}")
                risk_scores.append(40 + 10 * len(pii_findings))
        except Exception as exc:
            logger.exception("PII detector failed")
            detector_errors.append(f"pii: {exc}")
            decision = Decision.INDETERMINATE

        # 3. Shadow server detection
        try:
            is_shadow, reason = self.shadow_detector.detect(tool_call)
            if is_shadow:
                findings.append(f"shadow_server:{reason}")
                risk_scores.append(80)
        except Exception as exc:
            logger.exception("Shadow server detector failed")
            detector_errors.append(f"shadow_server: {exc}")
            decision = Decision.INDETERMINATE

        # 4. Exfiltration (on arguments treated as partial output)
        tool_name = tool_call.get("name", "")
        arguments = tool_call.get("arguments", {})
        try:
            exfil, exfil_reasons = self.exfiltration_detector.detect(tool_name, arguments)
            if exfil:
                for r in exfil_reasons:
                    findings.append(f"exfiltration:{r}")
                risk_scores.append(70 + 5 * len(exfil_reasons))
        except Exception as exc:
            logger.exception("Exfiltration detector failed")
            detector_errors.append(f"exfiltration: {exc}")
            decision = Decision.INDETERMINATE

        # Compute final risk score
        risk_score = min(max(risk_scores, default=0), 100)

        # Determine final decision
        if decision == Decision.ALLOW:
            # Check if any detector found a threat
            if risk_score >= 50 or is_shadow:
                decision = Decision.BLOCK
                allowed = False
            else:
                allowed = True
        elif decision == Decision.INDETERMINATE:
            # Fail-closed in enforcement mode, fail-open in shadow mode
            if self.shadow_mode:
                logger.warning(
                    "Detector failure in shadow mode - allowing: %s", detector_errors
                )
                decision = Decision.ALLOW
                allowed = True
            else:
                logger.error("Detector failure in enforcement mode - blocking: %s", detector_errors)
                decision = Decision.BLOCK
                allowed = False

        # Log to audit
        self.audit_log.append(
            event_type="tool_call_inspected",
            data={
                "call_id": call_id,
                "tool_name": tool_name,
                "decision": decision.value,
                "allowed": allowed,
                "risk_score": risk_score,
                "findings": findings,
                "detector_errors": detector_errors,
                "shadow_mode": self.shadow_mode,
            },
        )

        return {
            "decision": decision.value,
            "allowed": allowed,
            "risk_score": risk_score,
            "findings": findings,
            "call_id": call_id,
            "detector_errors": detector_errors,
        }

    def inspect_output(self, tool_name: str, output: dict[str, Any]) -> dict[str, Any]:
        """Inspect a tool's output for exfiltration and PII leakage.

        Parameters
        ----------
        tool_name:
            Name of the tool that produced the output.
        output:
            The tool's output payload.

        Returns
        -------
        dict with keys: decision, allowed, risk_score, findings, call_id, detector_errors
        """
        call_id = str(uuid.uuid4())
        findings: list[str] = []
        risk_scores: list[int] = []
        detector_errors: list[str] = []
        decision = Decision.ALLOW

        # Exfiltration check
        try:
            exfil, exfil_reasons = self.exfiltration_detector.detect(tool_name, output)
            if exfil:
                for r in exfil_reasons:
                    findings.append(f"exfiltration:{r}")
                risk_scores.append(70 + 5 * len(exfil_reasons))
        except Exception as exc:
            logger.exception("Exfiltration detector failed on output")
            detector_errors.append(f"exfiltration: {exc}")
            decision = Decision.INDETERMINATE

        # PII in output
        try:
            output_text = str(output)
            pii_results = self.pii_detector.detect(output_text)
            if pii_results:
                for pii_type, values in pii_results.items():
                    findings.append(f"pii_output:{pii_type}:{len(values)}")
                risk_scores.append(50 + 10 * len(pii_results))
        except Exception as exc:
            logger.exception("PII detector failed on output")
            detector_errors.append(f"pii: {exc}")
            decision = Decision.INDETERMINATE

        risk_score = min(max(risk_scores, default=0), 100)

        # Determine final decision
        if decision == Decision.ALLOW:
            if risk_score >= 50:
                decision = Decision.BLOCK
                allowed = False
            else:
                allowed = True
        elif decision == Decision.INDETERMINATE:
            if self.shadow_mode:
                logger.warning(
                    "Detector failure in shadow mode - allowing: %s", detector_errors
                )
                decision = Decision.ALLOW
                allowed = True
            else:
                logger.error("Detector failure in enforcement mode - blocking: %s", detector_errors)
                decision = Decision.BLOCK
                allowed = False

        # Log to audit
        self.audit_log.append(
            event_type="tool_output_inspected",
            data={
                "call_id": call_id,
                "tool_name": tool_name,
                "decision": decision.value,
                "allowed": allowed,
                "risk_score": risk_score,
                "findings": findings,
                "detector_errors": detector_errors,
                "shadow_mode": self.shadow_mode,
            },
        )

        return {
            "decision": decision.value,
            "allowed": allowed,
            "risk_score": risk_score,
            "findings": findings,
            "call_id": call_id,
            "detector_errors": detector_errors,
        }