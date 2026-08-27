"""SIEM integration module for MCP Agent Security Gateway.

Exports security events in Elastic Common Schema (ECS) format,
provides correlation rules for multi-event attack pattern detection,
and ships structured logs to external SIEM/ELK infrastructure.

This module is designed for detection engineering practice in a lab
environment. It demonstrates real SIEM integration patterns but has
not been validated at production scale.
"""

from mcp_monitor.siem.correlation import CorrelationEngine, CorrelationRule
from mcp_monitor.siem.ecs_formatter import ECSEvent, ECSFormatter
from mcp_monitor.siem.shipper import ElasticsearchShipper, FileShipper, LogShipper

__all__ = [
    "ECSFormatter",
    "ECSEvent",
    "CorrelationEngine",
    "CorrelationRule",
    "LogShipper",
    "ElasticsearchShipper",
    "FileShipper",
]
