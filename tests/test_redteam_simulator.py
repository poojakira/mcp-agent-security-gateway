"""
tests/test_redteam_simulator.py
────────────────────────────────────────────────────────────────────────────────
Tests for mcp_monitor.redteam.simulator (previously 0% covered).

Exercises the attack-simulation harness against a real FiveLayerDefense:
full catalog run, per-category run, single-attack run, result accessors,
and the report/summary builder.
"""

import pytest

from mcp_monitor.audit.log import AuditLog
from mcp_monitor.layers.egress import NetworkEgressPolicy
from mcp_monitor.layers.kernel import KernelMonitor, ServerPolicy
from mcp_monitor.layers.orchestrator import FiveLayerDefense
from mcp_monitor.layers.proxy import InlineProxyGateway
from mcp_monitor.layers.semantic import SemanticIntentAnalyzer
from mcp_monitor.monitor import MCPSecurityMonitor
from mcp_monitor.redteam.payloads import ATTACK_CATALOG
from mcp_monitor.redteam.simulator import AttackResult, AttackSimulator, SimulationReport


@pytest.fixture
def defense(tmp_path):
    audit = AuditLog(str(tmp_path / "a.log"))
    monitor = MCPSecurityMonitor({"postmark", "github"}, audit)
    monitor.shadow_detector.register_server("postmark", ["send"])
    monitor.shadow_detector.register_server("github", ["repos"])
    proxy = InlineProxyGateway(inspector=monitor, block_threshold=50)
    kernel = KernelMonitor()
    kernel.register_policy(
        ServerPolicy(
            server_id="postmark",
            allowed_destinations={"api.postmarkapp.com"},
            allowed_ports={443},
        )
    )
    semantic = SemanticIntentAnalyzer(sensitivity=0.7)
    egress = NetworkEgressPolicy(default_deny=False)
    return FiveLayerDefense(proxy=proxy, kernel=kernel, semantic=semantic, egress=egress)


@pytest.fixture
def simulator(defense):
    return AttackSimulator(defense)


class TestAttackSimulator:
    def test_run_full_catalog_returns_report(self, simulator):
        report = simulator.run_full_catalog()
        assert isinstance(report, SimulationReport)
        # every catalog attack produces a result
        assert len(simulator.get_all_results()) == len(ATTACK_CATALOG)

    def test_full_catalog_results_are_attack_results(self, simulator):
        simulator.run_full_catalog()
        for r in simulator.get_all_results():
            assert isinstance(r, AttackResult)
            assert hasattr(r, "attack_name")

    def test_run_category_subset(self, simulator):
        cats = {a["category"] for a in ATTACK_CATALOG}
        some_cat = sorted(cats)[0]
        report = simulator.run_category(some_cat)
        assert isinstance(report, SimulationReport)
        expected = sum(1 for a in ATTACK_CATALOG if a["category"] == some_cat)
        assert len(simulator.get_all_results()) == expected

    def test_run_single_known_attack(self, simulator):
        name = ATTACK_CATALOG[0]["name"]
        result = simulator.run_single(name)
        assert result is not None
        assert result.attack_name == name

    def test_run_single_unknown_returns_none(self, simulator):
        assert simulator.run_single("this-attack-does-not-exist") is None

    def test_report_summary_counts_consistent(self, simulator):
        report = simulator.run_full_catalog()
        results = simulator.get_all_results()
        blocked = sum(1 for r in results if getattr(r, "blocked", False))

        # The report must faithfully describe the run it produced.
        assert report.total_attacks == len(results)
        assert report.blocked == blocked
        assert report.missed == report.total_attacks - report.blocked
        assert report.blocked + report.missed == report.total_attacks
        assert len(report.results) == report.total_attacks
        # detection_rate is the blocked percentage of the catalog.
        expected_rate = blocked / max(report.total_attacks, 1) * 100
        assert report.detection_rate == pytest.approx(expected_rate)
        assert 0.0 <= report.detection_rate <= 100.0

    def test_empty_before_run(self, defense):
        sim = AttackSimulator(defense)
        assert sim.get_all_results() == []
