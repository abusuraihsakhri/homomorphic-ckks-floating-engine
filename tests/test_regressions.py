"""Regression tests for audit integrity, privacy screening, packaging and UI."""
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from agents.api import app
from agents.base import AuditTrail, SecurityException
from agents.models import SystemTaskPayload
from agents.supervisor import SystemSupervisor
from cli import main


def test_audit_tampering_with_signed_fields_is_detected():
    trail = AuditTrail(secret_key="test-only-key")
    trail.log("user", "supervisor", "EVALUATE", {"status": "ok"})
    trail.log("user", "supervisor", "EVALUATE", {"status": "ok2"})
    assert trail.verify_integrity()
    trail.logs[1]["actor"] = "attacker"
    assert not trail.verify_integrity()


def test_audit_tampering_with_signature_is_detected():
    trail = AuditTrail(secret_key="test-only-key")
    trail.log("user", "supervisor", "EVALUATE", {"status": "ok"})
    trail.logs[0]["current_hash"] = "0" * 64
    assert not trail.verify_integrity()


def test_audit_trail_snapshot_cannot_change_internal_logs():
    trail = AuditTrail(secret_key="test-only-key")
    returned = trail.log("user", "supervisor", "EVALUATE", {"status": "ok"})
    returned["actor"] = "modified"
    snapshot = trail.get_trail()
    snapshot[0]["actor"] = "modified"
    assert trail.verify_integrity()
    assert trail.get_trail()[0]["actor"] == "user"


@pytest.mark.parametrize("bad_number", [float("nan"), float("inf"), float("-inf")])
def test_nonfinite_metrics_are_rejected(bad_number):
    with pytest.raises(ValidationError):
        SystemTaskPayload(task_id="T", target_identifier="K", primary_metric=bad_number)


def test_attributes_are_screened_for_obvious_identifiers():
    supervisor = SystemSupervisor(model_provider="mock")
    payload = SystemTaskPayload(
        task_id="T",
        target_identifier="SYNTHETIC-001",
        primary_metric=1,
        attributes={"notes": "MRN-1234567"},
    )
    with pytest.raises(SecurityException):
        supervisor.process_task(payload)


def test_api_invalid_identifier_returns_client_error():
    client = TestClient(app)
    response = client.post("/api/audit", json={
        "task_id": "patient@example.com", "target_identifier": "SYNTHETIC-001", "primary_metric": 3
    })
    assert response.status_code == 422


def test_audit_logs_disabled_without_access_token(monkeypatch):
    monkeypatch.delenv("AUDIT_API_TOKEN", raising=False)
    client = TestClient(app)
    assert client.get("/api/audit/logs").status_code == 503
    monkeypatch.setenv("AUDIT_API_TOKEN", "private-test-token")
    assert client.get("/api/audit/logs").status_code == 403
    assert client.get("/api/audit/logs", headers={"X-Audit-Token": "wrong"}).status_code == 403
    response = client.get("/api/audit/logs", headers={"X-Audit-Token": "private-test-token"})
    assert response.status_code == 200
    assert response.json()["verified"] is True


def test_dashboard_has_no_fabricated_crypto_results():
    html = Path(__file__).resolve().parent.parent.joinpath("web", "index.html").read_text(encoding="utf-8")
    assert "evaluateLocally" in html
    assert 'fetch("/api/audit"' in html
    assert "HMAC_SHA256_e83f9" not in html
    assert "No encryption performed" in html


def test_batch_skips_nonfinite_metrics(tmp_path, capsys):
    source = tmp_path / "input.csv"
    output = tmp_path / "output.csv"
    source.write_text(
        "task_id,target_identifier,primary_metric,secondary_metric,status_descriptor\n"
        "INVALID,K1,nan,5,NOMINAL\n"
        "VALID,K2,3,5,NOMINAL\n", encoding="utf-8")
    assert main(["batch", "-i", str(source), "-o", str(output)]) == 0
    assert "Skipping row" in capsys.readouterr().err
    text = output.read_text(encoding="utf-8")
    assert "VALID" in text
    assert "INVALID,K1" not in text


def test_packaged_dashboard_route():
    client = TestClient(app)
    result = client.get("/")
    assert result.status_code == 200
    assert "Local browser evaluation" in result.text


def test_browser_javascript_syntax_when_node_available(tmp_path):
    import shutil
    import subprocess
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is not available")
    html = Path(__file__).resolve().parent.parent.joinpath("web", "index.html").read_text(encoding="utf-8")
    script = html.split("<script>", 1)[1].split("</script>", 1)[0]
    script_path = tmp_path / "dashboard.js"
    script_path.write_text(script, encoding="utf-8")
    result = subprocess.run([node, "--check", str(script_path)], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


def test_hmac_field_boundaries_are_unambiguous():
    trail = AuditTrail(secret_key="test-only-key")
    trail.log("alpha|beta", "gamma", "EVENT", {"ok": True})
    trail.logs[0]["actor"] = "alpha"
    trail.logs[0]["actor_tier"] = "beta|gamma"
    assert not trail.verify_integrity()
