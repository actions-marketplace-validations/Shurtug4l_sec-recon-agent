"""sec-recon-gate CLI shell: exit codes and output plumbing.

run_gate is stubbed - the orchestration logic is covered in test_runner.py;
these tests pin the CI-facing contract (0 pass / 1 policy fail / 2 infra).
"""

import json
from pathlib import Path
from typing import Any

import pytest

import sec_recon_agent.gate.cli as cli_mod
from sec_recon_agent.agent.schema import SsvcAssessment, SsvcBasis, SsvcDecision
from sec_recon_agent.gate.cli import main
from sec_recon_agent.gate.models import GatePolicy, GateReport
from sec_recon_agent.mcp_server.errors import KevDownloadError, SbomError


def make_report(*, passed: bool) -> GateReport:
    return GateReport(
        sbom_format="requirements",
        components_total=1,
        components_scanned=1,
        findings=[],
        ssvc=SsvcAssessment(
            decision=SsvcDecision.TRACK,
            rule="no-cves",
            rationale="test",
            driving_cve=None,
            basis=SsvcBasis.EVIDENCE,
        ),
        policy=GatePolicy(fail_on="act", triggered=[], passed=passed),
        tool_version="0.1.0",
    )


@pytest.fixture
def sbom_file(tmp_path: Path) -> Path:
    path = tmp_path / "requirements.txt"
    path.write_text("liba==1.0\n")
    return path


def stub_run_gate(monkeypatch: pytest.MonkeyPatch, outcome: GateReport | Exception) -> None:
    async def fake(content: str, **kwargs: Any) -> GateReport:
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(cli_mod, "run_gate", fake)


class TestExitCodes:
    def test_pass_is_zero(self, monkeypatch: pytest.MonkeyPatch, sbom_file: Path) -> None:
        stub_run_gate(monkeypatch, make_report(passed=True))
        assert main([str(sbom_file)]) == 0

    def test_policy_fail_is_one(self, monkeypatch: pytest.MonkeyPatch, sbom_file: Path) -> None:
        stub_run_gate(monkeypatch, make_report(passed=False))
        assert main([str(sbom_file)]) == 1

    def test_unreadable_input_is_two(self, tmp_path: Path) -> None:
        assert main([str(tmp_path / "missing.txt")]) == 2

    def test_unusable_sbom_is_two(self, monkeypatch: pytest.MonkeyPatch, sbom_file: Path) -> None:
        stub_run_gate(monkeypatch, SbomError("nope"))
        assert main([str(sbom_file)]) == 2

    def test_kev_unavailable_is_two(self, monkeypatch: pytest.MonkeyPatch, sbom_file: Path) -> None:
        stub_run_gate(monkeypatch, KevDownloadError("catalog unreachable"))
        assert main([str(sbom_file)]) == 2


class TestOutputs:
    def test_report_sarif_written_openvex_skipped_without_products(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sbom_file: Path,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        stub_run_gate(monkeypatch, make_report(passed=True))
        report_path = tmp_path / "gate.json"
        sarif_path = tmp_path / "gate.sarif"
        vex_path = tmp_path / "gate.vex.json"

        code = main(
            [
                str(sbom_file),
                "--report",
                str(report_path),
                "--sarif",
                str(sarif_path),
                "--openvex",
                str(vex_path),
            ]
        )

        assert code == 0
        parsed = json.loads(report_path.read_text())
        assert parsed["policy"]["passed"] is True
        sarif = json.loads(sarif_path.read_text())
        assert sarif["version"] == "2.1.0"
        assert sarif["runs"][0]["properties"]["source"] == "sec-recon-gate"
        # No findings -> no product identity -> the VEX is skipped, not fabricated.
        assert not vex_path.exists()
        err = capsys.readouterr().err
        assert "openvex skipped" in err
        assert "gate PASS" in err

    def test_fail_on_flag_maps_hyphen_to_literal(
        self, monkeypatch: pytest.MonkeyPatch, sbom_file: Path
    ) -> None:
        captured: dict[str, Any] = {}

        async def fake(content: str, **kwargs: Any) -> GateReport:
            captured.update(kwargs)
            return make_report(passed=True)

        monkeypatch.setattr(cli_mod, "run_gate", fake)
        assert main([str(sbom_file), "--fail-on", "track-star", "--strict"]) == 0
        assert captured["fail_on"] == "track_star"
        assert captured["strict"] is True
