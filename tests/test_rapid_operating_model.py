"""Regression tests for the rolling, advisory-first hardening fixtures."""
from __future__ import annotations

import copy
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from contextlib import redirect_stdout

import yaml

ROOT = Path(__file__).resolve().parents[1]
from scripts import advisory_lane_fixture, cve_disposition_fixture, rapid_hardening_checks, rolling_manifest, runtime_containment_fixture, run_openssl_gcc_analyzer


class OperatingModelFixtureTests(unittest.TestCase):
    def test_reference_manifest_validates_and_binds_local_inputs(self):
        manifest = json.loads((ROOT / "fixtures/rolling-intake/reference-snapshot.json").read_text())
        self.assertEqual(rolling_manifest.validate_manifest(manifest, ROOT), [])
        tampered = copy.deepcopy(manifest)
        tampered["configuration"]["machine"] = "qemuarm64"
        errors = rolling_manifest.validate_manifest(tampered, ROOT)
        self.assertTrue(any("configuration.identity_sha256" in error for error in errors))
        self.assertTrue(any("manifest_sha256" in error for error in errors))

    def test_manifest_binds_each_revision_to_its_named_repository(self):
        source = json.loads((ROOT / "fixtures/rolling-intake/reference-snapshot.json").read_text())
        wrong_repo_revision = next(repo["revision"] for repo in source["repositories"] if repo["name"] == "bitbake")

        layer_mismatch = copy.deepcopy(source)
        layer_mismatch["selected_layers"][0]["revision"] = wrong_repo_revision
        layer_mismatch["manifest_sha256"] = rolling_manifest.canonical_digest(
            {k: v for k, v in layer_mismatch.items() if k != "manifest_sha256"}
        )
        self.assertTrue(any("selected_layers[0].revision" in error for error in rolling_manifest.validate_manifest(layer_mismatch, ROOT)))

        metadata_mismatch = copy.deepcopy(source)
        metadata_mismatch["recipe_sources"][0]["metadata_revision"] = wrong_repo_revision
        metadata_mismatch["manifest_sha256"] = rolling_manifest.canonical_digest(
            {k: v for k, v in metadata_mismatch.items() if k != "manifest_sha256"}
        )
        self.assertTrue(any("metadata_revision" in error for error in rolling_manifest.validate_manifest(metadata_mismatch, ROOT)))

    def test_promoted_manifest_requires_all_passing_gate_evidence(self):
        manifest = json.loads((ROOT / "fixtures/rolling-intake/reference-snapshot.json").read_text())
        manifest["candidate"]["status"] = "promoted"
        manifest["manifest_sha256"] = rolling_manifest.canonical_digest(
            {k: v for k, v in manifest.items() if k != "manifest_sha256"}
        )
        errors = rolling_manifest.validate_manifest(manifest, ROOT)
        self.assertTrue(any("promotion_evidence" in error for error in errors))

    def test_failed_intake_retains_prior_candidate_and_cannot_be_promoted(self):
        manifest = json.loads((ROOT / "fixtures/rolling-intake/failed-intake-example.json").read_text())
        self.assertEqual(rolling_manifest.validate_manifest(manifest, ROOT), [])
        self.assertEqual(manifest["candidate"]["status"], "not-promoted")
        self.assertEqual(manifest["intake_outcome"]["gate_result"], "failed")
        self.assertTrue(manifest["intake_outcome"]["previous_candidate"]["retained_unchanged"])
        prior = manifest["intake_outcome"]["previous_candidate"]
        self.assertEqual(rolling_manifest.canonical_digest(prior["identity"]), prior["identity_sha256"])
        promoted = copy.deepcopy(manifest)
        promoted["candidate"]["status"] = "promoted"
        promoted["manifest_sha256"] = rolling_manifest.canonical_digest(
            {k: v for k, v in promoted.items() if k != "manifest_sha256"}
        )
        self.assertTrue(any("promotion_evidence" in error for error in rolling_manifest.validate_manifest(promoted, ROOT)))

    def test_manifest_records_exact_git_srcrev_for_cve_data(self):
        manifest = json.loads((ROOT / "fixtures/rolling-intake/reference-snapshot.json").read_text())
        revision = "a" * 40
        manifest["repositories"].append({
            "name": "cve-cvelist",
            "url": "https://github.com/CVEProject/cvelistV5.git",
            "revision": revision,
            "role": "fixture CVE database source",
        })
        manifest["recipe_sources"].append({
            "recipe": "sbom-cve-check-update-cvelist-native",
            "version": "main",
            "metadata_repository": "openembedded-core",
            "metadata_revision": "f94ae3d6ba49aef86f497998c0e0232a5039510a",
            "source_kind": "git",
            "source_repository": "cve-cvelist",
            "source_revision": revision,
            "source_uri": "git://github.com/CVEProject/cvelistV5.git;branch=main;protocol=https",
        })
        manifest["manifest_sha256"] = rolling_manifest.canonical_digest(
            {k: v for k, v in manifest.items() if k != "manifest_sha256"}
        )
        self.assertEqual(rolling_manifest.validate_manifest(manifest, ROOT), [])
        manifest["recipe_sources"][-1]["source_revision"] = "b" * 40
        manifest["manifest_sha256"] = rolling_manifest.canonical_digest(
            {k: v for k, v in manifest.items() if k != "manifest_sha256"}
        )
        self.assertTrue(any("source_revision" in error for error in rolling_manifest.validate_manifest(manifest, ROOT)))

    def test_openssl_analyzer_marks_missing_or_unpinned_artifact_not_clean(self):
        missing = run_openssl_gcc_analyzer.run(ROOT / "missing-openssl-archive.tar.gz")
        self.assertEqual(missing["state"], "not-run")
        with patch("pathlib.Path.is_file", return_value=True), patch(
            "scripts.run_openssl_gcc_analyzer.sha256", return_value="0" * 64
        ):
            wrong = run_openssl_gcc_analyzer.run(ROOT / "wrong-openssl-archive.tar.gz")
        self.assertEqual(wrong["state"], "tool-error")
        self.assertIsNone(wrong["tool_exit"])

    def test_manifest_replay_is_local_exact_and_non_promoting(self):
        report = rolling_manifest.replay_fixture()
        self.assertEqual(report["status"], "passed")
        self.assertFalse(report["network_used"])
        self.assertFalse(report["promotes_candidate"])
        self.assertEqual(len(report["revision"]), 40)
        expected = json.loads((ROOT / "evidence/rolling-intake-replay.json").read_text())
        self.assertEqual(report, expected)

    def test_analyzer_finding_records_preserve_triage_fields(self):
        record = run_openssl_gcc_analyzer.build_finding_records(
            ["bounded warning"],
            triage_owner="security owner",
            finding_disposition="reported-upstream",
            upstream_route="https://example.invalid/project/issues/1",
            applicability_rationale="Reproduces in the supported target configuration.",
        )[0]
        self.assertEqual(run_openssl_gcc_analyzer.triage_record_errors(record), [])
        self.assertEqual(record["triage_owner"], "security owner")
        self.assertEqual(record["disposition"], "reported-upstream")
        self.assertEqual(record["upstream_route"], "https://example.invalid/project/issues/1")
        self.assertEqual(
            record["applicability_rationale"],
            "Reproduces in the supported target configuration.",
        )
        pending = run_openssl_gcc_analyzer.build_finding_records(["bounded warning"])[0]
        self.assertTrue(run_openssl_gcc_analyzer.triage_record_errors(pending))

    def test_diagnostic_findings_include_triage_and_reject_missing_fields(self):
        report = advisory_lane_fixture.evaluate("finding-only")
        finding = report["diagnostics"]["finding_records"][0]
        self.assertEqual(run_openssl_gcc_analyzer.triage_record_errors(finding), [])
        incomplete = copy.deepcopy(finding)
        del incomplete["upstream_route"]
        self.assertTrue(any("upstream_route" in error for error in run_openssl_gcc_analyzer.triage_record_errors(incomplete)))
        clean = run_openssl_gcc_analyzer.run(ROOT / "missing-openssl-archive.tar.gz")
        self.assertEqual(clean["state"], "not-run")
        self.assertEqual(run_openssl_gcc_analyzer.triage_record_errors(clean["triage_summary"]), [])

    def test_diagnostic_findings_are_advisory_but_build_and_test_failures_block(self):
        finding = advisory_lane_fixture.evaluate("finding-only")
        self.assertEqual(finding["diagnostics"]["gate"], "advisory")
        self.assertFalse(finding["diagnostics"]["finding_alone_blocks"])
        self.assertEqual(finding["exit_code"], 0)
        for state in ("unsupported", "tool-error"):
            result = advisory_lane_fixture.evaluate(state)
            self.assertEqual(result["diagnostics"]["state"], state)
            self.assertTrue(result["diagnostics"]["invocation_problem_is_visible"])
        for state in ("build-failure", "test-failure"):
            result = advisory_lane_fixture.evaluate(state)
            self.assertEqual(result["exit_code"], 1)
            self.assertEqual(result["overall"], "failed")

    def test_advisory_cli_exit_status_preserves_primary_gate(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/advisory_lane_fixture.py"), "--scenario", "build-failure"],
            cwd=ROOT, text=True, capture_output=True, timeout=10,
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["diagnostics"]["state"], "findings")
        self.assertEqual(report["exit_code"], 1)

    def test_cve_fixture_cli_writes_report_and_preserves_failure_exit(self):
        script = ROOT / "scripts/cve_disposition_fixture.py"
        source = ROOT / "fixtures/cve/rolling-cve-fixture.json"
        document = json.loads(source.read_text())
        (ROOT / "tmp").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / "tmp") as temporary:
            output_path = Path(temporary) / "valid-report.json"
            valid = subprocess.run(
                [sys.executable, str(script), str(source), "--output", str(output_path)],
                cwd=ROOT, text=True, capture_output=True, timeout=10,
            )
            self.assertEqual(valid.returncode, 0, valid.stdout + valid.stderr)
            self.assertEqual(json.loads(valid.stdout), json.loads(output_path.read_text()))
            self.assertEqual(json.loads(valid.stdout)["status"], "passed")

            broken = copy.deepcopy(document)
            broken["records"] = []
            broken_path = Path(temporary) / "broken-fixture.json"
            broken_path.write_text(json.dumps(broken), encoding="utf-8")
            failure_path = Path(temporary) / "failure-report.json"
            failed = subprocess.run(
                [sys.executable, str(script), str(broken_path), "--output", str(failure_path)],
                cwd=ROOT, text=True, capture_output=True, timeout=10,
            )
            self.assertEqual(failed.returncode, 1, failed.stdout + failed.stderr)
            self.assertEqual(json.loads(failed.stdout), json.loads(failure_path.read_text()))
            self.assertEqual(json.loads(failed.stdout)["status"], "failed")

    def test_cve_fixture_covers_report_states_without_product_claim(self):
        fixture = json.loads((ROOT / "fixtures/cve/rolling-cve-fixture.json").read_text())
        self.assertEqual(cve_disposition_fixture.validate(fixture), [])
        self.assertEqual(fixture["product_evidence"], "not-run")
        ignored = next(item for item in fixture["records"] if item["report_status"] == "Ignored")
        del ignored["ignore_rationale"]
        self.assertTrue(any("ignore_rationale" in error for error in cve_disposition_fixture.validate(fixture)))

    def test_runtime_fixture_detects_removed_control_and_keeps_enforcement_open(self):
        report = runtime_containment_fixture.evaluate()
        self.assertEqual(report["static_policy"]["status"], "passed")
        self.assertEqual(report["negative_policy_test"]["status"], "passed")
        self.assertIn(report["systemd_syntax"]["status"], {"passed", "not-run"})
        self.assertEqual(report["kernel_configuration"]["status"], "not-run")
        self.assertEqual(report["runtime_enforcement"]["status"], "not-run")
        self.assertFalse(report["service_started"])
        kernel_reference = report["kernel_reference"]
        self.assertIn(kernel_reference["status"], {"observed-host-config-only", "not-run"})
        self.assertEqual(kernel_reference["product_kernel_status"], "not-run")
        self.assertEqual(kernel_reference["runtime_enforcement_status"], "not-run")
        for control in kernel_reference["controls"]:
            self.assertEqual(control["product_status"], "not-run")
            self.assertIn("v6.17", control["source"])
        if kernel_reference["status"] == "observed-host-config-only":
            controls = {control["symbol"]: control for control in kernel_reference["controls"]}
            self.assertEqual(controls["CONFIG_STRICT_KERNEL_RWX"]["observed_value"], "y")
            self.assertEqual(controls["CONFIG_PAGE_TABLE_CHECK"]["reference_status"], "disabled")

    def test_ci_path_filters_cover_authoritative_checklist_docs_and_fixtures(self):
        workflow = yaml.load(
            (ROOT / ".github/workflows/traceability.yml").read_text(),
            Loader=yaml.BaseLoader,
        )
        for event in ("push", "pull_request"):
            paths = workflow["on"][event]["paths"]
            self.assertIn("CHECKLIST.md", paths, f"{event} does not validate checklist edits")
            self.assertIn("docs/**", paths)
            self.assertIn("fixtures/**", paths)
            self.assertIn("scripts/**", paths)
            self.assertIn("traceability/**", paths)
            self.assertIn("tests/**", paths)
        steps = workflow["jobs"]["validate"]["steps"]
        self.assertTrue(
            any("scripts/rapid_hardening_checks.py" in step.get("run", "") for step in steps),
            "CI must run the unified local hardening verification suite",
        )

    def test_unified_runner_returns_failure_when_a_child_gate_fails(self):
        child_result = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="injected child failure"
        )
        child_stage = {"name": "injected", "status": "failed", "command": []}
        output = io.StringIO()
        with patch.object(rapid_hardening_checks, "doorstop_command", return_value="/fake/doorstop"):
            with patch.object(rapid_hardening_checks, "run_command", return_value=(child_stage, child_result)):
                with patch("sys.argv", ["rapid_hardening_checks"]), redirect_stdout(output):
                    exit_code = rapid_hardening_checks.main()
        self.assertEqual(exit_code, 1)
        report = json.loads(output.getvalue())
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["promotion_authorized"])

if __name__ == "__main__":
    unittest.main()
