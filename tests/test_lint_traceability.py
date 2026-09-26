"""Offline closure/schema regressions; synthetic evidence is never product evidence.

Run: .venv-doorstop/bin/python -m unittest discover -s tests -v
All mutations are confined to disposable copies under the repository's tmp/.
"""
from __future__ import annotations

import copy
import hashlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml
from doorstop.core.builder import build

ROOT = Path(__file__).resolve().parents[1]
DOCUMENTS = {
    "requirements": "REQ001",
    "entrypoints": "EP001",
    "risks": "RISK001",
    "controls": "CTRL001",
    "verification": "VER001",
}


class TraceabilityTests(unittest.TestCase):
    def setUp(self):
        (ROOT / "tmp").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="closure-test-", dir=ROOT / "tmp")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "scripts").mkdir()
        shutil.copy2(ROOT / "scripts/lint_traceability.py", self.root / "scripts")
        (self.root / "evidence").mkdir()
        (self.root / "evidence/fixture.md").write_text(
            "Synthetic local test observation; no product or upstream execution.\n",
            encoding="utf-8",
        )
        self.decision_path = self.root / "evidence/decision.md"
        self.decision_path.write_text(
            "Synthetic owner decision for the disposable test scope only.\n"
            "Test owner accepts missing evidence, or excludes a non-applicable check.\n"
            "This is not a real approval or a product verification result.\n",
            encoding="utf-8",
        )
        shutil.copytree(ROOT / "docs", self.root / "docs")
        shutil.copy2(ROOT / "CHECKLIST.md", self.root / "CHECKLIST.md")
        parent = None
        for dirname, uid in DOCUMENTS.items():
            directory = self.root / "traceability" / dirname
            directory.mkdir(parents=True)
            shutil.copy2(ROOT / "traceability" / dirname / ".doorstop.yml", directory)
            item = yaml.safe_load((ROOT / "traceability" / dirname / f"{uid}.yml").read_text())
            item["links"] = [parent] if parent else []
            item["reviewed"] = None
            for field in ("source_refs", "evidence_refs"):
                if field in item:
                    item[field] = ["evidence/fixture.md"]
            if dirname == "entrypoints":
                item.update(status="covered", disposition="finding")
            if dirname == "verification":
                item.update(verification_status="passed", observed="Synthetic fixture observation only.")
            self.write(dirname, item)
            parent = uid

    def path(self, dirname):
        return self.root / "traceability" / dirname / f"{DOCUMENTS[dirname]}.yml"

    def read(self, dirname):
        return yaml.safe_load(self.path(dirname).read_text())

    def write(self, dirname, item):
        self.path(dirname).write_text(yaml.safe_dump(item, sort_keys=False), encoding="utf-8")

    def update(self, dirname, **values):
        item = self.read(dirname)
        item.update(values)
        self.write(dirname, item)

    def decision(self, check="risk-evidence", outcome="accepted-residual"):
        return {
            "check": check,
            "outcome": outcome,
            "owner": "Test product risk owner",
            "decided_on": "2026-09-14",
            "scope": "Disposable synthetic test scope; no product claim.",
            "rationale": "Missing test evidence is explicitly retained in this test decision.",
            "decision_ref": "evidence/decision.md",
            "decision_sha256": hashlib.sha256(self.decision_path.read_bytes()).hexdigest(),
        }

    def run_lint(self, expected, warnings=None, strict=False, contains=None):
        command = [sys.executable, "scripts/lint_traceability.py"]
        if strict:
            command.append("--strict-completeness")
        result = subprocess.run(command, cwd=self.root, text=True, capture_output=True, timeout=30)
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, expected, output)
        self.assertNotIn("Traceback", output)
        if warnings is not None:
            self.assertIn(f"completeness warnings: {warnings}\n", output)
        if contains:
            self.assertIn(contains, output)
        summary = next(line for line in result.stdout.splitlines() if line.startswith("traceability errors:"))
        print(f"{self.id().rsplit('.', 1)[-1]} strict={strict}: exit={result.returncode}; {summary}")
        return output

    def test_local_source_refs_reject_out_of_range_lines(self):
        self.update("requirements", source_refs=["evidence/fixture.md:1-2"])
        self.run_lint(1, contains="line range 1-2 exceeds 1 lines")

    def test_local_worktree_code_refs_reject_out_of_range_lines(self):
        self.update(
            "entrypoints",
            code_refs=[{
                "repository": "checklist",
                "path": "evidence/fixture.md",
                "lines": "1-2",
                "revision": "worktree",
            }],
        )
        self.run_lint(1, contains="line range 1-2 exceeds 1 lines")

    def test_current_records_remain_open(self):
        shutil.copytree(ROOT / "traceability", self.root / "traceability", dirs_exist_ok=True)
        for dirname in ("docs", "evidence", "fixtures", "scripts"):
            shutil.copytree(ROOT / dirname, self.root / dirname, dirs_exist_ok=True)
        shutil.copy2(ROOT / "CHECKLIST.md", self.root)
        self.run_lint(0, warnings=15)
        self.run_lint(2, warnings=15, strict=True)

    def test_strong_evidence(self):
        for evidence_class in ("fixture-confirmed", "end-to-end", "product-verified", "deployment-verified"):
            with self.subTest(evidence_class=evidence_class):
                self.update("risks", evidence_class=evidence_class)
                self.run_lint(0, warnings=0, strict=True)
                print(f"accepted evidence_class={evidence_class}")

    def test_weak_evidence_is_warning_only(self):
        for evidence_class in ("source-confirmed", "source-supported", "hypothesis", "not-run"):
            with self.subTest(evidence_class=evidence_class):
                self.update("risks", evidence_class=evidence_class)
                self.run_lint(0, warnings=1, contains="[risk-evidence]")
                self.run_lint(2, warnings=1, strict=True)

    def test_closures_accept_both_outcomes_without_upgrading_evidence(self):
        for outcome in ("accepted-residual", "justified-exclusion"):
            with self.subTest(outcome=outcome):
                self.update("risks", evidence_class="not-run", closures=[self.decision(outcome=outcome)])
                output = self.run_lint(0, warnings=0, strict=True, contains=f"risk-evidence={outcome}")
                self.assertIn("(not verification evidence)", output)
                self.assertEqual(self.read("risks")["evidence_class"], "not-run")
                print(f"accepted closure outcome={outcome}; evidence_class remains not-run")

    def test_closures_are_scoped_and_do_not_propagate(self):
        self.update("risks", evidence_class="not-run", closures=[self.decision()])
        self.update("verification", verification_status="planned")
        self.run_lint(2, warnings=1, strict=True, contains="[verification-result]")
        self.update("verification", closures=[self.decision("verification-result")])
        self.run_lint(0, warnings=0, strict=True)
        self.assertEqual(self.read("verification")["verification_status"], "planned")
        self.update("controls", active=False)
        self.run_lint(2, warnings=1, strict=True, contains="[missing-child]")
        self.update("risks", closures=[self.decision(), self.decision("missing-child")])
        self.run_lint(0, warnings=0, strict=True)

    def test_missing_child_can_be_justifiably_excluded(self):
        self.path("verification").unlink()
        self.run_lint(0, warnings=1, contains="[missing-child]")
        self.update("controls", closures=[self.decision("missing-child", "justified-exclusion")])
        self.run_lint(0, warnings=0, strict=True, contains="missing-child=justified-exclusion")

    def test_covered_does_not_hide_unverified_disposition(self):
        for disposition in ("unverified", "hypothesis", "gap"):
            with self.subTest(disposition=disposition):
                self.update("entrypoints", status="covered", disposition=disposition)
                self.run_lint(0, warnings=1, contains="[entrypoint-coverage]")
                self.run_lint(2, warnings=1, strict=True)
        self.update("entrypoints", status="unverified", closures=[self.decision("entrypoint-coverage")])
        self.run_lint(0, warnings=0, strict=True)
        self.assertEqual(self.read("entrypoints")["status"], "unverified")

    def test_closure_required_fields(self):
        for key in self.decision():
            for mode in ("missing", "blank", "wrong-type"):
                with self.subTest(key=key, mode=mode):
                    decision = self.decision()
                    if mode == "missing":
                        del decision[key]
                    else:
                        decision[key] = " " if mode == "blank" else []
                    self.update("risks", closures=[decision])
                    self.run_lint(1, contains="closures[0]")

    def test_invalid_closure_states(self):
        cases = [
            {"outcome": "covered"}, {"outcome": "passed"}, {"outcome": "evidence"},
            {"check": "verification-result"}, {"check": "all"},
            {"decided_on": "2026-02-30"}, {"decided_on": "20260914"},
            {"decision_ref": "evidence/missing.md"}, {"decision_ref": "evidence"},
            {"decision_ref": "../outside.md"}, {"decision_ref": str(self.decision_path)},
            {"decision_sha256": "not-a-hash"}, {"decision_sha256": "0" * 64},
            {"extra": "unrecognized"},
        ]
        for values in cases:
            with self.subTest(values=values):
                decision = self.decision()
                decision.update(values)
                self.update("risks", closures=[decision])
                self.run_lint(1, contains="closures[0]")
        for closures in (None, {}, "accepted-residual", [None], [self.decision(), self.decision()]):
            with self.subTest(closures=closures):
                self.update("risks", closures=closures)
                self.run_lint(1, contains="closures")

    def test_changed_decision_content_is_blocking(self):
        self.update("risks", closures=[self.decision()])
        self.decision_path.write_text("Changed scope after owner decision.\n", encoding="utf-8")
        self.run_lint(1, contains="does not match decision_ref content")

    def test_symlink_escape_is_blocking(self):
        # The outside file is also disposable and inside the authorized worktree.
        with tempfile.TemporaryDirectory(dir=ROOT / "tmp") as outside:
            target = Path(outside) / "outside.md"
            target.write_text("Outside the fixture root.\n", encoding="utf-8")
            (self.root / "evidence/link.md").symlink_to(target)
            decision = self.decision()
            decision.update(decision_ref="evidence/link.md", decision_sha256=hashlib.sha256(target.read_bytes()).hexdigest())
            self.update("risks", closures=[decision])
            self.run_lint(1, contains="existing repository-local file")

    def test_closures_require_fingerprint_configuration(self):
        for dirname in DOCUMENTS:
            with self.subTest(dirname=dirname):
                path = self.root / "traceability" / dirname / ".doorstop.yml"
                original = path.read_text()
                config = yaml.safe_load(original)
                config["attributes"]["reviewed"].remove("closures")
                path.write_text(yaml.safe_dump(config), encoding="utf-8")
                self.run_lint(1, contains="missing material fields: ['closures']")
                path.write_text(original, encoding="utf-8")

    def test_doorstop_fingerprints_every_closure_field(self):
        for dirname, uid in DOCUMENTS.items():
            check = {"entrypoints": "entrypoint-coverage", "risks": "risk-evidence", "verification": "verification-result"}.get(dirname, "missing-child")
            original = self.read(dirname)
            original["closures"] = [self.decision(check)]
            self.write(dirname, original)
            tree = build(cwd=str(self.root), root=str(self.root))
            item = tree.find_item(uid)
            stamp = str(item.stamp())
            for key in original["closures"][0]:
                with self.subTest(dirname=dirname, field=key):
                    modified = copy.deepcopy(original)
                    modified["closures"][0][key] += " changed"
                    self.write(dirname, modified)
                    item.load(reload=True)
                    self.assertNotEqual(str(item.stamp()), stamp, f"{dirname}.{key} not fingerprinted")
            self.write(dirname, original)

    def test_malformed_yaml_is_blocking(self):
        for text in ("broken: [", "null\n", "[]\n", "active: true\nactive: false\n", "? [a, b]\n: value\n", "1: numeric-key\n"):
            with self.subTest(text=text):
                self.path("risks").write_text(text, encoding="utf-8")
                self.run_lint(1, contains="invalid YAML")
        (self.root / "traceability/risks/.doorstop.yml").write_text("null\n", encoding="utf-8")
        self.run_lint(1, contains="document must be a mapping")

    def test_invalid_model_values_are_blocking(self):
        original = self.read("risks")
        for values in (
            {"evidence_class": "product-specific"}, {"evidence_class": []},
            {"evidence_class": {}}, {"evidence_class": None},
            {"active": "true"}, {"finding_id": "F-01"}, {"finding_id": " F-001"},
            {"code_refs": []}, {"evidence_refs": []}, {"unexpected": True},
            {"links": None}, {"links": [42]}, {"links": [{"EP001": []}]},
        ):
            with self.subTest(values=values):
                self.write("risks", {**original, **values})
                self.run_lint(1, contains="ERROR:")

    def test_broken_links_and_duplicate_ids_are_blocking(self):
        for links, message in (
            (["EP999"], "link target EP999 does not exist"),
            (["REQ001"], "must target document prefix EP"),
            (["EP001", "EP001"], "duplicate link UID"),
            (["EP01"], "links must contain UID"),
        ):
            with self.subTest(links=links):
                self.update("risks", links=links)
                self.run_lint(1, contains=message)
        self.update("risks", links=["EP001"], closures=[self.decision()])
        duplicate = self.read("risks")
        duplicate["level"] = "2.2"
        duplicate_path = self.path("risks").with_name("RISK002.yml")
        duplicate_path.write_text(yaml.safe_dump(duplicate), encoding="utf-8")
        self.run_lint(1, contains="duplicate finding_id F-001")
        duplicate_path.unlink()
        invalid_path = self.path("risks").with_name("RISKX001.yml")
        self.path("risks").rename(invalid_path)
        self.run_lint(1, contains="filename is not a RISK### UID")

    def test_closure_never_suppresses_integrity_errors(self):
        self.update("risks", evidence_class="not-run", closures=[self.decision()], links=["EP999"])
        output = self.run_lint(1, strict=True, contains="link target EP999 does not exist")
        self.assertNotIn("CLOSURE:", output)


if __name__ == "__main__":
    unittest.main()
