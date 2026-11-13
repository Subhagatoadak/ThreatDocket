import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from threatdocket import ci
from threatdocket.cli import main
from threatdocket.review import review
from threatdocket.static import excluded

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "examples" / "demo"


class ExcludeTests(unittest.TestCase):
    def test_patterns(self):
        self.assertTrue(excluded("tests/a.py", ["tests/**"]))
        self.assertTrue(excluded("tests/x/a.py", ["tests"]))
        self.assertTrue(excluded("a/b.yaml", ["*.yaml"]))
        self.assertTrue(excluded("Dockerfile", [" Dockerfile "]))
        self.assertFalse(excluded("src/tests_helper.py", ["tests"]))
        self.assertFalse(excluded("src/a.py", ["", "docs/**"]))

    def test_review_respects_exclude(self):
        all_findings = review(DEMO)["findings"]
        some = review(DEMO, exclude=["Dockerfile"])["findings"]
        self.assertTrue(any(f["path"] == "Dockerfile" for f in all_findings))
        self.assertFalse(any(f["path"] == "Dockerfile" for f in some))
        self.assertEqual(review(DEMO, exclude=["**"])["findings"], [])


class FormatTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = review(DEMO)

    def test_sarif_structure(self):
        sarif = ci.to_sarif(self.report, DEMO, base=ROOT)
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        self.assertEqual(run["tool"]["driver"]["name"], "ThreatDocket")
        self.assertEqual(len(run["results"]), len(self.report["findings"]))
        for result in run["results"]:
            self.assertEqual(rules[result["ruleIndex"]]["id"], result["ruleId"])
            location = result["locations"][0]["physicalLocation"]
            self.assertTrue(location["artifactLocation"]["uri"].startswith("examples/demo/"))
            self.assertGreaterEqual(location["region"]["startLine"], 1)
            self.assertIn(result["level"], {"error", "warning"})
        for rule in rules:
            self.assertGreater(float(rule["properties"]["security-severity"]), 0)
        json.dumps(sarif)

    def test_paths_outside_base_stay_relative(self):
        self.assertEqual(ci.repo_path(DEMO, "Dockerfile", base="/nonexistent-root"), "Dockerfile")

    def test_annotations_escape_and_levels(self):
        lines = ci.annotations(self.report, DEMO, base=ROOT)
        self.assertEqual(len(lines), len(self.report["findings"]))
        self.assertTrue(all(l.startswith(("::error ", "::warning ")) for l in lines))
        self.assertTrue(any("file=examples/demo/Dockerfile,line=2," in l for l in lines))
        report = {"findings": [{"status": "FAIL", "path": "a,b:c\n::error::x.py", "line": 3, "rule": "RUN001",
                                "title": "t", "action": "50% done\nnext", "technique": "AML.T0050"}],
                  "controls": [], "warnings": []}
        line = ci.annotations(report, "/nowhere", base="/elsewhere")[0]
        self.assertEqual(line.count("\n"), 0)
        self.assertIn("a%2Cb%3Ac%0A%3A%3Aerror%3A%3Ax.py", line)
        self.assertIn("50%25 done%0Anext", line)

    def test_markdown_summary(self):
        text = ci.markdown_summary(self.report, DEMO, base=ROOT)
        self.assertIn("❌ ThreatDocket scan", text)
        self.assertIn("**4** FAIL · **1** REVIEW", text)
        self.assertIn("`examples/demo/Dockerfile:2`", text)
        clean = ci.markdown_summary(review(DEMO, exclude=["**"]), DEMO)
        self.assertIn("✅", clean)
        self.assertIn("No static rule matched", clean)


class CLITests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)

    def run_cli(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = main(list(args))
        return code, out.getvalue()

    def test_ci_outputs_and_exit_codes(self):
        summary = self.tmp / "summary.md"
        summary.write_text("existing\n")
        code, out = self.run_cli("scan", str(DEMO), "--sarif", str(self.tmp / "r.sarif"),
                                 "--output", str(self.tmp / "r.json"), "--summary", str(summary),
                                 "--annotations", "--fail-on-findings")
        self.assertEqual(code, 1)
        self.assertTrue(out.startswith("::"))           # annotations, not the JSON report
        self.assertNotIn('"schema_version"', out)
        self.assertEqual(json.loads((self.tmp / "r.sarif").read_text())["version"], "2.1.0")
        self.assertTrue(summary.read_text().startswith("existing\n## "))  # appended, not replaced
        code, _ = self.run_cli("scan", str(DEMO), "--exclude", "Dockerfile, deployment.yaml",
                               "--exclude", ".github/**", "--fail-on-findings", "--output", str(self.tmp / "c.json"))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads((self.tmp / "c.json").read_text())["findings"], [])

    def test_sarif_not_overwritten(self):
        target = self.tmp / "r.sarif"
        target.write_text("keep")
        code, _ = self.run_cli("scan", str(DEMO), "--sarif", str(target))
        self.assertEqual(code, 2)
        self.assertEqual(target.read_text(), "keep")

    def test_plain_scan_still_prints_json(self):
        code, out = self.run_cli("scan", str(DEMO))
        self.assertEqual(code, 0)
        self.assertIn('"schema_version"', out)


if __name__ == "__main__":
    unittest.main()
