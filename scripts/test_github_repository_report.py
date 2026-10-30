import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("report", Path(__file__).with_name("github-repository-report.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def log(severities):
    return {"runs": [{"tool": {"driver": {"rules": []}}, "results": [
        {"ruleId": "secret-private-key", "level": "error", "properties": {"severity": s}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": ".env.example"}, "region": {"startLine": 1, "snippet": {"text": "secret never sent"}}}}]}
        for s in severities]}]}


class ReportTests(unittest.TestCase):
    env = {"SCAN_STATUS": "clean", "GITHUB_REPOSITORY": "our/repo", "GITHUB_RUN_ID": "123", "THREATCRUSH_REPO_TOKEN": "test"}

    def test_warning_and_critical_separate(self):
        lines, failed = module.report(log(["high", "critical"]), {"SCAN_STATUS": "clean"})
        self.assertFalse(failed)
        self.assertIn("**CRITICAL**: 1 | **Warnings**: 1", "\n".join(lines))
        self.assertIn("WARNING (test/example)", "\n".join(lines))

    def test_silence_retains_critical_and_no_credential_metadata(self):
        def submit(payload, token):
            self.assertNotIn("secret never sent", str(payload))
            return {"visible": [1]}
        data = log(["high", "critical"])
        lines, failed = module.report(data, self.env, submit)
        self.assertFalse(failed)
        self.assertIn("Silenced warnings**: 1", "\n".join(lines))
        self.assertIn("suppressions", data["runs"][0]["results"][0])
        self.assertNotIn("suppressions", data["runs"][0]["results"][1])

    def test_critical_cannot_be_silenced_by_response(self):
        lines, failed = module.report(log(["critical"]), self.env, lambda *args: {"visible": []})
        self.assertTrue(failed)
        self.assertIn("CRITICAL", "\n".join(lines))

    def test_network_failure_reports_local_findings_and_fails(self):
        def failure(*args):
            raise RuntimeError("token must not be echoed")
        lines, failed = module.report(log(["high"]), self.env, failure)
        self.assertTrue(failed)
        self.assertIn("connection failed", "\n".join(lines))
        self.assertNotIn("token must not be echoed", "\n".join(lines))

    def test_not_run_is_never_clean(self):
        lines, failed = module.report(log([]), {})
        self.assertIn("NOT RUN", "\n".join(lines))
        self.assertNotIn("No findings", "\n".join(lines))

    def test_rule_score_preserves_critical_legacy_metadata(self):
        self.assertEqual(module.severity({"ruleId": "x", "level": "error"}, {"x": {"properties": {"security-severity": "9.5"}}}), "critical")


if __name__ == "__main__":
    unittest.main()
