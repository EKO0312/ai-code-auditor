import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import auditor  # noqa: E402

SAMPLE = Path(__file__).resolve().parent.parent / "sample"


class AuditorTests(unittest.TestCase):
    def rules(self, findings):
        return {f.rule for f in findings}

    def test_sample_triggers_expected_rules(self):
        findings, _ = auditor.audit(SAMPLE, offline=True)
        expected = {"AIC001", "AIC002", "AIC003", "AIC004", "AIC005", "AIC006", "AIC007", "AIC008", "AIC009"}
        self.assertTrue(expected <= self.rules(findings), expected - self.rules(findings))

    def test_undeclared_import_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "a.py").write_text("import requests\nimport yaml\n")
            (Path(d) / "requirements.txt").write_text("pyyaml\n")
            findings, _ = auditor.audit(d, offline=True)
            msgs = [f.message for f in findings if f.rule == "AIC020"]
            self.assertEqual(len(msgs), 1)
            self.assertIn("requests", msgs[0])

    def test_clean_code_has_no_findings(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "ok.py").write_text(
                "import json\nimport subprocess\nimport secrets\n\n"
                "def f(x):\n    subprocess.run(['ls', x], check=True)\n    return json.dumps({'t': secrets.token_urlsafe(8)})\n")
            findings, _ = auditor.audit(d, offline=True)
            self.assertEqual(findings, [])

    def test_placeholder_secret_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "c.py").write_text('API_KEY = "your-api-key-here"\n')
            findings, _ = auditor.audit(d, offline=True)
            self.assertNotIn("AIC007", self.rules(findings))

    def test_safe_yaml_and_params_not_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "s.py").write_text(
                "import yaml\ndef f(cur, v, s):\n    cur.execute('SELECT 1 WHERE id = ?', (v,))\n    return yaml.safe_load(s)\n")
            findings, _ = auditor.audit(d, offline=True)
            self.assertEqual(self.rules(findings) - {"AIC020"}, set())

    def test_known_key_formats_detected(self):
        # Fake keys are assembled at runtime so no real-looking secret sits in the repo.
        with tempfile.TemporaryDirectory() as d:
            fake_openai = "sk" + "-" + "a" * 24
            fake_aws = "AK" + "IA" + "B" * 16
            (Path(d) / "k.py").write_text(f'x = "{fake_openai}"\ny = "{fake_aws}"\n')
            findings, _ = auditor.audit(d, offline=True)
            labels = " ".join(f.message for f in findings if f.rule == "AIC007")
            self.assertIn("OpenAI-style", labels)
            self.assertIn("AWS", labels)

    def test_fail_on_exit_code(self):
        self.assertEqual(auditor.main([str(SAMPLE), "--offline", "--fail-on", "high"]), 1)

    def test_missing_path(self):
        self.assertEqual(auditor.main(["/no/such/path"]), 2)


if __name__ == "__main__":
    unittest.main()
