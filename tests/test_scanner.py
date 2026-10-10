import unittest

from leaklens.rules import RULES
from leaklens.scanner import Scanner, entropy, is_placeholder, redact

from .helpers import rnd, samples


class RuleTests(unittest.TestCase):
    def test_every_rule_has_a_sample(self):
        self.assertEqual({r.id for r in RULES}, set(samples()))

    def test_each_sample_triggers_its_rule(self):
        scanner = Scanner()
        for rule_id, line in samples().items():
            with self.subTest(rule=rule_id):
                found = [f.rule_id for f in scanner.scan_line(line, 1, "x.txt")]
                self.assertEqual(found, [rule_id])

    def test_clean_code_has_no_findings(self):
        clean = "\n".join([
            "import os",
            "TOKEN = os.environ['BOT_TOKEN']",
            'password = "changeme"',
            'api_key = "<your-api-key>"',
            'secret = "${SECRET_FROM_VAULT}"',
            "API_KEY=",
            "PASSWORD=example_password",
            "url = 'postgres://localhost:5432/app'",
            "url = 'postgres://user:password@localhost/app'",
            "sha = '3f786850e387550fdab836ed7e6dc881de23001b'",
            "def get_token(user): return tokens[user.id]",
            "AKIAIOSFODNN7EXAMPLE",
            "token_type = 'bare-quoted-string'",
            "'pwd': 'pwd#module-pwd',",
            '"libsecret-1.so.0": "libsecret-1-0",',
            "ERRORTOKEN = token.ERRORTOKEN",
            "password_field = 'input#login-pass1'",
            '"Unexpected_token_1012": "\u4e88\u671f\u3057\u306a\u3044\u30c8\u30fc\u30af\u30f3"',
        ])
        self.assertEqual(Scanner().scan_text(clean, "clean.py"), [])


class ScannerTests(unittest.TestCase):
    def test_reports_position(self):
        text = "a = 1\n  key = 'ghp_" + rnd(36) + "'\n"
        (finding,) = Scanner().scan_text(text, "app.py")
        self.assertEqual((finding.line, finding.column), (2, 10))

    def test_specific_rule_wins_over_generic(self):
        line = 'token = "ghp_' + rnd(36) + '"'
        self.assertEqual([f.rule_id for f in Scanner().scan_line(line, 1, "a.py")], ["github-token"])

    def test_inline_ignore_marker(self):
        line = "ghp_" + rnd(36) + "  # leaklens:ignore"
        self.assertEqual(Scanner().scan_line(line, 1, "a.py"), [])

    def test_fingerprint_ignore(self):
        line = "ghp_" + rnd(36)
        (finding,) = Scanner().scan_line(line, 1, "a.py")
        scanner = Scanner(ignore_fingerprints=[finding.fingerprint])
        self.assertEqual(scanner.scan_line(line, 1, "a.py"), [])

    def test_min_severity(self):
        text = "\n".join(samples().values())
        severities = {f.severity for f in Scanner(min_severity="high").scan_text(text, "a.txt")}
        self.assertTrue(severities)
        self.assertLessEqual(severities, {"high", "critical"})

    def test_binary_and_oversized_content_is_skipped(self):
        secret = ("ghp_" + rnd(36)).encode()
        self.assertEqual(Scanner().scan_bytes(b"\x00\x01" + secret, "a.bin"), [])
        self.assertEqual(Scanner(max_file_size=10).scan_bytes(secret, "a.txt"), [])
        self.assertEqual(len(Scanner().scan_bytes(secret, "a.txt")), 1)

    def test_path_filtering(self):
        scanner = Scanner(ignore_patterns=["docs/", "*.sample", "fixtures/*.json"])
        for path in ["node_modules/x/index.js", "a/.git/config", "yarn.lock", "logo.PNG", "app.min.js",
                     "docs/setup.md", "conf/env.sample", "fixtures/users.json"]:
            self.assertTrue(scanner.path_ignored(path), path)
        for path in ["src/app.py", ".env", "config/settings.json", "mydocs/readme.md"]:
            self.assertFalse(scanner.path_ignored(path), path)

    def test_redaction_never_shows_the_whole_secret(self):
        secret = "ghp_" + rnd(36)
        self.assertNotIn(secret[6:-2], redact(secret))
        finding = Scanner().scan_line(secret, 1, "a.py")[0]
        self.assertNotIn(secret, str(finding.to_dict()))
        self.assertIn(secret, str(finding.to_dict(show_secrets=True)))

    def test_helpers(self):
        self.assertEqual(entropy(""), 0)
        self.assertEqual(entropy("aaaa"), 0)
        self.assertAlmostEqual(entropy("abcd"), 2.0)
        self.assertTrue(is_placeholder("YOUR_API_KEY_HERE"))
        self.assertFalse(is_placeholder(rnd(20)))


if __name__ == "__main__":
    unittest.main()
