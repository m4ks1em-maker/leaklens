import contextlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from leaklens.cli import main

from .helpers import rnd

SECRET = "ghp_" + rnd(36, seed=7)


def run(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(args))
    return code, out.getvalue(), err.getvalue()


def git(*args, cwd):
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.com")
    subprocess.run(["git", "-c", "commit.gpgsign=false", *args], cwd=cwd, env=env, check=True, capture_output=True)


class TempDirCase(unittest.TestCase):
    def setUp(self):
        self.old = os.getcwd()
        self.dir = Path(tempfile.mkdtemp(prefix="leaklens-test-")).resolve()
        os.chdir(self.dir)

    def tearDown(self):
        os.chdir(self.old)
        shutil.rmtree(self.dir, ignore_errors=True)


class PlainDirectoryTests(TempDirCase):
    def test_clean_directory(self):
        Path("app.py").write_text("print('hello')\n")
        code, out, _ = run("scan", "--no-color")
        self.assertEqual(code, 0)
        self.assertIn("No secrets found", out)

    def test_finding_sets_exit_code_and_hides_secret(self):
        Path("config.py").write_text(f"GITHUB = '{SECRET}'\n")
        code, out, _ = run("scan", "--no-color")
        self.assertEqual(code, 1)
        self.assertIn("config.py", out)
        self.assertIn("github-token", out)
        self.assertNotIn(SECRET, out)
        self.assertEqual(run("scan", "--exit-zero")[0], 0)
        self.assertIn(SECRET, run("scan", "--show-secrets")[1])

    def test_json_and_sarif(self):
        Path("config.py").write_text(f"GITHUB = '{SECRET}'\n")
        data = json.loads(run("scan", "--format", "json")[1])
        self.assertEqual((data["total"], data["findings"][0]["rule"], data["findings"][0]["line"]),
                         (1, "github-token", 1))
        sarif = json.loads(run("scan", "--format", "sarif")[1])
        result = sarif["runs"][0]["results"][0]
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(result["ruleId"], "github-token")
        self.assertEqual(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "config.py")
        self.assertNotIn(SECRET, json.dumps(sarif))

    def test_output_file_ignore_file_and_exclude(self):
        Path("config.py").write_text(f"GITHUB = '{SECRET}'\n")
        code, out, err = run("scan", "--format", "json", "-o", "report.json")
        self.assertEqual((code, out), (1, ""))
        self.assertIn("report.json", err)
        fingerprint = json.loads(Path("report.json").read_text())["findings"][0]["fingerprint"]
        self.assertEqual(run("scan", "--exclude", "config.py")[0], 0)
        Path(".leaklensignore").write_text(f"# reviewed\n{fingerprint}\n")
        self.assertEqual(run("scan")[0], 0)
        Path(".leaklensignore").write_text("*.py\n")
        self.assertEqual(run("scan")[0], 0)

    def test_errors(self):
        self.assertEqual(run("scan", "missing-dir")[0], 2)
        self.assertEqual(run("scan", "--staged")[0], 2)
        self.assertEqual(run("install-hook")[0], 2)
        self.assertEqual(run("rules")[0], 0)


@unittest.skipUnless(shutil.which("git"), "git is not installed")
class GitTests(TempDirCase):
    def setUp(self):
        super().setUp()
        git("init", "-q", cwd=self.dir)

    def test_gitignored_files_are_skipped_by_default(self):
        Path(".gitignore").write_text(".env\n")
        Path(".env").write_text(f"GITHUB_TOKEN={SECRET}\n")
        self.assertEqual(run("scan")[0], 0)
        self.assertEqual(run("scan", "--all-files")[0], 1)

    def test_staged(self):
        Path("a.py").write_text("x = 1\n")
        git("add", "a.py", cwd=self.dir)
        Path("b.py").write_text(f"t = '{SECRET}'\n")  # not staged
        self.assertEqual(run("scan", "--staged")[0], 0)
        git("add", "b.py", cwd=self.dir)
        code, out, _ = run("scan", "--staged", "--no-color")
        self.assertEqual(code, 1)
        self.assertIn("b.py", out)

    def test_history_finds_deleted_secret_and_its_commit(self):
        Path("a.py").write_text("x = 1\n")
        git("add", ".", cwd=self.dir)
        git("commit", "-qm", "init", cwd=self.dir)
        Path("a.py").write_text(f"x = 1\ny = 2\nt = '{SECRET}'\n")
        git("commit", "-qam", "add token", cwd=self.dir)
        Path("a.py").write_text("x = 1\ny = 2\n")
        git("commit", "-qam", "remove token", cwd=self.dir)

        self.assertEqual(run("scan")[0], 0)  # gone from the working tree
        code, out, _ = run("scan", "--history", "--format", "json")
        self.assertEqual(code, 1)
        (finding,) = json.loads(out)["findings"]
        log = subprocess.run(["git", "log", "--format=%H %s"], cwd=self.dir, capture_output=True, text=True).stdout
        sha = next(line.split()[0] for line in log.splitlines() if line.endswith("add token"))
        self.assertEqual((finding["file"], finding["line"], finding["commit"]), ("a.py", 3, sha[:12]))

    def test_history_of_empty_repository(self):
        self.assertEqual(run("scan", "--history")[0], 0)

    def test_install_hook(self):
        code, out, _ = run("install-hook")
        hook = Path(".git/hooks/pre-commit")
        self.assertEqual(code, 0)
        self.assertIn("leaklens scan --staged", hook.read_text())
        self.assertEqual(run("install-hook")[0], 0)  # re-installing our own hook is fine
        hook.write_text("#!/bin/sh\necho custom\n")
        self.assertEqual(run("install-hook")[0], 2)
        self.assertEqual(run("install-hook", "--force")[0], 0)


if __name__ == "__main__":
    unittest.main()
