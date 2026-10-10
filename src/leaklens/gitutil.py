"""Thin wrappers around the git command line."""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Iterator, List, Optional, Tuple

_COMMIT_MARK = "\x01"
_FIELD_SEP = "\x02"


class GitError(RuntimeError):
    pass


def _run(args: List[str], cwd: Path) -> bytes:
    try:
        proc = subprocess.run(["git", *args], cwd=str(cwd), capture_output=True)
    except FileNotFoundError as exc:
        raise GitError("git is not installed or not on PATH") from exc
    if proc.returncode != 0:
        raise GitError(proc.stderr.decode("utf-8", "replace").strip() or "git command failed")
    return proc.stdout


def repo_root(path: Path) -> Optional[Path]:
    """Top-level directory of the repository that contains `path`, if any."""
    start = path if path.is_dir() else path.parent
    try:
        out = _run(["rev-parse", "--show-toplevel"], start)
    except GitError:
        return None
    return Path(out.decode("utf-8", "replace").strip())


def list_files(directory: Path) -> List[str]:
    """Tracked plus untracked-but-not-ignored files, relative to `directory`."""
    out = _run(["ls-files", "-co", "--exclude-standard", "-z"], directory)
    return [p for p in out.decode("utf-8", "replace").split("\0") if p]


def staged_files(root: Path) -> List[str]:
    out = _run(["diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"], root)
    return [p for p in out.decode("utf-8", "replace").split("\0") if p]


def staged_content(root: Path, path: str) -> bytes:
    return _run(["show", f":{path}"], root)


def history_added_lines(root: Path) -> Iterator[Tuple[dict, str, int, str]]:
    """Yield (commit, path, line_number, text) for every line added in any commit.

    Commits come oldest first, so the first time a secret shows up is the
    commit that introduced it.
    """
    fmt = _COMMIT_MARK + _FIELD_SEP.join(["%H", "%an", "%aI"])
    args = ["git", "log", "--all", "--reverse", "-p", "--unified=0", "--no-color",
            "--no-ext-diff", "--no-textconv", f"--format={fmt}"]
    try:
        proc = subprocess.Popen(args, cwd=str(root), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError as exc:
        raise GitError("git is not installed or not on PATH") from exc

    commit: dict = {}
    path: Optional[str] = None
    lineno = 0
    in_header = False
    assert proc.stdout is not None
    for raw in proc.stdout:
        line = raw.decode("utf-8", errors="replace").rstrip("\n").rstrip("\r")
        if line.startswith(_COMMIT_MARK):
            sha, author, date = (line[1:].split(_FIELD_SEP) + ["", "", ""])[:3]
            commit = {"commit": sha[:12], "author": author, "date": date}
            path = None
        elif line.startswith("diff --git "):
            path, in_header = None, True
        elif in_header and line.startswith("+++ "):
            target = line[4:].strip().strip('"')
            path = None if target == "/dev/null" else target[2:] if target.startswith("b/") else target
        elif line.startswith("@@ "):
            in_header = False
            try:
                lineno = int(line.split("+", 1)[1].split(" ", 1)[0].split(",", 1)[0])
            except (IndexError, ValueError):
                lineno = 1
        elif not in_header and path and line.startswith("+"):
            yield commit, path, lineno, line[1:]
            lineno += 1
    stderr = proc.stderr.read().decode("utf-8", "replace") if proc.stderr else ""
    if proc.wait() != 0:
        # An empty repository has no commits yet: that is not an error.
        if "does not have any commits yet" in stderr:
            return
        raise GitError(stderr.strip() or "git log failed")
