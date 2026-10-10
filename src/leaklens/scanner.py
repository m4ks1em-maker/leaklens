"""Core scanning logic: turns text into a list of findings."""
from __future__ import annotations

import fnmatch
import hashlib
import math
import os
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .rules import RULES, SEVERITIES, Rule, build_prefilter

IGNORE_MARKER = "leaklens:ignore"
IGNORE_FILE = ".leaklensignore"
MAX_LINE_LENGTH = 20_000
DEFAULT_MAX_FILE_SIZE = 2 * 1024 * 1024

EXCLUDED_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "bower_components", "vendor", "venv", ".venv", "env",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".tox", "dist", "build", "target", ".idea",
    ".vscode", ".next", ".nuxt", "coverage", "site-packages",
}
EXCLUDED_NAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock",
    "composer.lock", "Cargo.lock", "go.sum", "Gemfile.lock", IGNORE_FILE,
}
EXCLUDED_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".svg", ".pdf", ".zip", ".gz", ".tar",
    ".7z", ".rar", ".jar", ".exe", ".dll", ".so", ".dylib", ".bin", ".pyc", ".class", ".woff",
    ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".mov", ".avi", ".webm", ".dem", ".vpk",
    ".min.js", ".min.css", ".map", ".lock",
)

_PLACEHOLDER_PARTS = ("example", "changeme", "change_me", "placeholder", "xxxx", "****", "....",
                      "your_", "your-", "<", ">", "${", "{{", "%s", "redacted", "insert", "todo")
_PLACEHOLDER_PREFIXES = ("test", "dummy", "fake", "sample", "demo", "mock", "$", "env(", "os.environ",
                         "process.env", "getenv")
_PLACEHOLDER_VALUES = {"password", "passwd", "secret", "token", "pass", "user", "username", "root",
                       "admin", "none", "null", "true", "false", "undefined", "localhost"}


# A function call ("client.login(") or an escaped string ("\\u4e88\\u671f") is code, not a secret.
_CODE_LIKE = re.compile(r"[A-Za-z_]\w*\(|\\u[0-9a-fA-F]{4}")


def entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    total = len(text)
    return -sum(n / total * math.log2(n / total) for n in Counter(text).values())


def looks_fake(secret: str) -> bool:
    """Documentation tokens: ones marked EXAMPLE or made of a few repeated characters."""
    if "example" in secret.lower():
        return True
    return len(set(secret)) <= max(2, min(5, len(secret) // 4))


def is_placeholder(value: str) -> bool:
    low = value.lower()
    return (low in _PLACEHOLDER_VALUES
            or low.startswith(_PLACEHOLDER_PREFIXES)
            or any(part in low for part in _PLACEHOLDER_PARTS))


def looks_like_word(value: str) -> bool:
    """'quoted-string', 'TokenError', 'token.EOF': identifiers or prose, not credentials."""
    if not value.isascii() or _CODE_LIKE.search(value):
        return True
    if any(c.isdigit() for c in value) or any(not c.isalnum() and c not in "-_./: " for c in value):
        return False
    return not (len(value) >= 20 and entropy(value) >= 4.0)


def echoes_name(value: str, name: str) -> bool:
    """`'pwd': 'pwd#module-pwd'`: the value just repeats its own key."""
    value, name = value.lower(), name.lower()
    return len(name) >= 3 and (value.startswith(name[:5]) or name in value)


def redact(secret: str) -> str:
    if len(secret) >= 12:
        return f"{secret[:4]}{'*' * 8}{secret[-2:]}"
    return f"{secret[:2]}{'*' * 6}"


@dataclass
class Finding:
    rule_id: str
    description: str
    severity: str
    path: str
    line: int
    column: int
    secret: str
    commit: Optional[str] = None
    author: Optional[str] = None
    date: Optional[str] = None

    @property
    def fingerprint(self) -> str:
        raw = f"{self.rule_id}:{self.path}:{self.secret}".encode("utf-8", "replace")
        return hashlib.sha256(raw).hexdigest()[:16]

    def to_dict(self, show_secrets: bool = False) -> Dict[str, object]:
        data: Dict[str, object] = {
            "rule": self.rule_id,
            "description": self.description,
            "severity": self.severity,
            "file": self.path,
            "line": self.line,
            "column": self.column,
            "match": self.secret if show_secrets else redact(self.secret),
            "fingerprint": self.fingerprint,
        }
        if self.commit:
            data.update(commit=self.commit, author=self.author, date=self.date)
        return data


def load_ignore_file(directory: Path) -> Tuple[List[str], Set[str]]:
    """Read .leaklensignore: glob patterns and 16-char finding fingerprints."""
    patterns: List[str] = []
    fingerprints: Set[str] = set()
    path = directory / IGNORE_FILE
    if not path.is_file():
        return patterns, fingerprints
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if len(line) == 16 and all(c in "0123456789abcdef" for c in line):
            fingerprints.add(line)
        else:
            patterns.append(line)
    return patterns, fingerprints


class Scanner:
    def __init__(self, rules: Sequence[Rule] = RULES, min_severity: str = "low",
                 ignore_patterns: Iterable[str] = (), ignore_fingerprints: Iterable[str] = (),
                 max_file_size: int = DEFAULT_MAX_FILE_SIZE) -> None:
        threshold = SEVERITIES.index(min_severity)
        self.rules = [r for r in rules if SEVERITIES.index(r.severity) >= threshold]
        self._prefilter = build_prefilter(self.rules)
        self.ignore_patterns = list(ignore_patterns)
        self.ignore_fingerprints = set(ignore_fingerprints)
        self.max_file_size = max_file_size
        self.files_scanned = 0

    # -- path filtering ---------------------------------------------------
    def path_ignored(self, path: str) -> bool:
        posix = path.replace(os.sep, "/").lstrip("./")
        parts = posix.split("/")
        name = parts[-1]
        if any(part in EXCLUDED_DIRS for part in parts[:-1]):
            return True
        if name in EXCLUDED_NAMES or name.lower().endswith(EXCLUDED_SUFFIXES):
            return True
        for pattern in self.ignore_patterns:
            if pattern.endswith("/"):
                if posix.startswith(pattern) or f"/{pattern}" in f"/{posix}":
                    return True
            elif fnmatch.fnmatch(posix, pattern) or fnmatch.fnmatch(name, pattern):
                return True
        return False

    # -- text scanning ----------------------------------------------------
    def scan_line(self, line: str, lineno: int, path: str, **meta) -> List[Finding]:
        if len(line) > MAX_LINE_LENGTH:
            return []
        lowered = line.lower()
        if not self._prefilter.search(lowered) or IGNORE_MARKER in line:
            return []
        findings: List[Finding] = []
        taken: List[Tuple[int, int]] = []
        for rule in self.rules:
            if not rule.hint.search(lowered):
                continue
            for match in rule.pattern.finditer(line):
                secret = match.group(rule.group)
                start, end = match.span(rule.group)
                if any(start < t_end and t_start < end for t_start, t_end in taken):
                    continue
                if rule.id != "private-key" and looks_fake(secret):
                    continue
                if rule.generic and is_placeholder(secret):
                    continue
                if rule.strict_value and looks_like_word(secret):
                    continue
                name = match.groupdict().get("name")
                if name and echoes_name(secret, name):
                    continue
                if rule.min_entropy and entropy(secret) < rule.min_entropy:
                    continue
                finding = Finding(rule.id, rule.description, rule.severity, path, lineno,
                                  start + 1, secret, **meta)
                if finding.fingerprint in self.ignore_fingerprints:
                    continue
                taken.append((start, end))
                findings.append(finding)
        return findings

    def scan_text(self, text: str, path: str, **meta) -> List[Finding]:
        findings: List[Finding] = []
        for lineno, line in enumerate(text.splitlines(), 1):
            findings.extend(self.scan_line(line, lineno, path, **meta))
        return findings

    def scan_bytes(self, data: bytes, path: str, **meta) -> List[Finding]:
        if len(data) > self.max_file_size or b"\x00" in data[:8192]:
            return []
        self.files_scanned += 1
        return self.scan_text(data.decode("utf-8", errors="replace"), path, **meta)

    def scan_file(self, file: Path, display_path: str) -> List[Finding]:
        try:
            if file.stat().st_size > self.max_file_size:
                return []
            return self.scan_bytes(file.read_bytes(), display_path)
        except OSError:
            return []
