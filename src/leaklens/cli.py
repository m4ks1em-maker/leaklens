"""Command line interface."""
from __future__ import annotations

import argparse
import os
import stat
import sys
import time
from pathlib import Path
from typing import List, Optional, Sequence

from . import __version__, gitutil, report
from .rules import RULES, SEVERITIES
from .scanner import DEFAULT_MAX_FILE_SIZE, EXCLUDED_DIRS, Finding, Scanner, load_ignore_file

EXIT_CLEAN, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2
HOOK_MARK = "# leaklens pre-commit hook"


def _display(path: Path) -> str:
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _walk(directory: Path) -> List[Path]:
    files: List[Path] = []
    for current, dirs, names in os.walk(directory):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED_DIRS)
        files.extend(Path(current) / name for name in sorted(names))
    return files


def scan_worktree(scanner: Scanner, targets: Sequence[Path], all_files: bool) -> List[Finding]:
    findings: List[Finding] = []
    for target in targets:
        if target.is_file():
            findings.extend(scanner.scan_file(target, _display(target)))
            continue
        if not target.is_dir():
            raise FileNotFoundError(f"path does not exist: {target}")
        if not all_files and gitutil.repo_root(target):
            files = [target / rel for rel in gitutil.list_files(target)]
        else:
            files = _walk(target)
        for file in files:
            shown = _display(file)
            if file.is_file() and not scanner.path_ignored(shown):
                findings.extend(scanner.scan_file(file, shown))
    return findings


def scan_staged(scanner: Scanner, root: Path) -> List[Finding]:
    findings: List[Finding] = []
    for path in gitutil.staged_files(root):
        if not scanner.path_ignored(path):
            findings.extend(scanner.scan_bytes(gitutil.staged_content(root, path), path))
    return findings


def scan_history(scanner: Scanner, root: Path) -> List[Finding]:
    findings: List[Finding] = []
    seen = set()
    paths = set()
    for commit, path, lineno, text in gitutil.history_added_lines(root):
        if scanner.path_ignored(path):
            continue
        paths.add(path)
        for finding in scanner.scan_line(text, lineno, path, **commit):
            if finding.fingerprint not in seen:
                seen.add(finding.fingerprint)
                findings.append(finding)
    scanner.files_scanned = len(paths)
    return findings


def cmd_scan(args: argparse.Namespace) -> int:
    targets = [Path(p) for p in (args.paths or ["."])]
    root = gitutil.repo_root(targets[0] if targets[0].exists() else Path.cwd())
    patterns, fingerprints = load_ignore_file(root or Path.cwd())
    scanner = Scanner(min_severity=args.min_severity, ignore_patterns=patterns + args.exclude,
                      ignore_fingerprints=fingerprints, max_file_size=args.max_file_size * 1024)

    started = time.perf_counter()
    if args.staged or args.history:
        if root is None:
            print("leaklens: not a git repository", file=sys.stderr)
            return EXIT_ERROR
        mode = "staged changes" if args.staged else "git history"
        findings = scan_staged(scanner, root) if args.staged else scan_history(scanner, root)
    else:
        mode = "working tree"
        findings = scan_worktree(scanner, targets, args.all_files)
    elapsed = time.perf_counter() - started

    if args.format == "json":
        text = report.render_json(findings, scanner.files_scanned, args.show_secrets)
    elif args.format == "sarif":
        text = report.render_sarif(findings)
    else:
        color = report.use_color(sys.stdout, args.no_color or bool(args.output))
        text = report.render_text(findings, scanner.files_scanned, elapsed, mode, color, args.show_secrets)
    report.write(text, args.output)
    if args.output:
        print(f"leaklens: {report.summary_line(findings) if findings else 'no secrets found'}, "
              f"report written to {args.output}", file=sys.stderr)
    return EXIT_FINDINGS if findings and not args.exit_zero else EXIT_CLEAN


def cmd_install_hook(args: argparse.Namespace) -> int:
    root = gitutil.repo_root(Path.cwd())
    if root is None:
        print("leaklens: not a git repository", file=sys.stderr)
        return EXIT_ERROR
    hooks = root / ".git" / "hooks"
    hooks.mkdir(parents=True, exist_ok=True)
    hook = hooks / "pre-commit"
    if hook.exists() and HOOK_MARK not in hook.read_text(encoding="utf-8", errors="replace") and not args.force:
        print(f"leaklens: {hook} already exists, use --force to replace it", file=sys.stderr)
        return EXIT_ERROR
    python = sys.executable.replace("\\", "/")
    hook.write_text(f'#!/bin/sh\n{HOOK_MARK}\nexec "{python}" -m leaklens scan --staged\n',
                    encoding="utf-8", newline="\n")
    hook.chmod(hook.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print(f"Installed pre-commit hook: {hook}")
    print("Commits that contain secrets will now be blocked. Bypass once with: git commit --no-verify")
    return EXIT_CLEAN


def cmd_rules(_: argparse.Namespace) -> int:
    for rule in RULES:
        print(f"{rule.id.ljust(28)} {rule.severity.ljust(9)} {rule.description}")
    return EXIT_CLEAN


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="leaklens", description="Find leaked secrets in source code and git history.")
    parser.add_argument("--version", action="version", version=f"leaklens {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="command")

    scan = sub.add_parser("scan", help="scan files, staged changes or git history")
    scan.add_argument("paths", nargs="*", help="files or directories (default: current directory)")
    mode = scan.add_mutually_exclusive_group()
    mode.add_argument("--staged", action="store_true", help="scan only what is staged for commit")
    mode.add_argument("--history", action="store_true", help="scan every commit in the repository")
    scan.add_argument("--all-files", action="store_true", help="also scan files ignored by .gitignore")
    scan.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    scan.add_argument("--output", "-o", default="", metavar="FILE", help="write the report to a file")
    scan.add_argument("--min-severity", choices=SEVERITIES, default="low")
    scan.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                      help="skip paths matching the pattern (repeatable)")
    scan.add_argument("--max-file-size", type=int, default=DEFAULT_MAX_FILE_SIZE // 1024, metavar="KB")
    scan.add_argument("--show-secrets", action="store_true", help="print secrets in full (off by default)")
    scan.add_argument("--no-color", action="store_true")
    scan.add_argument("--exit-zero", action="store_true", help="always exit with 0, even with findings")
    scan.set_defaults(func=cmd_scan)

    hook = sub.add_parser("install-hook", help="block commits that contain secrets")
    hook.add_argument("--force", action="store_true", help="replace an existing pre-commit hook")
    hook.set_defaults(func=cmd_install_hook)

    rules = sub.add_parser("rules", help="list detection rules")
    rules.set_defaults(func=cmd_rules)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return EXIT_CLEAN
    try:
        return args.func(args)
    except (gitutil.GitError, FileNotFoundError) as exc:
        print(f"leaklens: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        return EXIT_ERROR
