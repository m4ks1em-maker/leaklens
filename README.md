# LeakLens

[![CI](https://github.com/m4ks1em-maker/leaklens/actions/workflows/ci.yml/badge.svg)](https://github.com/m4ks1em-maker/leaklens/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**Find leaked secrets before someone else does.** LeakLens scans your source
code and your whole git history for API tokens, private keys, database
passwords and other credentials that should never be committed.

- **Zero dependencies.** Pure Python standard library, one `pip install`.
- **Looks into the past.** A deleted token is still in git history; `--history` finds it and names the commit.
- **Stops leaks at the source.** A pre-commit hook blocks the commit before the secret leaves your machine.
- **Safe output.** Secrets are masked in every report by default.
- **CI ready.** JSON and SARIF output, meaningful exit codes, GitHub code scanning support.

```text
$ leaklens scan
LeakLens 0.1.0 - working tree: 3 files scanned in 0.00s

bot.py
  3:14      CRITICAL telegram-bot-token         1043********Wv
            Telegram bot token  id:8a5a05d802666aa2

config/settings.py
  1:33      HIGH     database-url               gfyg********cU
            Database URL with a password  id:5a017c8f9a00913e
  2:11      CRITICAL github-token               ghp_********kx
            GitHub access token  id:57a461f90beb43e0
  3:16      MEDIUM   generic-secret             wnQr********U!
            Hardcoded password, token or key  id:66702f639401465e

[!] 4 potential secrets found (2 critical, 1 high, 1 medium)
```

## Install

```bash
pip install git+https://github.com/m4ks1em-maker/leaklens.git
```

Requires Python 3.9+ and, for the git features, `git` on your `PATH`.
Works on Windows, Linux and macOS.

## Usage

```bash
leaklens scan                      # current directory (respects .gitignore)
leaklens scan src/ config.py       # specific files and folders
leaklens scan --history            # every commit on every branch
leaklens scan --staged             # only what is about to be committed
leaklens scan --all-files          # include files ignored by git (.env and friends)
leaklens install-hook              # block commits that contain secrets
leaklens rules                     # list detection rules
```

Useful options for `scan`:

| Option | What it does |
| --- | --- |
| `--format text\|json\|sarif` | Output format (default `text`) |
| `-o, --output FILE` | Write the report to a file |
| `--min-severity LEVEL` | Report only `low`, `medium`, `high` or `critical` and above |
| `--exclude GLOB` | Skip matching paths, can be repeated |
| `--show-secrets` | Print secrets in full instead of masking them |
| `--exit-zero` | Exit with 0 even when something was found |

Exit codes: `0` nothing found, `1` secrets found, `2` error.

## What it detects

25 rules, grouped by how sure the match is:

| Group | Examples |
| --- | --- |
| Provider tokens with a fixed format | GitHub, GitLab, AWS, Google, Stripe, Slack, Telegram and Discord bots, OpenAI, Anthropic, SendGrid, npm, PyPI, Hugging Face, DigitalOcean |
| Key material | RSA, EC, OpenSSH and PGP private key blocks, JSON Web Tokens |
| Connection strings | Database URLs with a password, credentials inside `https://user:pass@host` |
| Generic assignments | `password = "..."`, `API_KEY=...` and similar, filtered by entropy |

Generic rules filter out placeholders (`changeme`, `<your-token>`,
`${SECRET}`), plain words and values that only repeat their own key, so that a
scan of a normal project stays readable.

## Block secrets before they are committed

```bash
cd your-project
leaklens install-hook
```

From now on `git commit` runs `leaklens scan --staged` first and stops if
anything is found. To skip the check for one commit: `git commit --no-verify`.

## Handling false positives

Mark a single line:

```python
EXAMPLE_KEY = "not-a-real-key-123456"  # leaklens:ignore
```

Or create `.leaklensignore` in the repository root with path patterns and
finding ids (the `id:` value from the report):

```gitignore
# folders and globs
docs/
tests/fixtures/*.json

# a finding that was reviewed and accepted
57a461f90beb43e0
```

## Use in GitHub Actions

Fail the build when a secret is committed:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
- uses: actions/setup-python@v5
  with:
    python-version: "3.12"
- run: pip install git+https://github.com/m4ks1em-maker/leaklens.git
- run: leaklens scan --history
```

Or show the findings in the repository's **Security** tab (the job needs the
`security-events: write` permission):

```yaml
- run: leaklens scan --history --format sarif -o leaklens.sarif --exit-zero
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: leaklens.sarif
```

## You found a secret. Now what?

1. **Revoke it first.** Generate a new token or password at the provider. A secret that was pushed must be treated as stolen.
2. Move the new value out of the code, into an environment variable or a secret manager.
3. Only then clean the history (for example with `git filter-repo`), if you still need to.

Deleting the line in a new commit is not enough: the old value stays in history.

## Limitations

- Detection is pattern based. It can miss secrets in unusual formats and can flag strings that only look like secrets.
- LeakLens does not check whether a token is still valid. It never sends anything anywhere: all scanning is local.
- Binary files, files over 2 MB, lock files and dependency folders (`node_modules`, `venv`, ...) are skipped.

## Development

```bash
git clone https://github.com/m4ks1em-maker/leaklens.git
cd leaklens
pip install -e .
python -m unittest
```

Test tokens are generated at runtime, so the repository itself contains
nothing that looks like a credential.

## Roadmap

- Baseline file for adopting the tool in an old repository
- Custom rules from a config file
- Scan only the commits of a pull request

## License

MIT, see [LICENSE](LICENSE).
