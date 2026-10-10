"""Detection rules.

Each rule is a regular expression plus a little metadata. Specific rules
(provider tokens with a fixed prefix) come first, generic ones last: when two
rules hit the same text, the earlier rule wins.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Pattern, Tuple

SEVERITIES: Tuple[str, ...] = ("low", "medium", "high", "critical")

# Token boundaries. "\b" is not enough: tokens may end with "-" or "_".
_B = r"(?<![A-Za-z0-9_\-])"
_E = r"(?![A-Za-z0-9_\-])"


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    severity: str
    pattern: Pattern[str]
    hint: Pattern[str]          # cheap pre-check run against the lowercased line
    group: int = 0              # regex group that holds the secret itself
    min_entropy: float = 0      # Shannon entropy threshold, 0 disables the check
    generic: bool = False       # skip placeholder values such as "changeme" or "<token>"
    strict_value: bool = False  # skip values that look like plain words or identifiers


def _rule(id, description, severity, regex, keywords=(), hint=None, group=0, min_entropy=0,
          generic=False, strict_value=False, flags=0):
    """`keywords` are lowercase substrings, `hint` a raw regex; one of them is required."""
    hint = re.compile(hint or "|".join(re.escape(word) for word in keywords))
    return Rule(id, description, severity, re.compile(regex, flags), hint, group,
                min_entropy, generic, strict_value)


_SECRET_WORDS = ("pass", "pwd", "secret", "token", "key")
# "token_type = ...", "password_field = ..." describe a secret, they do not contain one.
_BENIGN_NAME = (r"(?![A-Za-z0-9_.\-]*(?:type|name|file|path|url|uri|field|header|param|length|size|"
                r"format|prefix|suffix|label|hint|regex|pattern|env|var|ttl|count|kind|mode|scope)s?"
                r"['\"]?\s*[:=])")


RULES: Tuple[Rule, ...] = (
    _rule("private-key", "Private key block", "critical",
          r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----", keywords=('-----begin',)),
    _rule("aws-access-key-id", "AWS access key ID", "high",
          _B + r"(?:AKIA|ASIA)[0-9A-Z]{16}" + _E, keywords=('akia', 'asia')),
    _rule("aws-secret-access-key", "AWS secret access key", "critical",
          r"aws[A-Za-z0-9_\-.]{0,24}(?:secret|private)[A-Za-z0-9_\-.]{0,24}\s*[:=]\s*['\"]?"
          r"([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])", group=1, min_entropy=3.5, flags=re.I, keywords=('aws',)),
    _rule("github-token", "GitHub access token", "critical",
          _B + r"gh[pousr]_[A-Za-z0-9]{36,255}" + _E, keywords=('ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_')),
    _rule("github-fine-grained-token", "GitHub fine-grained token", "critical",
          _B + r"github_pat_[A-Za-z0-9_]{60,255}" + _E, keywords=('github_pat_',)),
    _rule("gitlab-token", "GitLab personal access token", "critical",
          _B + r"glpat-[A-Za-z0-9_\-]{20,}" + _E, keywords=('glpat-',)),
    _rule("telegram-bot-token", "Telegram bot token", "critical",
          _B + r"\d{8,10}:[A-Za-z0-9_\-]{35}" + _E, hint=r"\d{8}:"),
    _rule("discord-bot-token", "Discord bot token", "critical",
          _B + r"[MNO][A-Za-z\d_\-]{23,25}\.[A-Za-z\d_\-]{6}\.[A-Za-z\d_\-]{27,38}" + _E, hint=r"[mno][a-z\d_\-]{23}\."),
    _rule("discord-webhook", "Discord webhook URL", "high",
          r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{15,22}/[A-Za-z0-9_\-]{30,}", keywords=('/api/webhooks/',)),
    _rule("slack-token", "Slack token", "critical",
          _B + r"xox[baprs]-[A-Za-z0-9\-]{10,}" + _E, keywords=('xox',)),
    _rule("slack-webhook", "Slack webhook URL", "high",
          r"https://hooks\.slack\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/[A-Za-z0-9]{20,}", keywords=('hooks.slack.com',)),
    _rule("stripe-live-key", "Stripe live secret key", "critical",
          _B + r"[sr]k_live_[A-Za-z0-9]{20,}" + _E, keywords=('k_live_',)),
    _rule("google-api-key", "Google API key", "high",
          _B + r"AIza[0-9A-Za-z_\-]{35}" + _E, keywords=('aiza',)),
    _rule("anthropic-api-key", "Anthropic API key", "critical",
          _B + r"sk-ant-[A-Za-z0-9_\-]{20,}" + _E, keywords=('sk-ant-',)),
    _rule("openai-api-key", "OpenAI API key", "critical",
          _B + r"sk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,}" + _E, min_entropy=3.5, keywords=('sk-',)),
    _rule("sendgrid-api-key", "SendGrid API key", "critical",
          _B + r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}" + _E, keywords=('sg.',)),
    _rule("npm-token", "npm access token", "critical",
          _B + r"npm_[A-Za-z0-9]{36}" + _E, keywords=('npm_',)),
    _rule("pypi-token", "PyPI upload token", "critical",
          _B + r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}" + _E, keywords=('pypi-',)),
    _rule("huggingface-token", "Hugging Face token", "high",
          _B + r"hf_[A-Za-z0-9]{34,}" + _E, keywords=('hf_',)),
    _rule("digitalocean-token", "DigitalOcean token", "critical",
          _B + r"do[por]_v1_[a-f0-9]{64}" + _E, keywords=('_v1_',)),
    _rule("jwt", "JSON Web Token", "medium",
          _B + r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}" + _E, keywords=('eyj',)),
    _rule("database-url", "Database URL with a password", "high",
          r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?)://"
          r"[^\s:/@'\"]*:([^\s@'\"]{3,})@", group=1, generic=True, flags=re.I, keywords=('://',)),
    _rule("url-credentials", "Credentials inside a URL", "medium",
          r"\bhttps?://[^\s:/@'\"]+:([^\s@'\"/]{6,})@[\w.\-]+", group=1, generic=True, flags=re.I, keywords=('://',)),
    _rule("generic-secret", "Hardcoded password, token or key", "medium",
          r"\b(?P<name>[A-Za-z0-9_.\-]*(?:password|passwd|pwd|secret|token|api[_\-]?key|access[_\-]?key|"
          r"auth[_\-]?key|private[_\-]?key)" + _BENIGN_NAME +
          r"[A-Za-z0-9_.\-]*)['\"]?\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]",
          group=2, min_entropy=3.0, generic=True, strict_value=True, keywords=_SECRET_WORDS, flags=re.I),
    _rule("env-secret", "Secret in an environment-style assignment", "medium",
          r"^\s*(?:export\s+)?(?P<name>[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|"
          r"PRIVATE_?KEY)[A-Z0-9_]*)\s*=\s*([^\s'\"#(){}$<>]{8,})\s*$",
          group=2, min_entropy=3.0, generic=True, keywords=_SECRET_WORDS, strict_value=True),
)

RULES_BY_ID = {rule.id: rule for rule in RULES}


def build_prefilter(rules) -> Pattern[str]:
    """One regex that tells whether any rule could match a (lowercased) line."""
    return re.compile("|".join(f"(?:{rule.hint.pattern})" for rule in rules) or r"(?!)")
