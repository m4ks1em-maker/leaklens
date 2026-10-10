"""Test tokens are generated at runtime, so this repository never contains
anything that looks like a real credential (and never trips secret scanners)."""
import random
import string

ALNUM = string.ascii_letters + string.digits


def rnd(length, alphabet=ALNUM, seed=1):
    rng = random.Random(f"{seed}:{length}:{alphabet}")
    return "".join(rng.choice(alphabet) for _ in range(length))


def samples():
    """rule id -> a line of text that must trigger exactly that rule."""
    hexa = "0123456789abcdef"
    upper = string.ascii_uppercase + string.digits
    return {
        "private-key": "-----BEGIN " + "RSA PRIVATE KEY-----",
        "aws-access-key-id": "key = AKIA" + rnd(16, upper),
        "aws-secret-access-key": "aws_secret_access_key = " + rnd(40),
        "github-token": "GH = 'ghp_" + rnd(36) + "'",
        "github-fine-grained-token": "github_pat_" + rnd(82),
        "gitlab-token": "glpat-" + rnd(20),
        "telegram-bot-token": "bot = Bot('" + rnd(10, string.digits) + ":" + rnd(35) + "')",
        "discord-bot-token": "client.login('M" + rnd(23) + "." + rnd(6) + "." + rnd(27) + "')",
        "discord-webhook": "https://discord.com/api/" + "webhooks/" + rnd(18, string.digits) + "/" + rnd(60),
        "slack-token": "xox" + "b-" + rnd(12, string.digits) + "-" + rnd(24),
        "slack-webhook": "https://hooks.slack.com/" + "services/T" + rnd(8, upper) + "/B" + rnd(8, upper) + "/" + rnd(24),
        "stripe-live-key": "sk_" + "live_" + rnd(24),
        "google-api-key": "AIza" + rnd(35),
        "anthropic-api-key": "sk-" + "ant-" + rnd(40),
        "openai-api-key": "sk-" + "proj-" + rnd(48),
        "sendgrid-api-key": "SG." + rnd(22) + "." + rnd(43),
        "npm-token": "npm_" + rnd(36),
        "pypi-token": "pypi-" + "AgEIcHlwaS5vcmc" + rnd(60),
        "huggingface-token": "hf_" + rnd(34),
        "digitalocean-token": "dop_" + "v1_" + rnd(64, hexa),
        "jwt": "eyJ" + rnd(20) + ".eyJ" + rnd(30) + "." + rnd(40),
        "database-url": "postgres://app:" + rnd(14) + "@db.internal:5432/shop",
        "url-credentials": "https://deploy:" + rnd(14) + "@git.internal/repo.git",
        "generic-secret": 'db_pass' + 'word = "' + rnd(16) + '"',
        "env-secret": "SESSION_SEC" + "RET=" + rnd(24),
    }
