import re
from dataclasses import dataclass, field
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

PHRASE_SIGNALS: list[tuple[re.Pattern, float, str]] = [
    (re.compile(r"giveaway", re.I), 0.15, "giveaway"),
    (re.compile(r"promo\s*code", re.I), 0.20, "promo code"),
    (re.compile(r"bonus\s*code", re.I), 0.15, "bonus code"),
    (re.compile(r"activate\s*(the\s*)?code", re.I), 0.20, "activate code"),
    (re.compile(r"withdrawal\s*success", re.I), 0.30, "withdrawal success"),
    (re.compile(r"withdraw\s*(your|the)?\s*bonus", re.I), 0.20, "withdraw bonus"),
    (re.compile(r"post\s*will\s*be\s*deleted", re.I), 0.35, "scarcity: post will be deleted"),
    (re.compile(r"only\s*the\s*fastest", re.I), 0.30, "scarcity: only the fastest"),
    (re.compile(r"crypto(currency)?\s*casino", re.I), 0.25, "crypto casino"),
    (re.compile(r"\$\s?\d{1,3}(,\d{3})*\s*(bonus|to everyone|for everyone)", re.I), 0.25, "cash bonus to everyone"),
    (re.compile(r"follow\s*me\s*for\s*a\s*cookie", re.I), 0.20, "impersonation bio phrase"),
    (re.compile(r"rakeback", re.I), 0.10, "rakeback"),
    (re.compile(r"vip[\s-]?club", re.I), 0.05, "vip club"),
    (re.compile(r"register(ing|s)?\s*(will\s*)?(get|receive)", re.I), 0.15, "register to receive"),
]

URL_PATTERN = re.compile(r"(?:https?://)?(?:www\.)?([a-z0-9-]+\.[a-z]{2,})", re.I)

SUSPICIOUS_DOMAIN_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b[a-z]{3,8}win\.(?:com|net|org|io|bet|casino)\b", re.I), "*win.<tld> scam-pattern domain"),
]


def _load_lines(filename: str) -> list[str]:
    path = DATA_DIR / filename
    if not path.exists():
        return []
    lines = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            lines.append(line)
    return lines


def load_scam_domains() -> list[str]:
    return _load_lines("scam_domains.txt")


def load_watched_names() -> list[str]:
    return _load_lines("watched_names.txt")


@dataclass
class HeuristicResult:
    score: float
    reasons: list[str] = field(default_factory=list)


def score_text(text: str) -> HeuristicResult:
    if not text or not text.strip():
        return HeuristicResult(score=0.0)

    lower = text.lower()
    score = 0.0
    reasons: list[str] = []

    for pattern, weight, label in PHRASE_SIGNALS:
        if pattern.search(lower):
            score += weight
            reasons.append(label)

    scam_domains = load_scam_domains()
    matched_domain = next((d for d in scam_domains if d in lower), None)
    if matched_domain:
        score += 0.5
        reasons.append(f"known scam domain: {matched_domain}")
    else:
        for pattern, label in SUSPICIOUS_DOMAIN_PATTERNS:
            match = pattern.search(lower)
            if match:
                score += 0.35
                reasons.append(f"{label}: {match.group(0)}")
                break

    watched_names = load_watched_names()
    matched_name = next((n for n in watched_names if n in lower), None)
    if matched_name and reasons:
        score += 0.3
        reasons.append(f"impersonates watched name: {matched_name}")

    return HeuristicResult(score=min(score, 1.0), reasons=reasons)
