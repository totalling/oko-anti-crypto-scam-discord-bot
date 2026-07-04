import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


def _float(name: str, default: float) -> float:
    val = os.getenv(name)
    return float(val) if val else default


def _int(name: str, default: int) -> int:
    val = os.getenv(name)
    return int(val) if val else default


@dataclass(frozen=True)
class Config:
    discord_token: str
    tesseract_cmd: str
    heuristic_auto_scam_score: float
    confidence_ban_threshold: float
    hash_distance_threshold: int


def load_config() -> Config:
    token = os.getenv("DISCORD_TOKEN", "")
    if not token:
        raise RuntimeError("DISCORD_TOKEN is not set. Copy .env.example to .env and fill it in.")

    return Config(
        discord_token=token,
        tesseract_cmd=os.getenv("TESSERACT_CMD", ""),
        heuristic_auto_scam_score=_float("HEURISTIC_AUTO_SCAM_SCORE", 0.6),
        confidence_ban_threshold=_float("CONFIDENCE_BAN_THRESHOLD", 0.6),
        hash_distance_threshold=_int("HASH_DISTANCE_THRESHOLD", 8),
    )
