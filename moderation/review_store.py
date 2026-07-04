import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path

REVIEW_STORE_PATH = Path(__file__).resolve().parent.parent / "data" / "pending_reviews.json"

_lock = asyncio.Lock()


@dataclass
class ReviewRecord:
    guild_id: int
    author_id: int
    confidence: float
    reasons: list[str] = field(default_factory=list)
    content: str = ""
    image_hashes: list[str] = field(default_factory=list)
    resolved: bool = False


def _read_store() -> dict:
    if not REVIEW_STORE_PATH.exists():
        return {}
    try:
        return json.loads(REVIEW_STORE_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def _write_store(data: dict) -> None:
    REVIEW_STORE_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")


async def save_review(log_message_id: int, record: ReviewRecord) -> None:
    async with _lock:
        store = _read_store()
        store[str(log_message_id)] = {
            "guild_id": record.guild_id,
            "author_id": record.author_id,
            "confidence": record.confidence,
            "reasons": record.reasons,
            "content": record.content,
            "image_hashes": record.image_hashes,
            "resolved": record.resolved,
        }
        _write_store(store)


async def get_review(log_message_id: int) -> ReviewRecord | None:
    store = _read_store()
    data = store.get(str(log_message_id))
    if data is None:
        return None
    return ReviewRecord(**data)
