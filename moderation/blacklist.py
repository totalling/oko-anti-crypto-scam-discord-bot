import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

STORE_PATH = Path(__file__).resolve().parent.parent / "data" / "global_blacklist.json"

_lock = asyncio.Lock()


def _read_store() -> dict:
    if not STORE_PATH.exists():
        return {}
    try:
        return json.loads(STORE_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def _write_store(data: dict) -> None:
    STORE_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")


async def get_entry(user_id: int) -> dict | None:
    store = _read_store()
    return store.get(str(user_id))


async def add(user_id: int, *, reason: str, source_guild_id: int, confidence: float) -> None:
    async with _lock:
        store = _read_store()
        store[str(user_id)] = {
            "reason": reason,
            "source_guild_id": source_guild_id,
            "confidence": confidence,
            "added_at": datetime.now(timezone.utc).isoformat(),
        }
        _write_store(store)
