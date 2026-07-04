import asyncio
import io
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import imagehash
from PIL import Image

HASH_STORE_PATH = Path(__file__).resolve().parent.parent / "data" / "scam_hashes.json"

_lock = asyncio.Lock()


def _compute_phash_sync(image_bytes: bytes) -> str:
    with Image.open(io.BytesIO(image_bytes)) as img:
        return str(imagehash.phash(img))


async def compute_phash(image_bytes: bytes) -> str | None:
    try:
        return await asyncio.to_thread(_compute_phash_sync, image_bytes)
    except Exception:
        return None


def _read_store() -> dict:
    if not HASH_STORE_PATH.exists():
        return {}
    try:
        return json.loads(HASH_STORE_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def _write_store(data: dict) -> None:
    HASH_STORE_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")


@dataclass
class HashMatch:
    hash_hex: str
    distance: int
    source: str


async def find_closest_match(hash_hex: str, max_distance: int) -> HashMatch | None:
    store = _read_store()
    if not store:
        return None

    target = imagehash.hex_to_hash(hash_hex)
    best: HashMatch | None = None
    for known_hex, meta in store.items():
        distance = target - imagehash.hex_to_hash(known_hex)
        if distance <= max_distance and (best is None or distance < best.distance):
            best = HashMatch(hash_hex=known_hex, distance=distance, source=meta.get("source", "unknown"))
    return best


async def add_hash(hash_hex: str, source: str, added_by: str) -> None:
    async with _lock:
        store = _read_store()
        store[hash_hex] = {
            "source": source,
            "added_by": added_by,
            "added_at": datetime.now(timezone.utc).isoformat(),
        }
        _write_store(store)


async def remove_hash(hash_hex: str) -> bool:
    async with _lock:
        store = _read_store()
        if hash_hex in store:
            del store[hash_hex]
            _write_store(store)
            return True
        return False
