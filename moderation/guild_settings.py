import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

SETTINGS_PATH = Path(__file__).resolve().parent.parent / "data" / "guild_settings.json"

_lock = asyncio.Lock()


def _read_store() -> dict:
    if not SETTINGS_PATH.exists():
        return {}
    try:
        return json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def _write_store(data: dict) -> None:
    SETTINGS_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")


async def is_enabled(guild_id: int) -> bool:
    store = _read_store()
    return store.get(str(guild_id), {}).get("enabled", True)


async def set_enabled(guild_id: int, enabled: bool) -> None:
    async with _lock:
        store = _read_store()
        entry = store.setdefault(str(guild_id), {})
        entry["enabled"] = enabled
        entry["updated_at"] = datetime.now(timezone.utc).isoformat()
        _write_store(store)


async def get_log_channel_id(guild_id: int) -> int | None:
    store = _read_store()
    return store.get(str(guild_id), {}).get("log_channel_id")


async def set_log_channel_id(guild_id: int, channel_id: int | None) -> None:
    async with _lock:
        store = _read_store()
        entry = store.setdefault(str(guild_id), {})
        entry["log_channel_id"] = channel_id
        entry["updated_at"] = datetime.now(timezone.utc).isoformat()
        _write_store(store)


async def increment_global_ban_count() -> int:
    async with _lock:
        store = _read_store()
        entry = store.setdefault("_global", {})
        entry["ban_count"] = entry.get("ban_count", 0) + 1
        entry["updated_at"] = datetime.now(timezone.utc).isoformat()
        _write_store(store)
        return entry["ban_count"]


async def get_global_ban_count() -> int:
    store = _read_store()
    return store.get("_global", {}).get("ban_count", 0)


VALID_PUNISHMENTS = ("ban", "kick", "timeout")


async def get_punishment(guild_id: int) -> str:
    store = _read_store()
    return store.get(str(guild_id), {}).get("punishment", "ban")


async def set_punishment(guild_id: int, punishment: str) -> None:
    if punishment not in VALID_PUNISHMENTS:
        raise ValueError(f"Invalid punishment: {punishment}")
    async with _lock:
        store = _read_store()
        entry = store.setdefault(str(guild_id), {})
        entry["punishment"] = punishment
        entry["updated_at"] = datetime.now(timezone.utc).isoformat()
        _write_store(store)


async def get_honeypot_channel_id(guild_id: int) -> int | None:
    store = _read_store()
    return store.get(str(guild_id), {}).get("honeypot_channel_id")


async def set_honeypot_channel_id(guild_id: int, channel_id: int | None) -> None:
    async with _lock:
        store = _read_store()
        entry = store.setdefault(str(guild_id), {})
        entry["honeypot_channel_id"] = channel_id
        entry["updated_at"] = datetime.now(timezone.utc).isoformat()
        _write_store(store)


async def get_honeypot_punishment(guild_id: int) -> str:
    store = _read_store()
    return store.get(str(guild_id), {}).get("honeypot_punishment", "ban")


async def set_honeypot_punishment(guild_id: int, punishment: str) -> None:
    if punishment not in VALID_PUNISHMENTS:
        raise ValueError(f"Invalid punishment: {punishment}")
    async with _lock:
        store = _read_store()
        entry = store.setdefault(str(guild_id), {})
        entry["honeypot_punishment"] = punishment
        entry["updated_at"] = datetime.now(timezone.utc).isoformat()
        _write_store(store)


async def get_global_blacklist_enabled(guild_id: int) -> bool:
    store = _read_store()
    return store.get(str(guild_id), {}).get("global_blacklist_enabled", False)


async def set_global_blacklist_enabled(guild_id: int, enabled: bool) -> None:
    async with _lock:
        store = _read_store()
        entry = store.setdefault(str(guild_id), {})
        entry["global_blacklist_enabled"] = enabled
        entry["updated_at"] = datetime.now(timezone.utc).isoformat()
        _write_store(store)
