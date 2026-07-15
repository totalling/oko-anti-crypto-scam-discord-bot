import io
import logging
from datetime import timedelta

import discord

import constants
from config import Config
from detection.pipeline import ScanResult
from moderation import blacklist, guild_settings, review_store, style
from moderation.views import ScamLogView

logger = logging.getLogger("scam_bot.moderation")

TIMEOUT_DURATION = timedelta(days=28)

_PUNISHMENT_VERBS = {"ban": "banned", "kick": "kicked", "timeout": "timed out"}


async def apply_punishment(member: discord.Member, punishment: str, reason: str) -> bool:
    try:
        if punishment == "kick":
            await member.kick(reason=reason)
        elif punishment == "timeout":
            await member.timeout(discord.utils.utcnow() + TIMEOUT_DURATION, reason=reason)
        else:
            await member.ban(reason=reason, delete_message_seconds=86400)
        return True
    except discord.Forbidden:
        logger.warning("Missing permission to %s user %s", punishment, member.id)
        return False


def _ban_reason(reasons: list[str]) -> str:
    for r in reasons:
        if r.startswith("known scam domain: "):
            return f"a scam giveaway linking to {r.split(': ', 1)[1]}"
    for r in reasons:
        if "scam-pattern domain: " in r:
            return f"a scam giveaway linking to {r.split(': ', 1)[1]}"
    for r in reasons:
        if r.startswith("impersonates watched name: "):
            return f"impersonating {r.split(': ', 1)[1]} in a fake giveaway"
    return "a crypto giveaway scam"


def _build_embed(message: discord.Message, result: ScanResult, action: str) -> discord.Embed:
    channel_mention = message.channel.mention if hasattr(message.channel, "mention") else str(message.channel)
    description = (
        f"> 🚫 **Scam detected** in {channel_mention}\n"
        f"> **Author:** {message.author.mention} `{message.author.id}`\n"
        f"> **Action:** {action}\n"
        f"> **Confidence:** {result.confidence:.2f} · **Signals:** {len(result.reasons)}"
    )
    return style.build(description, timestamp=True)


async def take_action(
    message: discord.Message,
    result: ScanResult,
    image_bytes_list: list[bytes],
    cfg: Config,
    bot: discord.Client,
) -> str:
    should_punish = result.confidence >= cfg.confidence_ban_threshold

    try:
        await message.delete()
        deleted = True
    except discord.Forbidden:
        deleted = False
        logger.warning("Missing permission to delete message %s", message.id)
    except discord.NotFound:
        deleted = True

    punished = False
    punishment = "ban"
    if should_punish and isinstance(message.author, discord.Member):
        punishment = await guild_settings.get_punishment(message.guild.id) if message.guild else "ban"
        punished = await apply_punishment(
            message.author,
            punishment,
            reason=f"Automated scam-giveaway detection (confidence={result.confidence:.2f})",
        )

    verb = _PUNISHMENT_VERBS.get(punishment, "banned")
    if deleted and punished:
        action = f"deleted message + {verb} author"
    elif deleted:
        action = "deleted message"
    elif punished:
        action = f"{verb} author"
    else:
        action = "flagged only (missing permissions)"

    await _log_to_mod_channel(message, result, image_bytes_list, action, cfg)

    if punished:
        await _post_public_gate(message, result, bot, verb)

    if punished and punishment == "ban" and message.guild is not None:
        reason = _ban_reason(result.reasons)
        await blacklist.add(
            message.author.id, reason=reason, source_guild_id=message.guild.id, confidence=result.confidence
        )
        await _propagate_global_ban(bot, message.author.id, message.guild, reason)

    return action


async def log_global_blacklist_action(
    bot: discord.Client, guild: discord.Guild, member: discord.Member, punishment: str, punished: bool, reason: str
) -> None:
    verb = _PUNISHMENT_VERBS.get(punishment, "banned") if punished else "flagged (missing permissions)"
    description = (
        f"> 🌐 **Global blacklist hit** in **{guild.name}**\n"
        f"> **User:** {member} `{member.id}`\n"
        f"> **Action:** {verb}\n"
        f"> **Reason:** {reason}"
    )
    embed = style.build(description, timestamp=True, thumbnail_url=member.display_avatar.url)

    log_channel_id = await guild_settings.get_log_channel_id(guild.id)
    channel = guild.get_channel(log_channel_id) if log_channel_id else None
    if channel is None:
        channel = bot.get_channel(constants.PUBLIC_GATE_CHANNEL_ID)
    if channel is None:
        return
    await channel.send(embed=embed)


async def _propagate_global_ban(bot: discord.Client, user_id: int, source_guild: discord.Guild, reason: str) -> None:
    for guild in bot.guilds:
        if guild.id == source_guild.id:
            continue
        if not await guild_settings.get_global_blacklist_enabled(guild.id):
            continue
        member = guild.get_member(user_id)
        if member is None:
            continue
        punishment = await guild_settings.get_punishment(guild.id)
        full_reason = f"banned in {source_guild.name} for {reason}"
        punished = await apply_punishment(member, punishment, reason=f"Global scam blacklist — {full_reason}"[:512])
        await log_global_blacklist_action(bot, guild, member, punishment, punished, full_reason)
        logger.info(
            "Global blacklist propagation: user=%s guild=%s punishment=%s success=%s",
            user_id,
            guild.id,
            punishment,
            punished,
        )


async def _post_public_gate(message: discord.Message, result: ScanResult, bot: discord.Client, verb: str) -> None:
    channel = bot.get_channel(constants.PUBLIC_GATE_CHANNEL_ID)
    if channel is None:
        return

    count = await guild_settings.increment_global_ban_count()
    reason = _ban_reason(result.reasons)
    description = (
        f"> **{message.author}** was {verb} for {reason}.\n"
        f"> **Total scammers caught:** {count}"
    )
    embed = style.build(description, timestamp=True, thumbnail_url=message.author.display_avatar.url)
    await channel.send(embed=embed)


async def _log_to_mod_channel(
    message: discord.Message,
    result: ScanResult,
    image_bytes_list: list[bytes],
    action: str,
    cfg: Config,
) -> None:
    if message.guild is None:
        return

    channel_id = await guild_settings.get_log_channel_id(message.guild.id)
    if not channel_id:
        logger.warning(
            "No log channel set for guild %s — run /scam setlogchannel to configure one", message.guild.id
        )
        return

    channel = message.guild.get_channel(channel_id)
    if channel is None:
        return

    embed = _build_embed(message, result, action)
    files = [
        discord.File(io.BytesIO(data), filename=f"evidence_{i}.png")
        for i, data in enumerate(image_bytes_list)
    ]
    view = ScamLogView()
    log_message = await channel.send(embed=embed, files=files if files else discord.utils.MISSING, view=view)

    await review_store.save_review(
        log_message.id,
        review_store.ReviewRecord(
            guild_id=message.guild.id,
            author_id=message.author.id,
            confidence=result.confidence,
            reasons=result.reasons,
            content=message.content,
            image_hashes=result.image_hashes,
        ),
    )
