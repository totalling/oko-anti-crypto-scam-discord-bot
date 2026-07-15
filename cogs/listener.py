import logging

import discord
from discord.ext import commands

from config import Config
from detection import pipeline
from moderation import actions, blacklist, guild_settings

logger = logging.getLogger("scam_bot.listener")


class ScamListener(commands.Cog):
    def __init__(self, bot: commands.Bot, cfg: Config):
        self.bot = bot
        self.cfg = cfg

    async def _image_bytes(self, message: discord.Message) -> list[bytes]:
        images = [a for a in message.attachments if (a.content_type or "").startswith("image/")]
        out = []
        for attachment in images:
            try:
                out.append(await attachment.read())
            except discord.HTTPException:
                logger.warning("Failed to download attachment %s on message %s", attachment.id, message.id)
        return out

    async def _handle_honeypot(self, message: discord.Message) -> None:
        member = message.author
        try:
            await message.delete()
        except discord.HTTPException:
            pass

        if not isinstance(member, discord.Member):
            return
        if member.guild_permissions.manage_guild:
            logger.info("Honeypot triggered by moderator %s — ignoring", member.id)
            return

        punishment = await guild_settings.get_honeypot_punishment(message.guild.id)
        punished = await actions.apply_punishment(member, punishment, reason="Triggered honeypot trap channel")
        logger.info("Honeypot triggered: user=%s punishment=%s success=%s", member.id, punishment, punished)

    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member):
        if not await guild_settings.get_global_blacklist_enabled(member.guild.id):
            return

        entry = await blacklist.get_entry(member.id)
        if entry is None:
            return

        punishment = await guild_settings.get_punishment(member.guild.id)
        source_guild = self.bot.get_guild(entry["source_guild_id"])
        source_name = source_guild.name if source_guild else "another server"
        reason = f"banned in {source_name} for {entry['reason']}"
        punished = await actions.apply_punishment(member, punishment, reason=f"Global scam blacklist — {reason}"[:512])
        await actions.log_global_blacklist_action(self.bot, member.guild, member, punishment, punished, reason)
        logger.info(
            "Global blacklist hit on join: user=%s guild=%s punishment=%s success=%s",
            member.id,
            member.guild.id,
            punishment,
            punished,
        )

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if message.author.bot or not message.guild:
            return

        honeypot_channel_id = await guild_settings.get_honeypot_channel_id(message.guild.id)
        if honeypot_channel_id and message.channel.id == honeypot_channel_id:
            await self._handle_honeypot(message)
            return

        if not message.content and not message.attachments:
            return
        if not await guild_settings.is_enabled(message.guild.id):
            return

        image_bytes_list = await self._image_bytes(message)
        if not message.content.strip() and not image_bytes_list:
            return

        result = await pipeline.scan(message.content, image_bytes_list, self.cfg)
        if not result.is_scam:
            return

        action = await actions.take_action(message, result, image_bytes_list, self.cfg, self.bot)
        logger.info(
            "Scam flagged: user=%s confidence=%.2f action=%s reasons=%s",
            message.author.id,
            result.confidence,
            action,
            result.reasons,
        )


async def setup(bot: commands.Bot):
    cfg: Config = bot.scam_cfg
    await bot.add_cog(ScamListener(bot, cfg))
