import logging

import discord
from discord.ext import commands

from config import Config
from detection import pipeline
from moderation import actions, guild_settings

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

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if message.author.bot or not message.guild:
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
