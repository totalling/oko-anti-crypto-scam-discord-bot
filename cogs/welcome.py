import discord
from discord.ext import commands

import constants
from moderation import style


class Welcome(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member):
        if member.guild.id != constants.OKO_GUILD_ID:
            return

        channel = member.guild.get_channel(constants.WELCOME_CHANNEL_ID)
        if channel is None:
            return

        guild_id = constants.OKO_GUILD_ID
        description = (
            "Check out these channels to get started:\n\n"
            f"📢 **https://discord.com/channels/{guild_id}/{constants.ANNOUNCEMENTS_CHANNEL_ID}** - Announcements\n"
            f"📝 **https://discord.com/channels/{guild_id}/{constants.UPDATES_CHANNEL_ID}** - Updates\n"
            f"🚨 **https://discord.com/channels/{guild_id}/{constants.REPORT_SCAMS_CHANNEL_ID}** - Report new scams"
        )
        embed = style.build(description, thumbnail_url=member.display_avatar.url)
        await channel.send(content=member.mention, embed=embed)

    @commands.Cog.listener()
    async def on_guild_join(self, guild: discord.Guild):
        channel = guild.system_channel
        if channel is None or not channel.permissions_for(guild.me).send_messages:
            channel = next(
                (c for c in guild.text_channels if c.permissions_for(guild.me).send_messages), None
            )
        if channel is None:
            return

        description = (
            "👋 **Thanks for adding me!**\n\n"
            "I automatically detect and remove crypto/giveaway scam messages.\n\n"
            "**Get started:**\n"
            "> `/scam setlogchannel` — set where detections get logged\n"
            "> `/scam toggle` — turn auto-moderation on/off (on by default)\n"
            "> `/scam setpunishment` — choose ban, kick, or timeout for scammers\n"
            "> `/scam honeypot setup` — set up a trap channel for scammers\n"
            "> `/support` — get help in the support server"
        )
        embed = style.build(description, thumbnail_url=guild.me.display_avatar.url)
        try:
            await channel.send(embed=embed)
        except discord.Forbidden:
            pass


async def setup(bot: commands.Bot):
    await bot.add_cog(Welcome(bot))
