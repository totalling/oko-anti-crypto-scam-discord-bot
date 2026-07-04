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


async def setup(bot: commands.Bot):
    await bot.add_cog(Welcome(bot))
