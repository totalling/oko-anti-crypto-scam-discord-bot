import logging

import discord
from discord import app_commands
from discord.ext import commands

from config import load_config
from moderation import style

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("scam_bot")


class ScamBot(commands.Bot):
    def __init__(self, cfg):
        intents = discord.Intents.default()
        intents.message_content = True
        intents.members = True
        super().__init__(command_prefix="!scam-unused ", intents=intents)
        self.scam_cfg = cfg

    async def setup_hook(self):
        await self.load_extension("cogs.listener")
        await self.load_extension("cogs.admin")
        await self.load_extension("cogs.welcome")

        async def on_tree_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
            if isinstance(error, (app_commands.MissingPermissions, app_commands.CheckFailure)):
                embed = style.command_reply(interaction, "You don't have permission to use this command.", emoji="🔒")
            else:
                embed = style.command_reply(interaction, "Something went wrong running that command.", emoji="❌")
                logger.exception("Unhandled app command error", exc_info=error)
            if interaction.response.is_done():
                await interaction.followup.send(embed=embed, ephemeral=True)
            else:
                await interaction.response.send_message(embed=embed, ephemeral=True)

        self.tree.on_error = on_tree_error
        await self.tree.sync()


def main():
    cfg = load_config()
    bot = ScamBot(cfg)

    async def update_presence():
        count = len(bot.guilds)
        label = f"{count} server{'s' if count != 1 else ''} for scams"
        await bot.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name=label))

    @bot.event
    async def on_ready():
        logger.info("Logged in as %s (id=%s)", bot.user, bot.user.id)
        await update_presence()

    @bot.event
    async def on_guild_join(guild: discord.Guild):
        await update_presence()

    @bot.event
    async def on_guild_remove(guild: discord.Guild):
        await update_presence()

    bot.run(cfg.discord_token, log_handler=None)


if __name__ == "__main__":
    main()
