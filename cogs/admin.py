from pathlib import Path

import discord
from discord import app_commands
from discord.ext import commands

from config import Config
from detection import phash_store
from detection.pipeline import ScanResult
from moderation import actions, guild_settings, style

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
SCAM_DOMAINS_FILE = DATA_DIR / "scam_domains.txt"
WATCHED_NAMES_FILE = DATA_DIR / "watched_names.txt"

INVITE_URL = (
    "https://discord.com/oauth2/authorize"
    "?client_id=1523055385190207709&permissions=8&integration_type=0&scope=bot+applications.commands"
)


def is_bot_owner():
    async def predicate(interaction: discord.Interaction) -> bool:
        return await interaction.client.is_owner(interaction.user)
    return app_commands.check(predicate)


def _append_unique_line(path: Path, value: str) -> bool:
    value = value.strip().lower()
    existing = {line.strip().lower() for line in path.read_text(encoding="utf-8").splitlines()}
    if value in existing:
        return False
    with path.open("a", encoding="utf-8") as f:
        f.write(f"\n{value}")
    return True


def _remove_line(path: Path, value: str) -> bool:
    value = value.strip().lower()
    lines = path.read_text(encoding="utf-8").splitlines()
    kept = [line for line in lines if line.strip().lower() != value]
    if len(kept) == len(lines):
        return False
    path.write_text("\n".join(kept) + "\n", encoding="utf-8")
    return True


class ScamAdmin(commands.Cog):
    def __init__(self, bot: commands.Bot, cfg: Config):
        self.bot = bot
        self.cfg = cfg

    scam_group = app_commands.Group(
        name="scam",
        description="Scam-detection moderation tools",
    )

    @scam_group.command(name="adddomain", description="[Bot owner only] Add a domain to the scam-domain blocklist")
    @is_bot_owner()
    async def add_domain(self, interaction: discord.Interaction, domain: str):
        added = _append_unique_line(SCAM_DOMAINS_FILE, domain)
        msg = f"`{domain}` has been added to the scam-domain blocklist." if added else f"`{domain}` is already blocklisted."
        await interaction.response.send_message(
            embed=style.command_reply(interaction, msg, emoji="✅" if added else "⚠️"), ephemeral=True
        )

    @scam_group.command(name="removedomain", description="[Bot owner only] Remove a domain from the scam-domain blocklist")
    @is_bot_owner()
    async def remove_domain(self, interaction: discord.Interaction, domain: str):
        removed = _remove_line(SCAM_DOMAINS_FILE, domain)
        msg = f"`{domain}` has been removed from the blocklist." if removed else f"`{domain}` was not found in the blocklist."
        await interaction.response.send_message(
            embed=style.command_reply(interaction, msg, emoji="✅" if removed else "❌"), ephemeral=True
        )

    @scam_group.command(name="addname", description="[Bot owner only] Add a public figure/brand name to the impersonation watchlist")
    @is_bot_owner()
    async def add_name(self, interaction: discord.Interaction, name: str):
        added = _append_unique_line(WATCHED_NAMES_FILE, name)
        msg = f"`{name}` has been added to the watched-names list." if added else f"`{name}` is already watched."
        await interaction.response.send_message(
            embed=style.command_reply(interaction, msg, emoji="✅" if added else "⚠️"), ephemeral=True
        )

    @scam_group.command(name="toggle", description="Enable or disable scam auto-moderation in this server")
    @app_commands.checks.has_permissions(manage_guild=True)
    @app_commands.describe(enabled="Turn scam detection on or off for this server")
    async def toggle(self, interaction: discord.Interaction, enabled: bool):
        if interaction.guild is None:
            return await interaction.response.send_message(
                embed=style.command_reply(interaction, "This only works in a server.", emoji="❌"), ephemeral=True
            )
        await guild_settings.set_enabled(interaction.guild.id, enabled)
        state = "enabled" if enabled else "disabled"
        await interaction.response.send_message(
            embed=style.command_reply(interaction, f"Scam auto-moderation is now **{state}** for this server."),
            ephemeral=True,
        )

    @scam_group.command(name="setlogchannel", description="Set the channel where this server's scam detections get logged")
    @app_commands.checks.has_permissions(manage_guild=True)
    @app_commands.describe(channel="Leave empty to clear — detections won't be logged anywhere until a channel is set")
    async def set_log_channel(self, interaction: discord.Interaction, channel: discord.TextChannel | None = None):
        if interaction.guild is None:
            return await interaction.response.send_message(
                embed=style.command_reply(interaction, "This only works in a server.", emoji="❌"), ephemeral=True
            )
        await guild_settings.set_log_channel_id(interaction.guild.id, channel.id if channel else None)
        msg = (
            f"Scam detections in this server will now be logged to {channel.mention}."
            if channel
            else "Cleared this server's log channel. Detections will no longer be logged until you set a new one."
        )
        await interaction.response.send_message(embed=style.command_reply(interaction, msg), ephemeral=True)

    @scam_group.command(name="stats", description="Show scam-detection blocklist sizes and this server's settings")
    @app_commands.checks.has_permissions(manage_guild=True)
    async def stats(self, interaction: discord.Interaction):
        domains = SCAM_DOMAINS_FILE.read_text(encoding="utf-8").splitlines()
        names = WATCHED_NAMES_FILE.read_text(encoding="utf-8").splitlines()
        hashes = phash_store._read_store()
        enabled = await guild_settings.is_enabled(interaction.guild.id) if interaction.guild else True
        log_channel_id = await guild_settings.get_log_channel_id(interaction.guild.id) if interaction.guild else None
        log_channel_text = f"<#{log_channel_id}>" if log_channel_id else "not set — run `/scam setlogchannel`"
        description = (
            f"> **Auto-moderation:** {'ON' if enabled else 'OFF'}\n"
            f"> **Log channel:** {log_channel_text}\n"
            f"> **Known scam domains:** {len([l for l in domains if l.strip() and not l.startswith('#')])}\n"
            f"> **Watched names:** {len([l for l in names if l.strip() and not l.startswith('#')])}\n"
            f"> **Known scam image hashes:** {len(hashes)}"
        )
        await interaction.response.send_message(embed=style.build(description), ephemeral=True)

    @app_commands.command(name="invite", description="Get an invite link to add this bot to your server")
    async def invite(self, interaction: discord.Interaction):
        embed = style.command_reply(interaction, "Click below to add me to your server.", emoji="🔗")
        view = discord.ui.View()
        view.add_item(discord.ui.Button(label="Invite bot", style=discord.ButtonStyle.link, url=INVITE_URL, emoji="➕"))
        await interaction.response.send_message(embed=embed, view=view, ephemeral=True)


async def setup(bot: commands.Bot):
    cfg: Config = bot.scam_cfg
    await bot.add_cog(ScamAdmin(bot, cfg))

    @app_commands.context_menu(name="Mark as Known Scam")
    @app_commands.default_permissions(manage_guild=True)
    async def mark_as_scam(interaction: discord.Interaction, message: discord.Message):
        await interaction.response.defer(ephemeral=True)

        image_bytes_list = []
        for attachment in message.attachments:
            if (attachment.content_type or "").startswith("image/"):
                image_bytes_list.append(await attachment.read())

        for data in image_bytes_list:
            phash_hex = await phash_store.compute_phash(data)
            if phash_hex:
                await phash_store.add_hash(phash_hex, source="manual", added_by=str(interaction.user.id))

        result = ScanResult(
            is_scam=True,
            confidence=1.0,
            reasons=[f"manually marked as scam by {interaction.user}"],
            hash_matched=False,
            image_hashes=[],
        )
        action = await actions.take_action(message, result, image_bytes_list, cfg, interaction.client)
        msg = (
            f"{message.author.mention} (`{message.author.id}`) has been blacklisted — {action}. "
            f"{len(image_bytes_list)} image hash(es) learned."
        )
        await interaction.followup.send(embed=style.command_reply(interaction, msg), ephemeral=True)

    bot.tree.add_command(mark_as_scam)
