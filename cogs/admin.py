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

BOT_AVATAR_EMOJI = "<:2c5cdb61411e80788732456a0cd8212a:1527058448125267968>"

DEVELOPER_URL = "https://discord.com/users/1026824982329839707"

SUPPORT_SERVER_URL = "https://discord.gg/zsNhVNAXkP"

HONEYPOT_CHANNEL_NAME = "dont-type-here"

PUNISHMENT_CHOICES = [
    app_commands.Choice(name="Ban", value="ban"),
    app_commands.Choice(name="Kick", value="kick"),
    app_commands.Choice(name="Timeout / Mute", value="timeout"),
]

PUNISHMENT_LABELS = {"ban": "Ban", "kick": "Kick", "timeout": "Timeout / Mute"}
PUNISHMENT_VERBS = {"ban": "banned", "kick": "kicked", "timeout": "timed out / muted"}


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

    @scam_group.command(name="setpunishment", description="Choose what happens to users caught by scam auto-moderation")
    @app_commands.checks.has_permissions(manage_guild=True)
    @app_commands.choices(punishment=PUNISHMENT_CHOICES)
    @app_commands.describe(punishment="What to do to a user caught by auto-moderation (scam links/images/messages)")
    async def set_punishment(self, interaction: discord.Interaction, punishment: app_commands.Choice[str]):
        if interaction.guild is None:
            return await interaction.response.send_message(
                embed=style.command_reply(interaction, "This only works in a server.", emoji="❌"), ephemeral=True
            )
        await guild_settings.set_punishment(interaction.guild.id, punishment.value)
        msg = f"Scam auto-moderation punishment for this server is now **{punishment.name}**."
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
        punishment = await guild_settings.get_punishment(interaction.guild.id) if interaction.guild else "ban"
        honeypot_id = await guild_settings.get_honeypot_channel_id(interaction.guild.id) if interaction.guild else None
        honeypot_text = f"<#{honeypot_id}>" if honeypot_id else "not set — run `/scam honeypot setup`"
        honeypot_punishment = (
            await guild_settings.get_honeypot_punishment(interaction.guild.id) if interaction.guild else "ban"
        )
        description = (
            f"> **Auto-moderation:** {'ON' if enabled else 'OFF'}\n"
            f"> **Log channel:** {log_channel_text}\n"
            f"> **Scam punishment:** {PUNISHMENT_LABELS.get(punishment, punishment)}\n"
            f"> **Honeypot channel:** {honeypot_text}\n"
            f"> **Honeypot punishment:** {PUNISHMENT_LABELS.get(honeypot_punishment, honeypot_punishment)}\n"
            f"> **Known scam domains:** {len([l for l in domains if l.strip() and not l.startswith('#')])}\n"
            f"> **Watched names:** {len([l for l in names if l.strip() and not l.startswith('#')])}\n"
            f"> **Known scam image hashes:** {len(hashes)}"
        )
        await interaction.response.send_message(embed=style.build(description), ephemeral=True)

    honeypot_group = app_commands.Group(
        name="honeypot",
        description="Configure a honeypot trap channel for scammers/bots",
        parent=scam_group,
    )

    @honeypot_group.command(name="setup", description="Create a trap channel — anyone who types in it is punished")
    @app_commands.checks.has_permissions(manage_guild=True)
    async def honeypot_setup(self, interaction: discord.Interaction):
        guild = interaction.guild
        if guild is None:
            return await interaction.response.send_message(
                embed=style.command_reply(interaction, "This only works in a server.", emoji="❌"), ephemeral=True
            )

        existing_id = await guild_settings.get_honeypot_channel_id(guild.id)
        if existing_id and guild.get_channel(existing_id):
            msg = f"A honeypot channel is already set up: <#{existing_id}>."
            return await interaction.response.send_message(
                embed=style.command_reply(interaction, msg, emoji="⚠️"), ephemeral=True
            )

        if not guild.me.guild_permissions.manage_channels:
            msg = "I need the **Manage Channels** permission to set up a honeypot."
            return await interaction.response.send_message(
                embed=style.command_reply(interaction, msg, emoji="❌"), ephemeral=True
            )

        overwrites = {
            guild.default_role: discord.PermissionOverwrite(view_channel=True, send_messages=True, read_message_history=True),
            guild.me: discord.PermissionOverwrite(
                view_channel=True, send_messages=True, manage_channels=True, manage_messages=True
            ),
        }
        try:
            channel = await guild.create_text_channel(
                HONEYPOT_CHANNEL_NAME,
                overwrites=overwrites,
                topic="🚨 Do NOT send a message in this channel — it's a trap. You will be punished.",
                reason=f"Honeypot setup by {interaction.user}",
            )
        except discord.Forbidden:
            msg = "I don't have permission to create channels in this server."
            return await interaction.response.send_message(
                embed=style.command_reply(interaction, msg, emoji="❌"), ephemeral=True
            )

        await guild_settings.set_honeypot_channel_id(guild.id, channel.id)
        punishment = await guild_settings.get_honeypot_punishment(guild.id)
        msg = (
            f"Honeypot channel created: {channel.mention}. Anyone who types there "
            f"(other than moderators) will be **{PUNISHMENT_VERBS.get(punishment, punishment)}**. "
            f"Change the honeypot punishment with `/scam honeypot setpunishment`."
        )
        await interaction.response.send_message(embed=style.command_reply(interaction, msg), ephemeral=True)

    @honeypot_group.command(name="setpunishment", description="Choose what happens to users who trigger the honeypot")
    @app_commands.checks.has_permissions(manage_guild=True)
    @app_commands.choices(punishment=PUNISHMENT_CHOICES)
    @app_commands.describe(punishment="What to do to a user who types in the honeypot channel")
    async def honeypot_set_punishment(self, interaction: discord.Interaction, punishment: app_commands.Choice[str]):
        if interaction.guild is None:
            return await interaction.response.send_message(
                embed=style.command_reply(interaction, "This only works in a server.", emoji="❌"), ephemeral=True
            )
        await guild_settings.set_honeypot_punishment(interaction.guild.id, punishment.value)
        msg = f"Honeypot punishment for this server is now **{punishment.name}**."
        await interaction.response.send_message(embed=style.command_reply(interaction, msg), ephemeral=True)

    @honeypot_group.command(name="disable", description="Remove the honeypot trap channel")
    @app_commands.checks.has_permissions(manage_guild=True)
    async def honeypot_disable(self, interaction: discord.Interaction):
        guild = interaction.guild
        if guild is None:
            return await interaction.response.send_message(
                embed=style.command_reply(interaction, "This only works in a server.", emoji="❌"), ephemeral=True
            )

        channel_id = await guild_settings.get_honeypot_channel_id(guild.id)
        if not channel_id:
            msg = "No honeypot channel is set up."
            return await interaction.response.send_message(
                embed=style.command_reply(interaction, msg, emoji="⚠️"), ephemeral=True
            )

        channel = guild.get_channel(channel_id)
        if channel:
            try:
                await channel.delete(reason=f"Honeypot disabled by {interaction.user}")
            except discord.Forbidden:
                pass
        await guild_settings.set_honeypot_channel_id(guild.id, None)
        await interaction.response.send_message(
            embed=style.command_reply(interaction, "Honeypot channel removed."), ephemeral=True
        )

    @app_commands.command(name="invite", description="Get an invite link to add this bot to your server")
    async def invite(self, interaction: discord.Interaction):
        embed = style.command_reply(interaction, "Click below to add me to your server.", emoji="🔗")
        view = discord.ui.View()
        view.add_item(discord.ui.Button(label="Invite bot", style=discord.ButtonStyle.link, url=INVITE_URL, emoji="➕"))
        await interaction.response.send_message(embed=embed, view=view, ephemeral=True)

    @app_commands.command(name="support", description="Get an invite link to the support server")
    async def support(self, interaction: discord.Interaction):
        embed = style.command_reply(interaction, "Need help? Join the support server below.", emoji="⚙️")
        view = discord.ui.View()
        view.add_item(
            discord.ui.Button(label="Support server", style=discord.ButtonStyle.link, url=SUPPORT_SERVER_URL, emoji="🔗")
        )
        await interaction.response.send_message(embed=embed, view=view, ephemeral=False)

    @app_commands.command(name="botinfo", description="Show information about this bot")
    async def botinfo(self, interaction: discord.Interaction):
        bot = self.bot
        guild_count = len(bot.guilds)
        member_count = sum(g.member_count or 0 for g in bot.guilds if g.member_count)
        latency_ms = round(bot.latency * 1000)
        ban_count = await guild_settings.get_global_ban_count()
        description = (
            f"### {bot.user.name}\n"
            f"Automated crypto/giveaway scam detection for Discord.\n\n"
            f"> **Servers:** {guild_count}\n"
            f"> **Members protected:** {member_count:,}\n"
            f"> **Scammers caught:** {ban_count}\n"
            f"> **Latency:** {latency_ms}ms\n"
            f"# **Developer:** {BOT_AVATAR_EMOJI} [medisiner](https://discord.com/users/1026824982329839707)\n\n"
            f"Use `/support` for help or `/invite` to add me to another server."
        )
        embed = style.build(description, thumbnail_url=bot.user.display_avatar.url)
        view = discord.ui.View()
        view.add_item(discord.ui.Button(label="Invite bot", style=discord.ButtonStyle.link, url=INVITE_URL, emoji="➕"))
        view.add_item(discord.ui.Button(label="Developer", style=discord.ButtonStyle.link, url=DEVELOPER_URL, emoji="👤"))
        await interaction.response.send_message(embed=embed, view=view, ephemeral=False)


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
