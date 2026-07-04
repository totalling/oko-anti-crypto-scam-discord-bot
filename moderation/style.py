import discord

EMBED_COLOR = discord.Color(0x2B2D31)


def build(description: str, *, timestamp: bool = False, thumbnail_url: str | None = None) -> discord.Embed:
    embed = discord.Embed(description=description, color=EMBED_COLOR)
    if timestamp:
        embed.timestamp = discord.utils.utcnow()
    if thumbnail_url:
        embed.set_thumbnail(url=thumbnail_url)
    return embed


def command_reply(interaction: discord.Interaction, message: str, *, emoji: str = "✅") -> discord.Embed:
    return build(f"{emoji} {interaction.user.mention}: {message}")
