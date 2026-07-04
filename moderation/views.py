import logging

import discord

from moderation import review_store, style

logger = logging.getLogger("scam_bot.moderation.views")

_STRONG_SIGNAL_PREFIXES = ("known scam domain", "impersonates watched name", "matches known scam image", "*win.")


def _is_mod(interaction: discord.Interaction) -> bool:
    return isinstance(interaction.user, discord.Member) and interaction.user.guild_permissions.manage_guild


def _clean_reason(reason: str) -> str:
    if reason.startswith("matches known scam image"):
        return "known scam image match"
    if ": " in reason:
        label, value = reason.split(": ", 1)
        if label == "known scam domain":
            return f"known domain ({value})"
        if label == "impersonates watched name":
            return f"impersonates {value}"
        if label.endswith("scam-pattern domain"):
            return f"suspicious domain ({value})"
    return reason


def _summarize_reasons(reasons: list[str]) -> str:
    if not reasons:
        return "no specific signals recorded"
    strong = [r for r in reasons if r.startswith(_STRONG_SIGNAL_PREFIXES)]
    rest = [r for r in reasons if r not in strong]
    ordered = strong + rest
    shown = ordered[:3]
    remaining = len(reasons) - len(shown)
    summary = ", ".join(_clean_reason(r) for r in shown)
    if remaining > 0:
        summary += f" +{remaining} more"
    return summary


class ScamLogView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    async def _deny(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_message(
            embed=style.command_reply(interaction, "You need Manage Server permission to use this.", emoji="🔒"),
            ephemeral=True,
        )

    @discord.ui.button(label="Details", style=discord.ButtonStyle.secondary, emoji="📋", custom_id="scam_details")
    async def details(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not _is_mod(interaction):
            return await self._deny(interaction)

        review = await review_store.get_review(interaction.message.id)
        if review is None:
            return await interaction.response.send_message(
                embed=style.command_reply(interaction, "No stored details for this entry.", emoji="❌"), ephemeral=True
            )

        summary = _summarize_reasons(review.reasons)
        message = review.content[:300] if review.content else "*(image only, no text)*"
        description = f"> **Signals:** {summary}\n> **Message:** {message}"
        await interaction.response.send_message(embed=style.build(description[:4000]), ephemeral=True)
