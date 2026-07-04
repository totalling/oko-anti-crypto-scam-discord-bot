# Oko

A Discord bot that catches the "celebrity crypto-giveaway" scam pattern — an
impersonated verified account, a casino promo code, and a staged
"withdrawal success" screenshot used as proof. Detection runs entirely
locally: perceptual-hash matching, OCR, and rule-based scoring. No paid
vision/LLM APIs, no data ever leaves your server.

## How detection works

1. **Perceptual hash lookup** — every posted image is fingerprinted and
   checked against a local library of confirmed scam images. A repost, even
   re-compressed or resized, is caught instantly.
2. **OCR** — local Tesseract reads any text baked into the image (promo
   codes, "withdrawal success" banners, giveaway copy).
3. **Rule-based scoring** — the combined message text + OCR text is scored
   against known scam phrases, a scam-domain blocklist, a domain
   generation-pattern regex, and a watchlist of impersonated public figures.
4. **Self-reinforcing** — any image confirmed scam by heuristics has its
   hash added to the library automatically, so the next repost anywhere is
   caught by hash match alone.

Above a confidence threshold, the message is deleted and the author banned;
everything is logged with full evidence to a channel you choose.

## Setup

### 1. Install Tesseract OCR

- **Windows**: [UB-Mannheim build](https://github.com/UB-Mannheim/tesseract/wiki), or `winget install --id UB-Mannheim.TesseractOCR -e`
- **Linux**: `sudo apt install tesseract-ocr`

### 2. Install Python dependencies

```
python -m venv .venv
.venv/bin/pip install -r requirements.txt      # Linux/macOS
.venv\Scripts\pip install -r requirements.txt  # Windows
```

### 3. Create the Discord bot

1. [Discord Developer Portal](https://discord.com/developers/applications) → New Application → Bot → Reset Token.
2. Enable **Message Content Intent** and **Server Members Intent** under Privileged Gateway Intents.
3. OAuth2 → URL Generator → scopes `bot`, `applications.commands`; permissions: Manage Messages, Ban Members, Read Message History, View Channels, Send Messages, Attach Files.
4. Invite the bot with the generated URL.

### 4. Configure

```
cp .env.example .env
```

Fill in `DISCORD_TOKEN`. `TESSERACT_CMD` only needs a value on Windows if
`tesseract` isn't on `PATH`.

### 5. Run

```
python main.py
```

## Deploying to a VPS

See [deploy/oko.service](deploy/oko.service) for a systemd unit. Broad
strokes: copy the repo to `/opt/oko`, set up the venv there, install
Tesseract, fill in `.env`, then:

```bash
sudo useradd -r -s /usr/sbin/nologin oko
sudo chown -R oko:oko /opt/oko
sudo cp deploy/oko.service /etc/systemd/system/oko.service
sudo systemctl daemon-reload
sudo systemctl enable --now oko
```

`sudo systemctl status oko` / `journalctl -u oko -f` to check on it.

## Slash commands

- `/scam adddomain <domain>` — bot owner only. Add a domain to the shared blocklist.
- `/scam removedomain <domain>` — bot owner only.
- `/scam addname <name>` — bot owner only. Add a public figure/brand to the impersonation watchlist.
- `/scam toggle <enabled>` — per-server, Manage Server permission. Turn detection on/off.
- `/scam setlogchannel [channel]` — per-server, Manage Server permission. Where detections get logged.
- `/scam stats` — per-server, Manage Server permission. Blocklist sizes and current settings.
- `/invite` — get an invite link.
- Right-click a message → **Mark as Known Scam** — deletes it, bans the author, and teaches the bot that image.

Domain/name-list commands are bot-owner-only because those lists are shared
across every server the bot is in — one server's admin shouldn't be able to
change what every other server blocks.

## Optional: welcome message + public scam-gate feed

`cogs/welcome.py` and the public "scam gate" feed in `moderation/actions.py`
are wired to one specific server via the IDs in `constants.py`. If you're
running your own instance, either edit those IDs to your own server/channels
or remove the calls to `_post_public_gate` / disable the `cogs.welcome`
extension in `main.py` if you don't want either feature.

## Tuning

In `.env`:
- `HEURISTIC_AUTO_SCAM_SCORE` (default `0.6`) — score needed to treat something as a confirmed scam.
- `CONFIDENCE_BAN_THRESHOLD` (default `0.6`) — confidence needed to ban, not just delete.
- `HASH_DISTANCE_THRESHOLD` (default `8`) — how visually similar an image must be to a known scam image to count as a match.

## License

MIT — see [LICENSE](LICENSE).
