# Phishing Image Bot

A minimal, single-file Discord bot that scans posted images (attachments, embeds, stickers) against a blocklist of perceptual hashes of known phishing/scam images, deletes matches, and optionally times out or bans the sender.

- **One file** (`bot.py`), no database — per-guild settings and hashes live in a small JSON file (`data/data.json`).
- **Minimal data**: the bot stores only your log channel, punishment settings, and hash blocklist. No message content, no user data.
- **Community hash list**: `/imgcheck synchashes` pulls the shared [`hashes.txt`](hashes.txt) straight from this GitHub repo, so every server can start from a maintained blocklist.

## How it works

Every image posted is hashed with a perceptual hash (pHash). If it lands within distance **8** of any blocklisted hash, the message is deleted, the configured punishment (timeout or ban) is applied, and a detection embed (user, matched hash, distance, the image) is posted to your log channel. Recompressed, resized, or lightly edited copies still match. Users with mod/admin permissions are immune.

## Quick start

### Docker

1. Copy `.env.example` to `.env` and set `DISCORD_TOKEN`.
2. Enable **Message Content Intent** in the Discord Developer Portal (required for automatic scanning).
3. `docker compose up -d --build`

### Bare Python

```bash
pip install -r requirements.txt
python bot.py
```

The invite link (with the required permissions) is printed on startup. Optional: set `DEV_GUILD_ID` in `.env` for instant slash-command sync to one server during development.

## Setup in your server

One command does it all — creates a hidden `#phishing-log` channel (or uses one you pass), sets the punishment, and pulls the community blocklist:

```
/imgcheck setup
/imgcheck setup channel:#mod-log action:timeout duration:1h
```

Everything can also be configured individually (`/imgcheck setchannel`, `setpunish`, `synchashes`).

## Commands

All commands are under `/imgcheck` and require **Manage Messages** by default (adjustable in Server Settings → Integrations).

| Command | Parameters | Description |
|---------|------------|-------------|
| `/imgcheck setup` | `channel`, `action`, `duration`, `sync` | One-shot setup: log channel (creates `#phishing-log` if omitted), punishment, community hash sync |
| `/imgcheck setchannel` | `channel` | Set the channel for detection alerts and debug logs (omit to show current) |
| `/imgcheck synchashes` | `removal` | Download the community hash list from GitHub and merge it in; `removal:True` mirrors it exactly (drops local hashes not in the list) |
| `/imgcheck setpunish` | `action`, `duration` | `ban` or `timeout`; duration e.g. `1h`, `30m`, `1d` (empty = permanent ban) |
| `/imgcheck settings` | | Show punishment, dry-run, debug, log channel, and blocklist size |
| `/imgcheck addimages` | `image`, `image2`, `image3` | Add uploaded images to the blocklist |
| `/imgcheck addhashes` | `raw_hashes` | Add hashes manually (space/comma/newline separated) |
| `/imgcheck drophashes` | `raw_hashes` | Remove hashes from the blocklist |
| `/imgcheck showhashes` | | List stored image hashes |
| `/imgcheck hashcheck` | `image`, … | Show perceptual hashes for uploaded images without blocking them |
| `/imgcheck dryrun` | `enabled` | Simulate enforcement (log detections, never punish) |
| `/imgcheck debug` | `enabled` | Verbose scan breadcrumbs to the log channel (default off) |
| `/imgcheck testmessage` | `message_id`, `channel` | Re-scan an existing message by ID (debug) |

## Contributing hashes

[`hashes.txt`](hashes.txt) is the community blocklist that `/imgcheck synchashes` serves. To add a phishing image: run `/imgcheck hashcheck` on it, then open a PR adding the hash (one per line; `#` comments allowed). Please don't commit the images themselves.

## Environment variables

| Variable | Purpose |
|----------|---------|
| `DISCORD_TOKEN` | Bot token (**required**) |
| `ENABLE_MESSAGE_CONTENT` | Must be `true` for automatic scanning |
| `PUBLIC_HASHES_URL` | Override the community hash list URL |
| `DATA_FILE` | Settings/hashes location (default `data/data.json`) |
| `DEV_GUILD_ID` | Instant slash sync to one guild (development) |
