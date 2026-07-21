"""Phishing Image Bot — blocks known phishing/spam images by perceptual hash.

Single-file Discord bot: slash commands under /imgcheck, JSON storage on disk
(guild settings + hash blocklists only), no database required.
"""

from __future__ import annotations

import asyncio
import io
import json
import logging
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from datetime import timedelta
from typing import Awaitable, Callable, Iterable, Literal

import aiohttp
import discord
import imagehash
from discord import app_commands
from dotenv import load_dotenv
from PIL import Image

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("phishing-image-bot")

DATA_FILE = os.getenv("DATA_FILE", "data/data.json")
DEV_GUILD_ID = int(guild_id) if (guild_id := os.getenv("DEV_GUILD_ID")) else None
# Community hash list — defaults to this bot's own GitHub repo.
PUBLIC_HASHES_URL = os.getenv(
    "PUBLIC_HASHES_URL",
    "https://raw.githubusercontent.com/mon5termatt/phishing-image-bot/main/hashes.txt",
)

IMAGE_EXTENSIONS = (".jpg", ".jpeg", ".png", ".webp", ".gif")
HASH_DISTANCE_THRESHOLD = 8
MAX_TIMEOUT_SECONDS = 2_419_200  # Discord cap: 28 days
MAX_IMAGE_BYTES = 32 * 1024 * 1024  # don't hash absurdly large files
MOD_PERMS = discord.Permissions(manage_messages=True)
INVITE_PERMISSIONS = discord.Permissions(
    view_channel=True,
    send_messages=True,
    manage_messages=True,
    manage_channels=True,  # for /imgcheck setup creating a log channel
    embed_links=True,
    attach_files=True,
    read_message_history=True,
    ban_members=True,
    moderate_members=True,
)

GUILD_DEFAULTS: dict = {
    "log_channel_id": None,
    "punish_action": "timeout",  # "timeout" | "ban"
    "punish_duration": 600,  # seconds; 0 = permanent (ban)
    "dry_run": False,
    "debug": False,
    "hashes": [],
}


def message_content_enabled() -> bool:
    return os.getenv("ENABLE_MESSAGE_CONTENT", "false").lower() in {"1", "true", "yes"}


# --------------------------------------------------------------------------- #
# Small utilities
# --------------------------------------------------------------------------- #

_DURATION_RE = re.compile(
    r"^(?:(?P<days>\d+)d)?(?:(?P<hours>\d+)h)?(?:(?P<minutes>\d+)m)?(?:(?P<seconds>\d+)s)?$"
)


def parse_timedelta(value: str) -> timedelta | None:
    match = _DURATION_RE.fullmatch(value.strip().lower())
    if not match or not any(match.groupdict().values()):
        return None
    return timedelta(
        days=int(match.group("days") or 0),
        hours=int(match.group("hours") or 0),
        minutes=int(match.group("minutes") or 0),
        seconds=int(match.group("seconds") or 0),
    )


def humanize_timedelta(delta: timedelta) -> str:
    total = int(delta.total_seconds())
    if total <= 0:
        return "0 seconds"

    parts: list[str] = []
    days, remainder = divmod(total, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)

    if days:
        parts.append(f"{days} day{'s' if days != 1 else ''}")
    if hours:
        parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
    if minutes:
        parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
    if seconds and not parts:
        parts.append(f"{seconds} second{'s' if seconds != 1 else ''}")

    return " ".join(parts)


def parse_hash_list(raw: str) -> list[str]:
    """Split hash input on whitespace, commas, or newlines; ignore comments."""
    values: list[str] = []
    for line in raw.splitlines():
        line = line.split("#", 1)[0]
        values.extend(part for part in re.split(r"[\s,]+", line.strip()) if part)
    return values


def pagify(text: str, *, page_length: int = 1800) -> Iterable[str]:
    if len(text) <= page_length:
        yield text
        return

    current: list[str] = []
    current_len = 0
    for line in text.splitlines():
        line_len = len(line) + 1
        if current and current_len + line_len > page_length:
            yield "\n".join(current)
            current = [line]
            current_len = line_len
        else:
            current.append(line)
            current_len += line_len

    if current:
        yield "\n".join(current)


async def send_ephemeral_boxed(
    interaction: discord.Interaction,
    content: str,
    *,
    lang: str = "",
) -> None:
    """Send code-boxed content across multiple ephemeral messages if needed."""
    pages = [f"```{lang}\n{page}\n```" for page in pagify(content or "(no output)")]
    await interaction.followup.send(pages[0], ephemeral=True)
    for page in pages[1:]:
        await interaction.followup.send(page, ephemeral=True)


def _phash_bytes(image_bytes: bytes) -> imagehash.ImageHash:
    with Image.open(io.BytesIO(image_bytes)) as img:
        return imagehash.phash(img)


async def hash_image_bytes(image_bytes: bytes) -> imagehash.ImageHash:
    """Hash off the event loop; decoding large images is CPU-bound."""
    return await asyncio.to_thread(_phash_bytes, image_bytes)


def is_immune(member: discord.Member) -> bool:
    perms = member.guild_permissions
    return perms.manage_messages or perms.kick_members or perms.ban_members or perms.administrator


def is_image_attachment(attachment: discord.Attachment) -> bool:
    if attachment.content_type and attachment.content_type.startswith("image/"):
        return True
    return attachment.filename.lower().endswith(IMAGE_EXTENSIONS)


# --------------------------------------------------------------------------- #
# Storage — one JSON file, guild settings + hashes only
# --------------------------------------------------------------------------- #


class Storage:
    """Per-guild settings and hash blocklists in a single JSON file.

    Only guilds that changed something are stored, and only the fields above —
    no message content, no user data.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = asyncio.Lock()
        self._guilds: dict[str, dict] = {}
        # Parsed ImageHash objects per guild, rebuilt on modification.
        self._hash_cache: dict[str, list[imagehash.ImageHash]] = {}

        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fp:
                data = json.load(fp)
            self._guilds = data.get("guilds", {})

    def _save(self) -> None:
        directory = os.path.dirname(self.path) or "."
        os.makedirs(directory, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=directory, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fp:
                json.dump({"guilds": self._guilds}, fp, indent=1)
            os.replace(tmp_path, self.path)
        except BaseException:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

    def guild(self, guild_id: int) -> dict:
        stored = self._guilds.get(str(guild_id), {})
        merged = {**GUILD_DEFAULTS, **stored}
        # Copy the list so callers can never mutate stored data (or the defaults).
        merged["hashes"] = list(merged["hashes"])
        return merged

    async def update(self, guild_id: int, **values) -> None:
        unknown = set(values) - set(GUILD_DEFAULTS)
        if unknown:
            raise KeyError(f"Unknown guild settings: {unknown}")
        async with self._lock:
            entry = self._guilds.setdefault(str(guild_id), {})
            entry.update(values)
            if "hashes" in values:
                self._hash_cache.pop(str(guild_id), None)
            self._save()

    def hashes(self, guild_id: int) -> list[str]:
        return list(self.guild(guild_id)["hashes"])

    def hash_objects(self, guild_id: int) -> list[imagehash.ImageHash]:
        key = str(guild_id)
        cached = self._hash_cache.get(key)
        if cached is None:
            cached = []
            for value in self.guild(guild_id)["hashes"]:
                try:
                    cached.append(imagehash.hex_to_hash(value))
                except ValueError:
                    logger.warning("Dropping invalid stored hash %r for guild %s", value, guild_id)
            self._hash_cache[key] = cached
        return cached

    async def add_hashes(self, guild_id: int, values: list[str]) -> int:
        current = self.hashes(guild_id)
        existing = set(current)
        added = [value for value in values if value not in existing]
        if added:
            await self.update(guild_id, hashes=current + added)
        return len(added)

    async def remove_hashes(self, guild_id: int, values: list[str]) -> int:
        current = self.hashes(guild_id)
        to_remove = set(values)
        remaining = [value for value in current if value not in to_remove]
        removed = len(current) - len(remaining)
        if removed:
            await self.update(guild_id, hashes=remaining)
        return removed


store = Storage(DATA_FILE)


# --------------------------------------------------------------------------- #
# Bot
# --------------------------------------------------------------------------- #


class PhishingImageBot(discord.Client):
    def __init__(self) -> None:
        intents = discord.Intents.default()
        # Privileged: Message Content only when enabled. Never enable Guild Members.
        intents.message_content = message_content_enabled()
        intents.members = False
        super().__init__(
            intents=intents,
            allowed_mentions=discord.AllowedMentions(everyone=False, roles=False, users=True),
        )
        self.tree = app_commands.CommandTree(self)
        self.session: aiohttp.ClientSession | None = None

    async def setup_hook(self) -> None:
        self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=60))
        self.tree.add_command(imgcheck)
        self.tree.on_error = self.on_app_command_error

        if DEV_GUILD_ID is not None:
            dev_guild = discord.Object(id=DEV_GUILD_ID)
            self.tree.copy_global_to(guild=dev_guild)
            synced = await self.tree.sync(guild=dev_guild)
            logger.info("Synced %s slash command(s) to guild %s.", len(synced), DEV_GUILD_ID)
        else:
            synced = await self.tree.sync()
            logger.info("Synced %s slash command(s) globally.", len(synced))

    async def close(self) -> None:
        if self.session is not None:
            await self.session.close()
        await super().close()

    async def on_app_command_error(
        self,
        interaction: discord.Interaction,
        error: app_commands.AppCommandError,
    ) -> None:
        message = "Something went wrong while running that command."
        if interaction.response.is_done():
            await interaction.followup.send(message, ephemeral=True)
        else:
            await interaction.response.send_message(message, ephemeral=True)
        logger.error("Slash command error: %r", error)

    async def on_ready(self) -> None:
        assert self.user is not None
        invite = discord.utils.oauth_url(
            self.application_id,
            permissions=INVITE_PERMISSIONS,
            scopes=("bot", "applications.commands"),
        )
        logger.info("Logged in as %s (ID: %s)", self.user, self.user.id)
        logger.info("Connected to %s guild(s).", len(self.guilds))
        logger.info("Invite link: %s", invite)
        if not self.intents.message_content:
            logger.warning(
                "Message Content Intent is disabled. Enable it in the Discord Developer "
                "Portal and set ENABLE_MESSAGE_CONTENT=true for automatic image scanning."
            )

    async def on_message(self, message: discord.Message) -> None:
        if not message.guild or message.author.bot or not self.intents.message_content:
            return
        if not collect_scan_targets(message):
            return
        await process_message(self, message)

    async def on_message_edit(self, before: discord.Message, after: discord.Message) -> None:
        # Link embeds often resolve *after* the original message event — Discord
        # dispatches that as an edit. Rescan only when new embeds appeared.
        if not after.guild or after.author.bot or not self.intents.message_content:
            return
        if len(after.embeds) <= len(before.embeds):
            return
        await process_message(self, after)


bot = PhishingImageBot()


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class ScanTarget:
    label: str
    read: Callable[[], Awaitable[bytes]]


async def fetch_url(url: str) -> bytes:
    assert bot.session is not None
    async with bot.session.get(url) as response:
        response.raise_for_status()
        return await response.read()


def collect_scan_targets(message: discord.Message) -> list[ScanTarget]:
    targets: list[ScanTarget] = []

    for attachment in message.attachments:
        if is_image_attachment(attachment):
            targets.append(ScanTarget(label=attachment.filename, read=attachment.read))

    for index, embed in enumerate(message.embeds):
        if embed.image and embed.image.url:
            url = embed.image.url
            targets.append(
                ScanTarget(label=f"embed-{index}-image", read=lambda url=url: fetch_url(url))
            )
        if embed.thumbnail and embed.thumbnail.url:
            url = embed.thumbnail.url
            targets.append(
                ScanTarget(label=f"embed-{index}-thumbnail", read=lambda url=url: fetch_url(url))
            )

    for index, sticker in enumerate(message.stickers):
        url = sticker.url
        targets.append(ScanTarget(label=f"sticker-{index}", read=lambda url=url: fetch_url(url)))

    return targets


async def resolve_log_channel(
    guild: discord.Guild, channel_id: int | None
) -> discord.TextChannel | None:
    if not channel_id:
        return None

    channel = guild.get_channel(channel_id)
    if channel is None:
        try:
            channel = await bot.fetch_channel(channel_id)
        except discord.HTTPException as exc:
            logger.warning("Failed to fetch log channel %s: %s", channel_id, exc)
            return None

    return channel if isinstance(channel, discord.TextChannel) else None


async def log_debug(
    guild: discord.Guild,
    settings: dict,
    event: str,
    details: str,
    *,
    color: discord.Color = discord.Color.blurple(),
) -> None:
    dry_run_note = " [DRY RUN]" if settings["dry_run"] else ""
    logger.info("[scan]%s %s: %s", dry_run_note, event, details.replace("\n", " | "))

    # Verbose breadcrumbs only reach Discord when /imgcheck debug is on.
    if not settings["debug"]:
        return

    channel = await resolve_log_channel(guild, settings["log_channel_id"])
    if channel is None:
        return

    embed = discord.Embed(
        title=f"[imgcheck debug] {event}{dry_run_note}",
        description=details[:4000],
        colour=color,
        timestamp=discord.utils.utcnow(),
    )
    try:
        await channel.send(embed=embed)
    except discord.HTTPException as exc:
        logger.warning("Failed to send debug embed: %s", exc)


async def resolve_member(
    guild: discord.Guild, author: discord.abc.User
) -> discord.Member | None:
    if isinstance(author, discord.Member):
        return author
    cached = guild.get_member(author.id)
    if cached is not None:
        return cached
    try:
        return await guild.fetch_member(author.id)
    except discord.HTTPException:
        return None


def channel_permission_issues(channel: discord.TextChannel) -> list[str]:
    """Permissions the bot is missing to post detection embeds in a channel."""
    me = channel.guild.me
    if me is None:
        return []
    perms = channel.permissions_for(me)
    missing: list[str] = []
    if not perms.send_messages:
        missing.append("Send Messages")
    if not perms.embed_links:
        missing.append("Embed Links")
    if not perms.attach_files:
        missing.append("Attach Files")
    return missing


async def process_message(client: PhishingImageBot, message: discord.Message) -> None:
    guild = message.guild
    assert guild is not None

    settings = store.guild(guild.id)
    blocked_hashes = store.hash_objects(guild.id)
    if not blocked_hashes:
        return

    scan_targets = collect_scan_targets(message)
    if not scan_targets:
        return

    user = await resolve_member(guild, message.author)
    user_label = (
        f"{user.mention} ({user.id})" if user else f"<@{message.author.id}> ({message.author.id})"
    )

    if user is not None and is_immune(user) and not settings["dry_run"]:
        await log_debug(
            guild,
            settings,
            "Skipped",
            f"User {user_label} is immune (mod/admin permissions).",
            color=discord.Color.light_grey(),
        )
        return

    await log_debug(
        guild,
        settings,
        "Scan started",
        (
            f"Message ID: `{message.id}`\n"
            f"User: {user_label}\n"
            f"Channel: {message.channel.mention}\n"
            f"Blocklist size: {len(blocked_hashes)}\n"
            f"Scannable items: {len(scan_targets)}"
        ),
    )

    for target in scan_targets:
        try:
            image_bytes = await target.read()
            if len(image_bytes) > MAX_IMAGE_BYTES:
                await log_debug(
                    guild,
                    settings,
                    "Skipped item",
                    (
                        f"Message ID: `{message.id}`\n"
                        f"Item: `{target.label}` is {len(image_bytes) // (1024 * 1024)} MiB "
                        f"(limit {MAX_IMAGE_BYTES // (1024 * 1024)} MiB)."
                    ),
                    color=discord.Color.light_grey(),
                )
                continue
            incoming_hash = await hash_image_bytes(image_bytes)

            matched_hash: imagehash.ImageHash | None = None
            matched_distance = 0
            closest_distance: int | None = None
            for blocked_hash in blocked_hashes:
                distance = incoming_hash - blocked_hash
                if closest_distance is None or distance < closest_distance:
                    closest_distance = distance
                if distance <= HASH_DISTANCE_THRESHOLD and matched_hash is None:
                    matched_hash = blocked_hash
                    matched_distance = distance

            if matched_hash is None:
                await log_debug(
                    guild,
                    settings,
                    "No match",
                    (
                        f"Message ID: `{message.id}`\n"
                        f"Item: `{target.label}`\n"
                        f"Hash: `{incoming_hash}`\n"
                        f"Closest distance: {closest_distance} "
                        f"(needs <= {HASH_DISTANCE_THRESHOLD})"
                    ),
                    color=discord.Color.green(),
                )
                continue

            await log_debug(
                guild,
                settings,
                "Match found",
                (
                    f"Message ID: `{message.id}`\n"
                    f"User: {user_label}\n"
                    f"Item: `{target.label}`\n"
                    f"Matched hash: `{matched_hash}`\n"
                    f"Distance: {matched_distance}"
                ),
                color=discord.Color.orange(),
            )

            if user is None:
                await log_detection(
                    guild,
                    settings,
                    message.author,
                    message,
                    str(matched_hash),
                    target.label,
                    image_bytes,
                    "Skipped — user left the server",
                    distance=matched_distance,
                )
                return

            await handle_violation(
                message,
                settings,
                str(matched_hash),
                target,
                image_bytes,
                user,
                distance=matched_distance,
            )
            return
        except Exception as exc:
            await log_debug(
                guild,
                settings,
                "Scan error",
                f"Message ID: `{message.id}`\nItem: `{target.label}`\nError: {exc}",
                color=discord.Color.red(),
            )
            logger.exception("Image scan error for %s", target.label)


async def handle_violation(
    message: discord.Message,
    settings: dict,
    matched_hash: str,
    target: ScanTarget,
    image_bytes: bytes,
    user: discord.Member,
    *,
    distance: int,
) -> None:
    guild = message.guild
    assert guild is not None

    dry_run = settings["dry_run"]
    action = settings["punish_action"]
    seconds = settings["punish_duration"]
    reason = f"Blacklisted image: {target.label} (Match: {matched_hash})"
    punish_str = "None (Cleanup Only)"

    if dry_run:
        logger.warning("[DRY RUN] Would delete message %s and %s user %s", message.id, action, user.id)
    else:
        try:
            await message.delete()
        except discord.Forbidden:
            pass
        await message.channel.send(
            f"⚠️ {user.mention}, your message was removed for matching known phishing images.",
            delete_after=15,
        )

    try:
        if action == "ban" and guild.me and guild.me.guild_permissions.ban_members:
            punish_str = "Ban (Permanent)"
            if dry_run:
                punish_str = f"[DRY RUN] {punish_str}"
            else:
                await guild.ban(user, reason=reason, delete_message_seconds=7200)
        elif action == "timeout" and guild.me and guild.me.guild_permissions.moderate_members:
            duration = (
                timedelta(seconds=seconds)
                if 0 < seconds <= MAX_TIMEOUT_SECONDS
                else timedelta(days=28)
            )
            punish_str = f"Timeout ({humanize_timedelta(duration)})"
            if dry_run:
                punish_str = f"[DRY RUN] {punish_str}"
            else:
                await user.timeout(duration, reason=reason)
        else:
            punish_str = f"Attempted {action} (Missing Permissions)"
    except Exception as exc:
        logger.error("Enforcement failed: %s", exc)
        punish_str = f"Error applying {action}"

    await log_detection(
        guild,
        settings,
        user,
        message,
        matched_hash,
        target.label,
        image_bytes,
        punish_str,
        distance=distance,
    )


async def log_detection(
    guild: discord.Guild,
    settings: dict,
    user: discord.abc.User,
    message: discord.Message,
    match_hash: str,
    filename: str,
    image_bytes: bytes,
    punish_str: str,
    *,
    distance: int,
) -> None:
    channel = await resolve_log_channel(guild, settings["log_channel_id"])
    if channel is None:
        logger.warning("No log channel configured for guild %s", guild.id)
        return

    dry_run_note = " [DRY RUN]" if settings["dry_run"] else ""
    embed = discord.Embed(
        title=f"Blacklisted Image Detected{dry_run_note}",
        color=discord.Color.red(),
        description=(
            f"**User:** {user.mention} (`{user}`) (`{user.id}`)\n"
            f"**Time:** {discord.utils.format_dt(message.created_at, style='F')}\n"
        ),
        timestamp=discord.utils.utcnow(),
    )
    embed.add_field(name="Action Applied", value=f"**{punish_str}**", inline=False)
    embed.add_field(name="Message ID", value=f"`{message.id}`", inline=True)
    embed.add_field(name="Detected File", value=f"`{filename}`", inline=True)
    embed.add_field(name="Matched Hash", value=f"`{match_hash}`", inline=True)
    embed.add_field(name="Distance", value=f"`{distance}`", inline=True)
    if message.content:
        embed.add_field(name="User Message", value=message.content[:1024], inline=False)

    safe_name = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in filename) or "match.png"
    attach_name = f"MATCH_{safe_name}"
    file = discord.File(io.BytesIO(image_bytes), filename=attach_name)
    embed.set_image(url=f"attachment://{attach_name}")
    try:
        await channel.send(embed=embed, file=file)
    except discord.HTTPException as exc:
        logger.warning("Failed to send detection log: %s", exc)


# --------------------------------------------------------------------------- #
# Slash commands — /imgcheck …
# --------------------------------------------------------------------------- #

imgcheck = app_commands.Group(
    name="imgcheck",
    description="Phishing image checker settings and moderation tools.",
    default_permissions=MOD_PERMS,
    guild_only=True,
)


def _merge_new_hashes(
    candidates: list[str],
    existing_objects: list[imagehash.ImageHash],
) -> tuple[list[str], list[str], int, int, int]:
    """Dedupe candidates against existing hashes; returns (new, log, added, skipped, errors)."""
    known = list(existing_objects)
    new_hashes: list[str] = []
    log_lines: list[str] = []
    added = skipped = errors = 0

    for value in candidates:
        try:
            hash_obj = imagehash.hex_to_hash(value)
        except Exception:
            log_lines.append(f"ERROR | {value} (Invalid Format)")
            errors += 1
            continue
        if any((hash_obj - existing) <= HASH_DISTANCE_THRESHOLD for existing in known):
            log_lines.append(f"SKIPPED | {value} (Duplicate/Similar)")
            skipped += 1
            continue
        new_hashes.append(str(hash_obj))
        known.append(hash_obj)
        log_lines.append(f"ADDED | {value}")
        added += 1

    return new_hashes, log_lines, added, skipped, errors


@dataclass(slots=True)
class SyncResult:
    added: int
    skipped: int
    errors: int
    removed: int
    total: int


async def sync_community_hashes(guild_id: int, *, removal: bool = False) -> SyncResult:
    """Merge the community hash list into a guild's blocklist.

    With removal=True the blocklist is mirrored: local hashes that are no
    longer in the community list (including ones added manually) are dropped.
    Raises on download failure or an empty remote list.
    """
    raw = (await fetch_url(PUBLIC_HASHES_URL)).decode("utf-8", errors="replace")
    values = parse_hash_list(raw)
    if not values:
        raise ValueError("the community hash list is empty")

    removed = 0
    if removal:
        remote: set[str] = set()
        for value in values:
            try:
                remote.add(str(imagehash.hex_to_hash(value)))
            except Exception:
                continue
        # Stored hashes are always canonical (str of an ImageHash), so exact
        # comparison against the canonicalized remote list is safe.
        stale = [value for value in store.hashes(guild_id) if value not in remote]
        removed = await store.remove_hashes(guild_id, stale)

    new_hashes, _, added, skipped, errors = _merge_new_hashes(
        values, store.hash_objects(guild_id)
    )
    if new_hashes:
        await store.add_hashes(guild_id, new_hashes)

    return SyncResult(
        added=added,
        skipped=skipped,
        errors=errors,
        removed=removed,
        total=len(store.hashes(guild_id)),
    )


@imgcheck.command(
    name="setup",
    description="One-shot setup: log channel, punishment, and community hash sync.",
)
@app_commands.describe(
    channel="Existing channel for detection alerts. Leave empty to create #phishing-log.",
    action="Punishment on detection (leave empty to keep current, default timeout).",
    duration="Timeout duration, e.g. 1h, 30m, 1d. Ignored for ban.",
    sync="Also download the community hash list from GitHub (default: true).",
)
async def setup_cmd(
    interaction: discord.Interaction,
    channel: discord.TextChannel | None = None,
    action: Literal["ban", "timeout"] | None = None,
    duration: str | None = None,
    sync: bool = True,
) -> None:
    guild = interaction.guild
    assert guild is not None
    await interaction.response.defer(ephemeral=True)
    lines: list[str] = []

    # 1. Log channel — use the given one, or create a hidden #phishing-log.
    if channel is None:
        overwrites: dict[discord.abc.Snowflake, discord.PermissionOverwrite] = {
            guild.default_role: discord.PermissionOverwrite(view_channel=False),
        }
        if guild.me is not None:
            overwrites[guild.me] = discord.PermissionOverwrite(
                view_channel=True,
                send_messages=True,
                embed_links=True,
                attach_files=True,
            )
        for role in guild.roles:
            if role.is_default() or role.managed:
                continue
            if role.permissions.manage_messages or role.permissions.administrator:
                overwrites[role] = discord.PermissionOverwrite(
                    view_channel=True, read_message_history=True
                )
        try:
            channel = await guild.create_text_channel(
                name="phishing-log",
                overwrites=overwrites,
                topic="Phishing image detections — created by /imgcheck setup.",
                reason=f"Imgcheck setup by {interaction.user} ({interaction.user.id})",
            )
            lines.append(f"**Log channel:** created {channel.mention} (hidden from @everyone)")
        except discord.Forbidden:
            lines.append(
                "**Log channel:** could not create one (missing **Manage Channels**). "
                "Re-run with `channel:` or grant the permission."
            )
    else:
        line = f"**Log channel:** {channel.mention}"
        missing = channel_permission_issues(channel)
        if missing:
            line += f" — ⚠️ missing **{', '.join(missing)}** there"
        lines.append(line)

    if channel is not None:
        await store.update(guild.id, log_channel_id=channel.id)

    # 2. Punishment.
    if action is not None or duration is not None:
        current = store.guild(guild.id)
        new_action = action or current["punish_action"]
        seconds = current["punish_duration"]
        if duration:
            parsed = parse_timedelta(duration)
            if parsed is None:
                lines.append(
                    f"**Punishment:** invalid duration `{duration}` — kept current settings. "
                    "Use formats like `1h`, `30m`, or `1d`."
                )
                new_action = None
            else:
                seconds = int(parsed.total_seconds())
        if new_action is not None:
            await store.update(guild.id, punish_action=new_action, punish_duration=seconds)
            time_msg = (
                humanize_timedelta(timedelta(seconds=seconds)) if seconds > 0 else "permanent"
            )
            lines.append(f"**Punishment:** {new_action} ({time_msg})")
    else:
        current = store.guild(guild.id)
        time_msg = (
            humanize_timedelta(timedelta(seconds=current["punish_duration"]))
            if current["punish_duration"] > 0
            else "permanent"
        )
        lines.append(f"**Punishment:** {current['punish_action']} ({time_msg}) — unchanged")

    # 3. Community hash list.
    if sync:
        try:
            result = await sync_community_hashes(guild.id)
            lines.append(
                f"**Hashes:** {result.added} added from the community list "
                f"({result.total} total)"
            )
        except Exception as exc:
            lines.append(f"**Hashes:** sync failed — {exc}")
    else:
        lines.append(
            f"**Hashes:** sync skipped ({len(store.hashes(guild.id))} stored) — "
            "run `/imgcheck synchashes` anytime"
        )

    if not message_content_enabled():
        lines.append(
            "⚠️ `ENABLE_MESSAGE_CONTENT` is off — automatic scanning is inactive."
        )

    await interaction.followup.send(
        "**Setup complete.**\n" + "\n".join(lines),
        ephemeral=True,
    )


@imgcheck.command(name="setchannel", description="Set the channel for detection alerts and debug logs.")
@app_commands.describe(channel="Channel to receive imgcheck logs (omit to show current).")
async def setchannel(
    interaction: discord.Interaction,
    channel: discord.TextChannel | None = None,
) -> None:
    assert interaction.guild is not None
    if channel is None:
        current_id = store.guild(interaction.guild.id)["log_channel_id"]
        current = f"<#{current_id}>" if current_id else "not set"
        await interaction.response.send_message(
            f"Current log channel: {current}. Pass `channel:` to change it.",
            ephemeral=True,
        )
        return

    await store.update(interaction.guild.id, log_channel_id=channel.id)
    reply = (
        f"Log channel set to {channel.mention}. "
        "Detection alerts (and debug embeds when enabled) will post there."
    )
    missing = channel_permission_issues(channel)
    if missing:
        reply += f"\n⚠️ I'm missing **{', '.join(missing)}** in that channel — alerts may fail."
    await interaction.response.send_message(reply, ephemeral=True)


@imgcheck.command(name="setpunish", description="Set punishment on detection.")
@app_commands.describe(
    action="Punishment to apply when a match is found.",
    duration="Timeout length, e.g. 1h, 30m, 1d (max 28d). Ignored for ban; empty = 28 days.",
)
async def setpunish(
    interaction: discord.Interaction,
    action: Literal["ban", "timeout"],
    duration: str | None = None,
) -> None:
    assert interaction.guild is not None

    seconds = 0
    note = ""
    if action == "ban":
        if duration:
            note = " (bans are always permanent; duration ignored)"
    elif duration:
        parsed = parse_timedelta(duration)
        if parsed is None:
            await interaction.response.send_message(
                "Invalid duration. Use formats like `1h`, `30m`, or `1d`.",
                ephemeral=True,
            )
            return
        seconds = int(parsed.total_seconds())
        if seconds > MAX_TIMEOUT_SECONDS:
            seconds = MAX_TIMEOUT_SECONDS
            note = " (capped at Discord's 28-day timeout limit)"

    await store.update(interaction.guild.id, punish_action=action, punish_duration=seconds)
    if action == "ban":
        time_msg = "permanently"
    elif seconds > 0:
        time_msg = f"for {humanize_timedelta(timedelta(seconds=seconds))}"
    else:
        time_msg = "for 28 days (default)"
    await interaction.response.send_message(
        f"Punishment set to **{action}** {time_msg}.{note}", ephemeral=True
    )


@imgcheck.command(name="dryrun", description="Toggle dry-run mode: detections are logged but never enforced.")
@app_commands.describe(enabled="Simulate punishments instead of applying them.")
async def dryrun(interaction: discord.Interaction, enabled: bool) -> None:
    assert interaction.guild is not None
    await store.update(interaction.guild.id, dry_run=enabled)
    state = "enabled" if enabled else "disabled"
    await interaction.response.send_message(
        f"Dry-run is now **{state}** for this server.", ephemeral=True
    )


@imgcheck.command(name="debug", description="Toggle verbose image-scan logs (sent to the log channel).")
@app_commands.describe(enabled="Enable or disable imgcheck debug embeds.")
async def debug(interaction: discord.Interaction, enabled: bool) -> None:
    assert interaction.guild is not None
    await store.update(interaction.guild.id, debug=enabled)
    settings = store.guild(interaction.guild.id)
    state = "enabled" if enabled else "disabled"
    dest = (
        f"<#{settings['log_channel_id']}>"
        if settings["log_channel_id"]
        else "nowhere yet — set one with `/imgcheck setchannel`"
    )
    await interaction.response.send_message(
        f"Image check debug logging is now **{state}**.\n"
        f"Scan progress embeds go to {dest}. "
        "Blocklist hits still post a single **Blacklisted Image Detected** embed.",
        ephemeral=True,
    )


@imgcheck.command(name="settings", description="Show image checker settings.")
async def settings_cmd(interaction: discord.Interaction) -> None:
    assert interaction.guild is not None
    data = store.guild(interaction.guild.id)
    if data["punish_action"] == "ban":
        punish_text = "ban (permanent)"
    elif data["punish_duration"] > 0:
        punish_text = f"timeout ({humanize_timedelta(timedelta(seconds=data['punish_duration']))})"
    else:
        punish_text = "timeout (28 days, default)"
    channel_text = (
        f"<#{data['log_channel_id']}>"
        if data["log_channel_id"]
        else "Not set — `/imgcheck setchannel` or `/imgcheck setup`"
    )
    lines = [
        f"**Punishment:** {punish_text}",
        f"**Dry-run:** {'enabled' if data['dry_run'] else 'disabled'}",
        f"**Debug logging:** {'enabled' if data['debug'] else 'disabled'}",
        f"**Log channel:** {channel_text}",
        f"**Blocklist size:** {len(data['hashes'])}",
        f"**Community list:** <{PUBLIC_HASHES_URL}>",
    ]
    if not message_content_enabled():
        lines.append("⚠️ `ENABLE_MESSAGE_CONTENT` is off — automatic scanning is inactive.")
    await interaction.response.send_message("\n".join(lines), ephemeral=True)


@imgcheck.command(name="showhashes", description="Show currently stored image hashes.")
async def showhashes(interaction: discord.Interaction) -> None:
    assert interaction.guild is not None
    await interaction.response.defer(ephemeral=True)
    hashes = store.hashes(interaction.guild.id)
    if not hashes:
        await interaction.followup.send("No values stored.", ephemeral=True)
        return
    await send_ephemeral_boxed(interaction, "\n".join(sorted(hashes)), lang="text")


@imgcheck.command(name="hashcheck", description="Show hashes for uploaded image(s).")
@app_commands.describe(
    image="Image to hash.",
    image2="Optional second image.",
    image3="Optional third image.",
)
async def hashcheck(
    interaction: discord.Interaction,
    image: discord.Attachment,
    image2: discord.Attachment | None = None,
    image3: discord.Attachment | None = None,
) -> None:
    await interaction.response.defer(ephemeral=True)
    results: list[str] = []
    for attachment in (image, image2, image3):
        if attachment is None:
            continue
        if not is_image_attachment(attachment):
            results.append(f"{attachment.filename}: Skipped (unsupported format).")
            continue
        try:
            results.append(f"{attachment.filename}: {await hash_image_bytes(await attachment.read())}")
        except Exception:
            results.append(f"{attachment.filename}: Error processing image.")
    await send_ephemeral_boxed(interaction, "\n".join(results), lang="yaml")


@imgcheck.command(name="addimages", description="Add uploaded image(s) to the blocklist.")
@app_commands.describe(
    image="Image to block.",
    image2="Optional second image.",
    image3="Optional third image.",
)
async def addimages(
    interaction: discord.Interaction,
    image: discord.Attachment,
    image2: discord.Attachment | None = None,
    image3: discord.Attachment | None = None,
) -> None:
    assert interaction.guild is not None
    await interaction.response.defer(ephemeral=True)

    known = list(store.hash_objects(interaction.guild.id))
    new_hashes: list[str] = []
    log_lines: list[str] = []

    for attachment in (image, image2, image3):
        if attachment is None:
            continue
        if not is_image_attachment(attachment):
            log_lines.append(f"IGNORED | {attachment.filename}")
            continue
        try:
            new_hash = await hash_image_bytes(await attachment.read())
            if any((new_hash - blocked) <= HASH_DISTANCE_THRESHOLD for blocked in known):
                log_lines.append(f"SKIPPED | {attachment.filename} (Duplicate)")
                continue
            new_hashes.append(str(new_hash))
            known.append(new_hash)
            log_lines.append(f"ADDED | {attachment.filename} ({new_hash})")
        except Exception:
            log_lines.append(f"ERROR | {attachment.filename}")

    if new_hashes:
        await store.add_hashes(interaction.guild.id, new_hashes)
    await send_ephemeral_boxed(interaction, "\n".join(log_lines), lang="ini")


@imgcheck.command(name="addhashes", description="Add image hashes manually.")
@app_commands.describe(raw_hashes="Hashes separated by spaces, commas, or newlines.")
async def addhashes(interaction: discord.Interaction, raw_hashes: str) -> None:
    assert interaction.guild is not None
    values = parse_hash_list(raw_hashes)
    if not values:
        await interaction.response.send_message("Please provide at least one hash.", ephemeral=True)
        return

    await interaction.response.defer(ephemeral=True)
    new_hashes, log_lines, added, skipped, errors = _merge_new_hashes(
        values, store.hash_objects(interaction.guild.id)
    )
    if new_hashes:
        await store.add_hashes(interaction.guild.id, new_hashes)

    summary = f"Summary: {added} added, {skipped} skipped, {errors} errors."
    await send_ephemeral_boxed(interaction, summary + "\n" + "\n".join(log_lines), lang="ini")


@imgcheck.command(name="drophashes", description="Remove image hashes from the blocklist.")
@app_commands.describe(raw_hashes="Hashes separated by spaces, commas, or newlines.")
async def drophashes(interaction: discord.Interaction, raw_hashes: str) -> None:
    assert interaction.guild is not None
    values = parse_hash_list(raw_hashes)
    if not values:
        await interaction.response.send_message("Please provide at least one hash.", ephemeral=True)
        return

    await interaction.response.defer(ephemeral=True)
    stored = set(store.hashes(interaction.guild.id))
    to_remove = [value for value in values if value in stored]
    await store.remove_hashes(interaction.guild.id, to_remove)

    removed = set(to_remove)
    log_lines = [
        f"REMOVED | {value}" if value in removed else f"NOT FOUND | {value}" for value in values
    ]
    await send_ephemeral_boxed(interaction, "\n".join(log_lines), lang="ini")


@imgcheck.command(
    name="synchashes",
    description="Download the community hash list from GitHub and merge it into this server.",
)
@app_commands.describe(
    removal="Also remove local hashes that are NOT in the community list (mirror it exactly).",
)
async def synchashes(interaction: discord.Interaction, removal: bool = False) -> None:
    assert interaction.guild is not None
    await interaction.response.defer(ephemeral=True)

    try:
        result = await sync_community_hashes(interaction.guild.id, removal=removal)
    except Exception as exc:
        await interaction.followup.send(
            f"Failed to sync the hash list from <{PUBLIC_HASHES_URL}>: {exc}",
            ephemeral=True,
        )
        return

    removal_note = (
        f", **{result.removed}** removed (not in the community list)" if removal else ""
    )
    await interaction.followup.send(
        f"Synced community hash list from <{PUBLIC_HASHES_URL}>.\n"
        f"**{result.added}** added, **{result.skipped}** already present/similar, "
        f"**{result.errors}** invalid{removal_note} (**{result.total}** total)."
        + (
            "\n⚠️ `removal:True` mirrors the community list — manually added hashes were dropped."
            if removal and result.removed
            else ""
        ),
        ephemeral=True,
    )


@imgcheck.command(name="testmessage", description="Re-scan a message by ID or link for debugging.")
@app_commands.describe(
    message_id="The message ID (or a full message link) to scan.",
    channel="Channel containing the message. Defaults to the current channel.",
)
async def testmessage(
    interaction: discord.Interaction,
    message_id: str,
    channel: discord.TextChannel | None = None,
) -> None:
    guild = interaction.guild
    assert guild is not None

    # Accept a full message link (https://discord.com/channels/g/c/m) as well as a bare ID.
    raw = message_id.strip()
    if "/" in raw:
        parts = [part for part in raw.split("/") if part]
        if len(parts) >= 3 and parts[-2].isdigit():
            found = guild.get_channel(int(parts[-2]))
            if isinstance(found, discord.TextChannel):
                channel = found
        raw = parts[-1]
    if not raw.isdigit():
        await interaction.response.send_message(
            "Provide a numeric message ID or a full message link.", ephemeral=True
        )
        return

    target_channel = channel or interaction.channel
    if not isinstance(target_channel, discord.TextChannel):
        await interaction.response.send_message("Run this in a text channel.", ephemeral=True)
        return

    await interaction.response.defer(ephemeral=True)
    try:
        message = await target_channel.fetch_message(int(raw))
    except (discord.NotFound, discord.Forbidden, discord.HTTPException) as exc:
        await interaction.followup.send(f"Could not fetch message: {exc}", ephemeral=True)
        return

    await process_message(bot, message)
    await interaction.followup.send(
        f"Scan complete for message `{message_id}` in {target_channel.mention}. "
        "Check the log channel for scan output (if `/imgcheck debug` is on).",
        ephemeral=True,
    )


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def main() -> None:
    token = os.getenv("DISCORD_TOKEN")
    if not token:
        print(
            "Error: DISCORD_TOKEN is not set.\n"
            "Copy .env.example to .env and add your bot token.",
            file=sys.stderr,
        )
        sys.exit(1)
    try:
        bot.run(token, log_handler=None)
    except discord.LoginFailure:
        print(
            "Error: Discord rejected the token. Double-check DISCORD_TOKEN in .env "
            "(Bot page of the Discord Developer Portal → Reset Token).",
            file=sys.stderr,
        )
        sys.exit(1)
    except discord.PrivilegedIntentsRequired:
        print(
            "Error: ENABLE_MESSAGE_CONTENT=true but the Message Content Intent is not "
            "enabled for this bot. Turn it on in the Discord Developer Portal → Bot → "
            "Privileged Gateway Intents, or set ENABLE_MESSAGE_CONTENT=false.",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
