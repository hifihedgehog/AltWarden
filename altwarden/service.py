"""Everything that happens to a member, from joining to verified, kicked, appealed or forgotten.

The bot and the web server both call in here. Nothing in this file imports discord.py or aiohttp's
server parts, so the whole flow runs in tests against a fake Discord.
"""
from __future__ import annotations

import asyncio
import copy
import json
import logging
import time
import weakref
from collections import OrderedDict, defaultdict, deque
from contextlib import asynccontextmanager
from dataclasses import dataclass

from . import altmatch, engine, fixes, health, notices, settings as settings_module, signals
from .catalog import BAN, BY_ID, CHECK_IDS, DENY, FAILURE_TEXT, HELP_SLUG, INSTANT, KICK, SEVERITY, WATCH, WEB
from .crypto import Keyring, is_sealed, network_of, new_token, token_hash, wide_network_of
from .db import Database
from .netintel import NetInfo, NetIntel, last_refusal
from .ports import DISCORD_BUSY, MEMBER_GONE, ROLE_TOO_LOW, DiscordPort, DiscordUnavailable, MemberInfo, Notice

log = logging.getLogger("altwarden.service")

LINK_MINUTES = 60
MAX_BYPASS_HOURS = 168
APPEAL_WINDOW = 7 * 86400
IMPORTED_WITHOUT_ROLE = "imported-without-role"  # an import by another role marks a member verified before they hold the verified role
BELOW_FLOOR_BAN_LOOKUPS = 3
REAPPEAL_SECONDS = 86400  # someone past a used-up limit can always try again, so a try alone can't reopen an appeal at once
MAX_APPEAL_CHARS = 1500
POW_BITS = 17
POW_BITS_RAID = 19  # four times the work, for a script sending many accounts during a raid
HONEYPOT_REPEAT = 60  # a flood of posts from one account gets one action
MAX_LINKS = 20  # accounts on one shared address can run to hundreds, and only the strongest matter
# The attempts a member can appeal or ask the help desk about. A honeypot post with no action taken left them nothing to contest.
APPEALABLE = "(outcome IN ('failed', 'role_problem') OR (outcome = 'honeypot' AND action IN ('timeout', 'kick', 'softban', 'ban')))"
KICK_RETRY_SECONDS = 3600  # an auto kick that failed tries again this much later
LOOKUP_CACHE_SECONDS = 3600
PUBLIC_BOT_SECONDS = 300
LOOKUP_CACHE_SIZE = 5000
LOOKUP_DAILY_LIMIT = 20  # per member. One member's retries mustn't be able to spend a server's whole quota
LOOKUP_NETWORK_LIMIT = 50  # per IPv6 /48 or IPv4 /24, because a new account or a new /64 costs nothing
LOOKUP_COUNT_SIZE = 20000
LOOKUP_WARNING_SECONDS = 86400
DAY = 86400
NOT_SET_UP = "This server isn't set up."
SETTINGS_LOCK = "settings"  # in place of a member's ID, for the lock that writes to a server's settings wait on
# Failing these means changing something on Discord, so the next try needs a new sign-in to see the change.
ACCOUNT_CHECKS = frozenset({"avatar", "mfa", "disposable_email"})
# Trying again right away can't change the answer to these.
NO_RETRY_CHECKS = frozenset({"max_attempts", "account_age", "geogate"})


@dataclass
class Result:
    """What the member sees after an attempt."""

    status: str  # verified, failed, cooldown, already, problem
    title: str
    message: str
    reason: str | None = None
    action: str | None = None
    help_slug: str | None = None
    retry: bool = False
    appeal: bool = False
    seconds_left: float = 0.0
    template: str | None = None
    args: dict | None = None
    retry_on: float | None = None
    staff_help: bool = False
    attempts_left: int | None = None  # with an attempt limit on and not yet reached
    quiet: bool = False  # past a limit: nobody was told anything, so a member with no page to read needs a DM
    fixes: list | None = None  # what to do about each check that stopped them, from fixes.for_findings

    def as_dict(self) -> dict:
        return {"status": self.status, "title": self.title, "message": self.message, "reason": self.reason,
                "action": self.action, "help": self.help_slug, "retry": self.retry, "appeal": self.appeal,
                "seconds_left": round(self.seconds_left), "template": self.template, "args": self.args,
                "retry_on": self.retry_on, "staff_help": self.staff_help, "attempts_left": self.attempts_left,
                "fixes": self.fixes or []}

    def discord_text(self) -> str:
        """The message for a reply in Discord, where timestamps show in each reader's own time zone."""
        text = self.message
        if self.seconds_left > 0:
            text += f" You can try again <t:{int(time.time() + self.seconds_left)}:R>."
        if self.retry_on:
            text += f"\n\nYou can try again after <t:{int(self.retry_on)}:f>."
        if self.attempts_left:
            text += f"\n\n{notices.tries_left(self.attempts_left)}"
        if self.fixes:
            text += notices.fixes_text(self.fixes, room=notices.DESCRIPTION_LIMIT - len(text))
        return text


@dataclass
class ResetResult:
    """What a reset did. It reads as true when the member was told."""

    told: bool = False
    problem: str | None = None  # a role change that didn't happen, or why nothing was done
    kept_hashes: bool = False   # the account is banned, so what catches its next account stayed

    def __bool__(self) -> bool:
        return self.told

    def as_dict(self) -> dict:
        return {"told": self.told, "problem": self.problem, "kept_hashes": self.kept_hashes}


class RaidWatch:
    """Counts different accounts joining in a sliding window, so one account rejoining isn't a raid. Held in memory because a raid is over by any restart."""

    def __init__(self) -> None:
        self.joins: dict[str, deque] = defaultdict(deque)

    def joined(self, guild_id: str, user_id: str, now: float, window: int, limit: int) -> bool:
        joins = self.joins[guild_id]
        joins.append((now, user_id))
        while joins and joins[0][0] < now - window:
            joins.popleft()
        return len({who for _, who in joins}) >= limit

    def forget(self, guild_id: str) -> None:
        """A raid that ended starts the count over, or the joins that began it would begin the next one."""
        self.joins.pop(guild_id, None)


class Service:
    def __init__(self, db: Database, keys: Keyring, net: NetIntel, port: DiscordPort, public_url: str,
                 regions: dict | None = None, zone_countries: dict | None = None):
        self.db = db
        self.keys = keys
        self.net = net
        self.port = port
        self.public_url = public_url.rstrip("/")
        self.regions = regions or {}
        self.zone_countries = zone_countries or {}
        self.raid = RaidWatch()
        self.webhook_sender = None  # set by the web layer, which owns the HTTP session
        self.proxycheck = None      # set at startup, and asked only for servers that chose it
        self._public_bot: tuple[float, bool | None] = (0.0, None)  # (good until, last answer)
        self._settings: dict[str, dict] = {}
        self._honeypot_seen: dict[tuple, float] = {}
        self._background: set = set()  # asyncio keeps only a weak reference, so a running task needs one here
        self._locks: weakref.WeakValueDictionary = weakref.WeakValueDictionary()
        self._lookup_cache: OrderedDict = OrderedDict()   # (server, keyed hash of a network): (good until, what was detected)
        self._lookup_counts: OrderedDict = OrderedDict()  # (server, member): (when their day began, lookups in it)
        self._lookup_networks: OrderedDict = OrderedDict()  # (server, keyed hash of a wide network): the same
        self._lookup_failures: dict[str, dict] = {}       # server: {at, message}, until the next answer
        self._lookup_warned: dict[str, float] = {}

    def _lock(self, *key: str) -> asyncio.Lock:
        """A lock for one thing. With a server and a member's ID: one attempt at a time per member, so counts and actions can't be doubled by a double click."""
        lock = self._locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[key] = lock
        return lock

    @asynccontextmanager
    async def _evidence_held(self, guild_id: str, digests: dict[str, str]):
        """Hold a lock for each piece of evidence, so two accounts sharing any of them finish one after the other.

        Without this, each could read the other as not yet verified, and both would pass the alt check. `altmatch.lock_keys`
        chooses the evidence and says why it's enough. The locks go in one sorted order and a member's own lock always comes
        first. Nothing done while these are held takes a member's lock, so no two attempts can end up waiting on each other.
        Accounts sharing none of that evidence never wait.
        """
        locks = [self._lock(guild_id, kind, digest) for kind, digest in sorted(digests.items())]
        held = []
        try:
            for lock in locks:
                await lock.acquire()
                held.append(lock)
            yield
        finally:
            for lock in reversed(held):
                lock.release()

    # --- settings ---------------------------------------------------------------------------

    async def get_settings(self, guild_id: str) -> dict | None:
        cached = self._settings.get(guild_id)
        if cached is not None:
            return cached
        row = await self.db.guild(guild_id)
        if row is None:
            return None
        document = settings_module.normalize(row["settings"])
        self._settings[guild_id] = document
        return document

    async def is_set_up(self, guild_id: str) -> bool:
        row = await self.db.guild(guild_id)
        return bool(row and row["setup_done"])

    async def edit_settings(self, guild_id: str, build, *, section: str, base: str | None = None, actor_id: str | None = None,
                            actor_name: str | None = None, setup_done: bool | None = None, record: bool = True) -> list[dict]:
        """Change a server's settings from what's stored at this moment, and return what changed, with old and new values.

        `build` gets a copy of the current document and returns the new one. Writes to one server wait for each
        other, so none is built from a document another has replaced. `base` is the `settings.revision` of `section`
        the person saving last saw: if that part has moved on, this raises settings.Conflict and writes nothing.
        With `record` off the change reaches neither the audit log nor the log channel, for a deletion whose old values
        must not be written down again.
        """
        async with self._lock(guild_id, SETTINGS_LOCK):
            before = await self.get_settings(guild_id)
            current = before if before is not None else settings_module.normalize(settings_module.defaults())
            if base is not None and base != settings_module.revision(current, section):
                raise settings_module.Conflict()
            clean = settings_module.normalize(build(copy.deepcopy(current)))
            await self.db.save_settings(guild_id, clean, setup_done=setup_done)
            self._settings[guild_id] = clean
            # Who wrote a message is bookkeeping for its footer line, and it would keep a member's ID in the log.
            changes = [change for change in settings_module.diff(before, clean) if not change["path"].endswith(".author")] if before and record else []
            if changes:
                await self.db.add_audit(guild_id, "settings", actor_id=actor_id, actor_name=actor_name, detail={"changes": changes[:200], "total": len(changes)})
        if changes:
            await self._log(guild_id, clean, ["settings"], notices.staff_log(
                "Settings changed", f"<@{actor_id}> changed {len(changes)} setting{'s' if len(changes) != 1 else ''}." if actor_id
                else f"{len(changes)} settings changed.", notices.GRAY, fields=[
                    {"name": change["path"][:250], "value": f"`{_short(change['before'])}` → `{_short(change['after'])}`", "inline": False}
                    for change in changes[:8]]))
        return changes

    async def save_settings(self, guild_id: str, document: dict, *, actor_id: str | None = None,
                            actor_name: str | None = None, setup_done: bool | None = None) -> list[dict]:
        """Replace a whole document, whatever is stored now. A save built on what someone read earlier uses edit_settings."""
        return await self.edit_settings(guild_id, lambda _: document, section="rules", actor_id=actor_id, actor_name=actor_name, setup_done=setup_done)

    def _open_sealed(self, purpose: str, guild_id: str, value: str) -> str:
        """Open a stored secret. One saved before sealing, and not yet sealed by a startup, reads as it is."""
        return self.keys.unseal(purpose, guild_id, value) if is_sealed(value) else value

    async def lookup_key(self, guild_id: str) -> str | None:
        """A server's proxycheck.io key, ready to use. One that can't be opened reads as no key, because a lookup is never worth stopping a member over."""
        stored = await self.db.lookup_key(guild_id)
        if stored is None:
            return None
        try:
            return self._open_sealed("lookup_keys.lookup_key", guild_id, stored)
        except ValueError:
            log.warning("The lookup key for %s can't be opened", guild_id)
            return None

    async def webhooks(self, guild_id: str, *, unreadable: bool = False) -> list[dict]:
        """A server's webhooks as stored, with `url` and `secret` opened and `events` still JSON.

        One that can't be opened is left out, or comes back with None for both when `unreadable` asks for it, so staff can remove it.
        """
        hooks = []
        for row in await self.db.all("SELECT * FROM webhooks WHERE guild_id = ?", (guild_id,)):
            try:
                hooks.append({**row, "url": self._open_sealed("webhooks.url", guild_id, row["url"]), "secret": self._open_sealed("webhooks.secret", guild_id, row["secret"])})
            except ValueError:
                log.warning("A webhook in %s can't be opened", guild_id)
                if unreadable:
                    hooks.append({**row, "url": None, "secret": None})
        return hooks

    async def add_webhook(self, guild_id: str, url: str, secret: str, events: list[str]) -> int:
        return await self.db.insert("INSERT INTO webhooks (guild_id, url, secret, events, created_at) VALUES (?, ?, ?, ?, ?)",
                                    (guild_id, self.keys.seal("webhooks.url", guild_id, url), self.keys.seal("webhooks.secret", guild_id, secret), json.dumps(events), time.time()))

    async def seal_stored_secrets(self) -> int:
        """Seal any secret still stored in plain text. Run at startup, safe to run again, and returns how many it sealed.

        The log file keeps the plain values until a checkpoint, so one follows.
        """
        found = await self.db.unsealed_secrets()
        sealed = 0
        for item in found:
            value = self.keys.seal(f"{item['table']}.{item['column']}", item["guild_id"], item["value"])
            sealed += await self.db.store_sealed(item["table"], item["column"], item["row_key"], value, plain=item["value"])
        if found:
            await self.db.checkpoint()
        return sealed

    async def set_lookup_key(self, guild_id: str, key: str | None, *, actor_id: str, actor_name: str) -> None:
        """Save or remove a server's proxycheck.io key, sealed. The key itself never reaches the audit log or the log channel."""
        await self.db.set_lookup_key(guild_id, self.keys.seal("lookup_keys.lookup_key", guild_id, key) if key else None)
        what = "saved" if key else "removed"
        await self.db.add_audit(guild_id, "settings", actor_id=actor_id, actor_name=actor_name,
                                detail={"changes": [{"path": "proxycheck.io key", "before": None, "after": what}]})
        document = await self.get_settings(guild_id)
        if document is not None:
            await self._log(guild_id, document, ["settings"], notices.staff_log(
                "Settings changed", f"<@{actor_id}> {what} the proxycheck.io key.", notices.GRAY))

    def forget_cached(self, guild_id: str) -> None:
        self._settings.pop(guild_id, None)

    async def trust_accounts(self, guild_id: str, first: str, second: str, actor_id: str, actor_name: str) -> None:
        """Stop alt matching for a pair. This changes who a check can stop, so it goes in the audit log and the staff log."""
        await self.db.trust_pair(guild_id, first, second, actor_id)
        await self.db.add_audit(guild_id, "trust", actor_id=actor_id, actor_name=actor_name, detail={"first": first, "second": second})
        document = await self.get_settings(guild_id)
        if document is not None:
            await self._clear_limits(guild_id, document, first, second)
            await self._log(guild_id, document, ["general"], notices.staff_log(
                "Accounts trusted", f"<@{actor_id}> trusted <@{first}> and <@{second}>, so they won't be matched as the same person."))

    async def _clear_limits(self, guild_id: str, document: dict, *user_ids: str) -> None:
        """Give attempts back to accounts staff say were wrongly linked, since the attempts that link spent weren't theirs to lose."""
        for user_id in user_ids:
            async with self._lock(guild_id, user_id):
                record = await self.db.member(guild_id, user_id)
                if record and (record["fails"] or record["limit_reached_at"]):
                    await self._give_attempts_back(guild_id, document, user_id)

    async def note_uninstall(self, guild_id: str, actor_id: str) -> None:
        """Said before the records go, because nothing will be left to say it from afterward."""
        document = await self.get_settings(guild_id)
        if document is not None:
            await self._log(guild_id, document, ["general"], notices.staff_log(
                "AltWarden uninstalled", f"<@{actor_id}> ran /uninstall. Every setting and record for this server is being deleted.", notices.RED))

    async def note_command_sync(self, guild_id: str, actor_id: str, actor_name: str, names: list[str]) -> None:
        document = await self.get_settings(guild_id)
        await self.db.add_audit(guild_id, "command_permissions", actor_id=actor_id, actor_name=actor_name, detail={"commands": names})
        if document is not None:
            await self._log(guild_id, document, ["settings"], notices.staff_log(
                "Command permissions changed", f"<@{actor_id}> changed Discord's command permissions for: {', '.join(names[:30])}.", notices.GRAY))

    async def warn_if_broken(self, guild_id: str, document: dict, modules: list[str]) -> None:
        """Tell the help desk or honeypot log when a save left that feature unable to work."""
        guild = await self.port.guild(guild_id)
        if guild is None or not modules:
            return
        titles = {"help_desk": "The help desk can't work yet", "honeypot": "The honeypot can't work yet"}
        for module, lines in health.feature_warnings(guild, document).items():
            if module in modules:
                await self._log(guild_id, document, [module], notices.staff_log(titles[module], "\n".join(lines), notices.AMBER))

    async def effective(self, guild_id: str, document: dict) -> dict:
        return engine.effective_settings(document, await self.raid_active(guild_id))

    async def raid_active(self, guild_id: str) -> bool:
        row = await self.db.guild(guild_id)
        return bool(row and row["raid_until"] > time.time())

    # --- joining ----------------------------------------------------------------------------

    async def on_join(self, member: MemberInfo, *, catching_up: bool = False) -> None:
        """A member joined. Catching up after downtime skips the raid count, because those joins didn't arrive in a burst."""
        guild_id, user_id = member.guild_id, member.user_id
        if member.is_bot or not await self.is_set_up(guild_id):
            return
        document = await self.get_settings(guild_id)
        if not catching_up:
            await self._note_join(guild_id, user_id, document)
        if await self.db.is_banned(guild_id, user_id):
            still_banned = await self._discord_ban(guild_id, user_id)
            if still_banned:  # a join and a ban that arrived together, or a stale member list during a catch-up
                return
            if still_banned is False:  # a banned account can't join, so the ban was lifted while the bot wasn't looking
                await self.on_unban(guild_id, user_id)
        known = await self.db.member(guild_id, user_id)
        await self.db.touch_member(guild_id, user_id, username=member.username, avatar=member.avatar)
        if known is None:
            await self.db.update_member(guild_id, user_id, joined_at=None)  # a new row starts with a time, and this join isn't handled yet
        await self._admit(member, document)
        # Last, because the catch-up after a restart skips anyone whose join time is recent. If anything above
        # didn't finish, that walk handles the member again, and a repeated DM does no harm.
        await self.db.update_member(guild_id, user_id, joined_at=time.time())

    async def _admit(self, member: MemberInfo, document: dict) -> None:
        guild_id, user_id = member.guild_id, member.user_id
        record = await self.db.member(guild_id, user_id)
        core = document["core"]
        # A link that finished before this join would still say "You're verified", and they may not be now.
        await self.db.run("DELETE FROM sessions WHERE guild_id = ? AND user_id = ? AND state = 'done'", (guild_id, user_id))

        if core["verified_role"] in member.role_ids:  # staff or a role-keeping bot got here first, so there's nothing to ask of them
            if record["status"] == "verified":
                await self.db.update_member(guild_id, user_id, **NO_KICK_TIMES)
            else:
                await self.db.mark_verified(guild_id, user_id, "imported")
            return
        if record["status"] == "approved" or (record["status"] == "verified" and core["remember_rejoin"]):
            problem = await self._grant(guild_id, document, user_id, "Already verified in this server")
            if problem is None:
                if record["status"] == "approved":
                    await self.db.mark_verified(guild_id, user_id, "staff")
                else:
                    await self.db.update_member(guild_id, user_id, **NO_KICK_TIMES)
                return
            await self._log(guild_id, document, ["general"], notices.staff_log(
                "Couldn't give the verified role", f"<@{user_id}> rejoined, but: {problem}", notices.RED))
            if record["status"] == "approved":
                return  # Staff already said yes, so this waits for the role to be fixed. Pressing Verify finishes it.
        await self.db.update_member(guild_id, user_id, status="pending")

        limit = document["checks"]["max_attempts"]
        if limit["role"] and record["limit_reached_at"] and limit["action"] in (WATCH, DENY):
            # Leaving took the role away, and the limit it marks is still there.
            problem = await self.port.add_role(guild_id, user_id, limit["role"], "Reached the attempt limit")
            await self._note_role_problem(guild_id, document, user_id, f"give <@&{limit['role']}>", problem)
        mode = core["mode"]
        kick_minutes = None
        live_bypass = await self._live_bypass(guild_id, user_id)
        if core["auto_kick"]["enabled"]:
            # Staff gave a link with its own end date, and rejoining doesn't shorten it.
            kick_minutes = core["auto_kick"]["minutes"]
            await self.db.update_member(guild_id, user_id, **_kick_times(document, live_bypass["expires_at"] if live_bypass else time.time()))
        if mode == INSTANT and not live_bypass:  # a link from staff is what they were told to use, and rejoining doesn't spend it
            await self._check_on_join(member)
            return
        if core["unverified_enabled"] and core["unverified_role"] and mode != INSTANT:
            problem = await self.port.add_role(guild_id, user_id, core["unverified_role"], "Waiting to verify")
            if problem:
                await self._log(guild_id, document, ["general"], notices.staff_log(
                    "Couldn't give the unverified role", f"<@{user_id}> joined, but: {problem}", notices.RED))
        if not core["auto_dm"]:
            return
        guild = await self.port.guild(guild_id)
        name = guild.name if guild else "this server"
        if mode == WEB or live_bypass:
            url, minutes = await self.new_link(guild_id, user_id, document)
            delivered = await self.port.dm(user_id, notices.link_notice(name, url, minutes=minutes, kick_minutes=None if live_bypass else kick_minutes, bypass=bool(live_bypass)))
        else:
            delivered = await self.port.dm(user_id, notices.go_to_channel_notice(name, core["channel"], kick_minutes))
        notify = core["notify_closed_dms"]
        if delivered is False and notify["enabled"] and core["channel"]:  # any other failure says nothing about their DMs
            await self.port.send(core["channel"], notices.closed_dms_notice(user_id, notify["seconds"], kick_minutes), guild_id=guild_id)

    async def _discord_ban(self, guild_id: str, user_id: str) -> bool | None:
        """Whether Discord has this ban, or None if it couldn't say, which mustn't read as no."""
        try:
            return await self.port.is_banned(guild_id, user_id)
        except DiscordUnavailable:
            return None

    async def _check_on_join(self, member: MemberInfo) -> None:
        """Instant mode has no page or button to show a result on, so anything unresolved goes by DM."""
        result = await self.run_quick(member, INSTANT)
        # With no time left to wait, the cooldown is another join still being checked, whose result reaches them. A failure was told already, unless it was a quiet one.
        if result.status not in ("cooldown", "problem") and not result.quiet or (result.status == "cooldown" and result.seconds_left <= 0):
            return
        guild = await self.port.guild(member.guild_id)
        name = guild.name if guild else "this server"
        if result.status == "cooldown":
            await self.port.dm(member.user_id, notices.wait_notice(name, time.time() + result.seconds_left))
        elif result.quiet:
            document = await self.get_settings(member.guild_id)
            appeal_url = f"{self.public_url}/appeal/{member.guild_id}" if document["appeals"]["enabled"] else None
            await self.port.dm(member.user_id, notices.failed_notice(name, "max_attempts", FAILURE_TEXT["max_attempts"], DENY, self.public_url, appeal_url,
                                                                     document["core"]["show_reason"], result.retry_on, instant=True))
        else:
            await self.port.dm(member.user_id, notices.problem_notice(name, result.title, result.message))

    async def _note_join(self, guild_id: str, user_id: str, document: dict) -> None:
        raid = document["raid"]
        if not raid["enabled"]:
            return
        now = time.time()
        if self.raid.joined(guild_id, user_id, now, raid["seconds"], raid["joins"]) and not await self.raid_active(guild_id):
            await self.start_raid(guild_id, document, f"{raid['joins']} joins within {raid['seconds']} seconds")

    async def start_raid(self, guild_id: str, document: dict, why: str, *, actor_id: str | None = None, actor_name: str | None = None,
                         minutes: int | None = None) -> None:
        raid = document["raid"]
        until = time.time() + (minutes or raid["duration_minutes"]) * 60
        await self.db.set_guild_field(guild_id, "raid_until", until)
        await self.db.add_audit(guild_id, "raid_start", actor_id=actor_id, actor_name=actor_name, detail={"why": why})
        who = f" <@{actor_id}> turned it on." if actor_id else ""
        await self._log(guild_id, document, ["raid", "general"], notices.staff_log(
            "Raid mode on", f"{why}. Rules are tightened until <t:{int(until)}:t>.{who}", notices.RED), alert_role=raid["alert_role"])
        await self._emit(guild_id, "raid.started", {"until": until})

    async def stop_raid(self, guild_id: str, document: dict, *, actor_id: str | None = None, actor_name: str | None = None) -> None:
        await self.db.set_guild_field(guild_id, "raid_until", 0)
        self.raid.forget(guild_id)
        await self.db.add_audit(guild_id, "raid_stop", actor_id=actor_id, actor_name=actor_name)
        who = f" <@{actor_id}> turned it off." if actor_id else ""
        await self._log(guild_id, document, ["raid", "general"], notices.staff_log("Raid mode off", f"Normal rules apply again.{who}", notices.GREEN), alert_for=[])
        await self._emit(guild_id, "raid.ended", {})

    # --- links ------------------------------------------------------------------------------

    async def new_link(self, guild_id: str, user_id: str, document: dict, *, bypass: list | None = None,
                       bypass_by: str | None = None, hours: int | None = None) -> tuple[str, int]:
        """Create a personal link, replacing any link the member already had.

        Only a hash of a link is kept, so a bypass link can't be shown again. If a member with a
        live one presses Verify, the new link inherits what it skips and when it ends.
        """
        now = time.time()
        minutes = hours * 60 if hours else LINK_MINUTES
        if not hours and document["core"]["auto_kick"]["enabled"]:
            minutes = document["core"]["auto_kick"]["minutes"]
        expires_at = now + minutes * 60
        skipped = json.dumps(bypass or [])
        kept = await self._live_bypass(guild_id, user_id) if bypass is None else None
        if kept is not None:
            skipped, bypass_by, expires_at = kept["bypass"], kept["bypass_by"], kept["expires_at"]
            minutes = max(1, int((expires_at - now) / 60))
        token = new_token()
        async with self._lock(guild_id, user_id):  # two presses at once would otherwise leave two live links
            await self.db.run("DELETE FROM sessions WHERE guild_id = ? AND user_id = ? AND state != 'done'", (guild_id, user_id))
            await self.db.run(
                "INSERT INTO sessions (token_hash, guild_id, user_id, bypass, bypass_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (token_hash(token), guild_id, user_id, skipped, bypass_by, now, expires_at))
        return f"{self.public_url}/v/{token}", minutes

    async def _live_bypass(self, guild_id: str, user_id: str) -> dict | None:
        return await self.db.one("SELECT bypass, bypass_by, expires_at FROM sessions WHERE guild_id = ? AND user_id = ? AND bypass != '[]' "
                                 "AND state IN ('open', 'signed_in', 'checking') AND expires_at > ?", (guild_id, user_id, time.time()))

    async def session(self, token: str) -> dict | None:
        row = await self.db.one("SELECT * FROM sessions WHERE token_hash = ?", (token_hash(token),))
        if row is None:
            return None
        row["bypass"] = json.loads(row["bypass"])
        row["account"] = json.loads(row["account"]) if row["account"] else None
        row["fixes"] = json.loads(row["fixes"]) if row.get("fixes") else []
        return row

    # --- the three ways to verify -----------------------------------------------------------

    async def press_verify(self, member: MemberInfo) -> Result | str:
        """The Verify button. Returns a link to show, or a finished result."""
        guild_id, user_id = member.guild_id, member.user_id
        if not await self.is_set_up(guild_id):
            return Result("problem", "Not set up yet", "This server hasn't finished setting up AltWarden.", reason="not_set_up")
        document = await self.get_settings(guild_id)
        await self.db.touch_member(guild_id, user_id, username=member.username, avatar=member.avatar)
        core = document["core"]
        verified_role = core["verified_role"]
        if verified_role in member.role_ids:
            return Result("already", "You're already verified", "You already have access to this server.")
        record = await self.db.member(guild_id, user_id)
        approved = record["status"] == "approved"
        if approved or (record["status"] == "verified" and record["method"] == IMPORTED_WITHOUT_ROLE):
            # Staff approved an appeal and the role couldn't be given at the time, or an import of another role marked this member verified.
            # Anyone else who is verified and lacks the role had it taken away, and taking a role off someone is how staff ask for a recheck, so they verify again.
            problem = await self._grant(guild_id, document, user_id, "Appeal approved by staff" if approved else "Already verified in this server")
            if problem is None:
                await self.db.mark_verified(guild_id, user_id, "staff" if approved else "imported")
                return Result("already", "You're verified", "Staff approved your appeal." if approved else "You already have access to this server.")
            told = await self._log(guild_id, document, ["general"], notices.staff_log(
                "Couldn't give the verified role", f"<@{user_id}> pressed Verify, but: {problem}", notices.RED))
            return Result("problem", "Almost there", _role_problem_text("Staff approved your appeal" if approved else "You're verified", problem, told), reason="role_problem", retry=True)
        mode = core["mode"]
        if mode == WEB or await self._live_bypass(guild_id, user_id):
            url, _ = await self.new_link(guild_id, user_id, document)
            return url
        if mode == INSTANT:
            rules = await self.effective(guild_id, document)
            record = await self._prepared_member(guild_id, user_id, rules)
            past = _past_deny_limit(engine.run_checks(engine.Attempt(rules, INSTANT, engine.Account(user_id, member.username, member.avatar), record), self.regions), record)
            if past is not None:  # rejoining wouldn't bring attempts back
                return _failed_result(rules, past, DENY, retry_on=past.retry_at)
            return Result("problem", "Rejoin to verify", "This server checks members when they join. Leave and rejoin to try again.")
        return await self.run_quick(member, mode)

    async def run_quick(self, member: MemberInfo, mode: str) -> Result:
        """Button and instant modes: only what Discord itself can tell us."""
        guild_id = member.guild_id
        lock = self._lock(guild_id, member.user_id)
        if lock.locked():  # the other press is being checked now, and its result will reach them
            return Result("cooldown", "Please wait", FAILURE_TEXT["cooldown"], reason="cooldown", help_slug=HELP_SLUG["cooldown"], retry=True)
        async with lock:
            document = await self.get_settings(guild_id)
            rules = await self.effective(guild_id, document)
            record = await self._prepared_member(guild_id, member.user_id, rules)
            account = engine.Account(member.user_id, member.username, member.avatar)
            decision = engine.run_checks(engine.Attempt(rules, mode, account, record), self.regions)
            past = _past_deny_limit(decision, record)
            if past is not None:
                return await self._quiet_failure(guild_id, member.user_id, rules, past)
            return await self._conclude(guild_id, rules, account, decision, mode=mode, session=None, started=None)

    async def _quiet_failure(self, guild_id: str, user_id: str, rules: dict, past: engine.Finding) -> Result:
        """Answer a try past a used-up limit. Its time is all it leaves behind, which is what lets a member appeal again."""
        await self.db.update_member(guild_id, user_id, last_fail_at=time.time())
        result = _failed_result(rules, past, DENY, retry_on=past.retry_at)
        result.quiet = True
        return result

    async def _prepared_member(self, guild_id: str, user_id: str, rules: dict) -> dict:
        """Load a member, giving back their attempts if the server's reset time has passed since the last tick."""
        await self.db.touch_member(guild_id, user_id)
        record = await self.db.member(guild_id, user_id)
        reset = rules["checks"]["max_attempts"]["reset_minutes"]
        if reset and record["limit_reached_at"] and time.time() >= record["limit_reached_at"] + reset * 60:
            await self._give_attempts_back(guild_id, rules, user_id)
            record = await self.db.member(guild_id, user_id)
        return record

    async def _give_attempts_back(self, guild_id: str, rules: dict, user_id: str) -> None:
        role = rules["checks"]["max_attempts"]["role"]
        if role:
            problem = await self.port.remove_role(guild_id, user_id, role, "Verification attempts came back")
            if problem == DISCORD_BUSY:  # the stamp stays, so the next minute's timer tries again and the role can't be left on for good
                return
            await self._note_role_problem(guild_id, rules, user_id, f"take <@&{role}> away", problem)
        await self.db.update_member(guild_id, user_id, fails=0, limit_reached_at=None)

    async def _note_role_problem(self, guild_id: str, rules: dict, user_id: str | None, what: str, problem: str | None) -> None:
        """Tell staff about a role change that didn't happen, when the member's main outcome went ahead without it. With no ID, the member has asked not to be named."""
        if problem and problem != MEMBER_GONE:
            who = f"<@{user_id}>" if user_id else "a member who deleted their records"
            await self._log(guild_id, rules, ["general"], notices.staff_log("Couldn't change a role", f"Couldn't {what} for {who}: {problem}", notices.RED))

    async def mark_opened(self, token: str) -> None:
        """The first time the page is viewed, which is when a member's time to verify starts."""
        await self.db.run("UPDATE sessions SET opened_at = ? WHERE token_hash = ? AND opened_at IS NULL", (time.time(), token_hash(token)))

    async def attach_account(self, token: str, account: dict, *, browser: str | None = None) -> str | None:
        """Save the sign-in result on the session, tied to the browser that signed in. Returns an error key, or None if it's fine."""
        row = await self.session(token)
        if row is None or row["expires_at"] <= time.time() or row["state"] in ("done", "closed"):
            return "link_expired"
        if account["id"] != row["user_id"]:
            return "wrong_account"
        # A check already running keeps its session, or the member could finish twice.
        now = time.time()
        await self.db.run("UPDATE sessions SET account = ?, browser_hash = ?, state = 'signed_in', finished_at = NULL, opened_at = COALESCE(opened_at, ?), signed_in_at = ? "
                          "WHERE token_hash = ? AND state IN ('open', 'signed_in')", (json.dumps(account), browser, now, now, token_hash(token)))
        if row["signed_in_at"] is None:
            await self.db.add_attempt(row["guild_id"], row["user_id"], "started", mode=WEB)
        await self.db.touch_member(row["guild_id"], row["user_id"], username=account.get("username"), avatar=account.get("avatar"))
        return None

    async def issue_challenge(self, token: str) -> dict | None:
        row = await self.session(token)
        if row is None or row["state"] != "signed_in" or row["expires_at"] <= time.time():
            return None
        nonce, salt = new_token(16), new_token(12)
        bits = POW_BITS_RAID if await self.raid_active(row["guild_id"]) else POW_BITS
        await self.db.run("UPDATE sessions SET nonce = ?, pow_salt = ?, pow_bits = ? WHERE token_hash = ?",
                          (nonce, salt, bits, token_hash(token)))
        return {"nonce": nonce, "salt": salt, "bits": bits}

    async def claim_submission(self, token: str, nonce: str) -> dict | None:
        """Take a session for one submission. A second submission with the same nonce finds nothing."""
        changed = await self.db.run(
            "UPDATE sessions SET nonce = NULL, state = 'checking' WHERE token_hash = ? AND state = 'signed_in' AND nonce = ? AND expires_at > ?",
            (token_hash(token), nonce, time.time()))
        return await self.session(token) if changed else None

    async def release(self, token: str) -> None:
        """Hand a session back after a failure, so one crash can't strand a member's link."""
        await self.db.run("UPDATE sessions SET state = 'signed_in' WHERE token_hash = ? AND state = 'checking'", (token_hash(token),))

    async def submit_web(self, token: str, row: dict, report: dict, *, ip: str, headers: dict, device_id: str | None,
                         cookie_refused: bool = False) -> Result:
        """Web mode: account, network and browser together. `cookie_refused` means the browser passed the first cookie check and then dropped the device cookie."""
        async with self._lock(row["guild_id"], row["user_id"]):
            # This waited its turn. A deletion, a reset or a staff verify may have gone through meanwhile, and what it would write would undo them.
            current = await self.session(token)
            if current is None or current["state"] != "checking":
                return Result("problem", "This link has expired", "Links are personal and stop working after a while, or when a newer link replaces them.",
                              reason="link_expired", help_slug="link-expired")
            return await self._submit_web(token, row, report, ip=ip, headers=headers, device_id=device_id, cookie_refused=cookie_refused)

    async def _submit_web(self, token: str, row: dict, report: dict, *, ip: str, headers: dict, device_id: str | None, cookie_refused: bool) -> Result:
        guild_id, user_id = row["guild_id"], row["user_id"]
        document = await self.get_settings(guild_id)
        if document is None or not await self.is_set_up(guild_id):
            await self.release(token)
            return Result("problem", "This server isn't ready", "It hasn't finished setting up AltWarden. Let its staff know.",
                          reason="not_set_up", help_slug="not-set-up")
        if await self.port.guild_loading(guild_id):
            await self.release(token)
            return Result("problem", "Discord is still loading this server", "Try again in a few minutes.",
                          reason="server_loading", help_slug="server-loading", retry=True)
        if await self.port.guild(guild_id) is None:
            await self.release(token)
            return Result("problem", "AltWarden isn't in this server", "Let the server's staff know.", reason="app_removed", help_slug="app-removed")
        member = await self.port.member(guild_id, user_id)
        if member is None:
            await self.release(token)
            return Result("problem", "You're not in the server", "Rejoin the server, then verify again.", reason="left_server", help_slug="left-server")
        if document["core"]["verified_role"] in member.role_ids:
            # Staff may have verified them after this link went out. An old link mustn't undo that.
            await self.db.run("UPDATE sessions SET state = 'done', account = NULL, finished_at = ? WHERE token_hash = ?", (time.time(), token_hash(token)))
            return Result("already", "You're already verified", "You already have access to this server.")
        rules = await self.effective(guild_id, document)
        if not self.net.ready and not rules["core"]["fail_open"]:
            await self.db.run("UPDATE sessions SET state = 'signed_in' WHERE token_hash = ?", (token_hash(token),))
            return Result("problem", "Try again in a moment", "The connection check isn't available right now.",
                          reason="connection_check", help_slug="connection-check", retry=True)
        record = await self._prepared_member(guild_id, user_id, rules)
        stored = row["account"]
        if rules["checks"]["disposable_email"]["enabled"] and "disposable_email" not in row["bypass"] and "email_verified" not in stored:
            # The rule came on after this sign-in, which didn't ask Discord for an email.
            await self.db.run("UPDATE sessions SET state = 'open', account = NULL WHERE token_hash = ?", (token_hash(token),))
            return Result("problem", "Please sign in again", "This server's rules changed, so Discord needs to confirm your account again.", reason="signin_again", retry=True)
        account = engine.Account(user_id, stored.get("username", ""), stored.get("avatar"), stored.get("mfa"),
                                 stored.get("email_verified"), stored.get("email_disposable"))
        bypass = frozenset(row["bypass"])
        # What the record alone can answer. A cooldown or a used-up limit costs no lookup, stores no hashes and tells nobody again.
        early = engine.run_checks(engine.Attempt(rules, WEB, account, record, bypass=bypass), self.regions)
        past = _past_deny_limit(early, record)
        if past is not None:
            result = await self._quiet_failure(guild_id, user_id, rules, past)
        elif early.cooldown_left > 0:
            result = await self._conclude(guild_id, rules, account, early, mode=WEB, session=row, started=None)
        if past is not None or early.cooldown_left > 0:
            await self._finish_session(token, "signed_in", result)
            return result
        verdict = signals.evaluate(report, headers)
        if cookie_refused:
            verdict.automated = True
            verdict.note("automated", "browser refused the cookie")
        net = self.net.lookup(ip)
        if not net.known and not net.reserved and not rules["core"]["fail_open"]:
            # Some lists loaded and this address's family didn't, which is the same missing answer as no lists at all.
            await self.db.run("UPDATE sessions SET state = 'signed_in' WHERE token_hash = ?", (token_hash(token),))
            return Result("problem", "Try again in a moment", "The connection check isn't available right now.",
                          reason="connection_check", help_slug="connection-check", retry=True)
        notes = {}
        # Past a limit that kicks or bans, the attempt is stopped whatever the answer would be.
        stopped = any(finding.check_id == "max_attempts" and finding.enforced for finding in early.findings)
        lookup = None if stopped else await self._outside_lookup(guild_id, user_id, ip, net, rules, bypass)
        if lookup:
            notes["lookup"] = lookup
        if net.reserved or not net.known:
            notes["network"] = "address not public" if net.reserved else "network data unavailable"
        zone = report.get("tz", {}).get("name") if isinstance(report.get("tz"), dict) else None
        expected = self.zone_countries.get(zone) if isinstance(zone, str) else None
        mismatch = bool(expected and net.country and net.country not in expected and not net.anonymized)
        suspect, hits = signals.suspect_score(verdict, net, account_days=account.age_days, has_avatar=bool(account.avatar),
                                              disposable=account.email_disposable is True, timezone_mismatch=mismatch)
        connection = report.get("conn") if isinstance(report.get("conn"), dict) else {}
        digests = self._digests(guild_id, ip, device_id, verdict)
        profile = self._profile(guild_id, verdict)
        privacy = rules["privacy"]
        alt = rules["checks"]["alt_account"]
        # A carrier shares one IPv4 address among many customers. An IPv6 /64 belongs to one.
        on_ipv6 = ":" in ip and not ip.lower().startswith("::ffff:")
        weak_ip = net.anonymized or net.reserved or ((net.shared or net.mobile) and not on_ipv6)
        # A member who bypasses the check still queues: someone else's check has to see this one's result.
        async with self._evidence_held(guild_id, altmatch.lock_keys(digests, alt, weak_fingerprint=verdict.weak_fingerprint, weak_ip=weak_ip)):
            links = []
            if alt["enabled"] and "alt_account" not in bypass:
                links = await self._alt_links(guild_id, user_id, digests, profile, alt, weak_fingerprint=verdict.weak_fingerprint, weak_ip=weak_ip)
            attempt = engine.Attempt(rules, WEB, account, record, net, verdict, links, suspect, hits,
                                     cellular=connection.get("type") == "cellular", bypass=bypass)
            decision = engine.run_checks(attempt, self.regions)
            past = _past_deny_limit(decision, record)
            if past is not None:
                result = await self._quiet_failure(guild_id, user_id, rules, past)
            else:
                await self._store_digests(guild_id, user_id, {**digests, **profile}, privacy)
                result = await self._conclude(guild_id, rules, account, decision, mode=WEB, session=row, started=row["opened_at"], notes=notes, browser=verdict)
        if past is not None:
            await self._finish_session(token, "signed_in", result)
            return result
        # "closed" means the link is spent without a pass, so the page can't claim the member got in.
        final = "done" if result.status == "verified" else "closed" if result.action in (KICK, BAN) else "signed_in"
        if final == "signed_in" and any(finding.check_id in ACCOUNT_CHECKS for finding in decision.enforced):
            final = "open"
        await self._finish_session(token, final, result)
        return result

    async def _alt_links(self, guild_id: str, user_id: str, digests: dict, profile: dict, alt: dict, *, weak_fingerprint: bool, weak_ip: bool) -> list:
        """Earlier accounts sharing evidence with this one, with roles and bans brought up to date.

        A ban or an unban can have happened while the bot wasn't looking, so Discord is asked about each link that would
        count if the other account is banned. If Discord can't say, what's on record stands.
        """
        links = await altmatch.find_links(self.db, guild_id, user_id, digests, methods=alt["methods"], weak_fingerprint=weak_fingerprint, weak_ip=weak_ip)
        links = links[:MAX_LINKS]
        below_floor = 0
        for link in links:
            if altmatch.strong_enough(link, alt["min_confidence"]):
                # Discord is asked one call at a time, under the locks on this evidence, so links that only a ban would make count get a few calls.
                if altmatch.RANK[link.confidence] < altmatch.RANK.get(alt["min_confidence"], altmatch.RANK["possible"]):
                    below_floor += 1
                on_discord = await self._discord_ban(guild_id, link.other_id) if below_floor <= BELOW_FLOOR_BAN_LOOKUPS or altmatch.RANK[link.confidence] >= altmatch.RANK.get(alt["min_confidence"], altmatch.RANK["possible"]) else None
                if on_discord and not link.banned:
                    link.banned = True
                    await self.on_ban(guild_id, link.other_id)  # the same as if the ban event had arrived
                elif on_discord is False and link.banned:
                    link.banned = False
                    await self.on_unban(guild_id, link.other_id)
            await altmatch.assign_roles(self.db, guild_id, user_id, link)
        links.sort(key=lambda link: (link.banned, link.verified, link.score), reverse=True)  # a ban found just now outranks a stronger match
        await altmatch.compare_profiles(self.db, guild_id, links, profile)
        return links

    async def _finish_session(self, token: str, state: str, result: Result) -> None:
        # What the sign-in read stays only while a retry can use it. finished_at marks a result the member has seen, which is what
        # makes a reload wait to be asked. A server problem hasn't used anything up, so that can run again by itself.
        # The last attempt's fixes stay too, so a page that reloads can still show them. Only a pass or a new failure replaces them.
        await self.db.run("UPDATE sessions SET state = ?, finished_at = CASE WHEN ? THEN ? ELSE finished_at END, account = CASE WHEN ? = 'signed_in' THEN account END, "
                          "fixes = CASE WHEN ? THEN ? ELSE fixes END WHERE token_hash = ?",
                          (state, result.status in ("failed", "verified", "cooldown"), time.time(), state,
                           result.status in ("failed", "verified"), json.dumps(result.fixes) if result.fixes else None, token_hash(token)))

    async def _outside_lookup(self, guild_id: str, user_id: str, ip: str, net: NetInfo, rules: dict, bypass: frozenset) -> str | None:
        """Ask proxycheck.io about a member's connection if the answer could matter, and write it onto `net`.

        Each lookup spends the server's daily quota, so a repeat from one network within the hour is answered from
        memory, and one member or one network can't spend more than a share of it. Anyone can use the quota up, so a
        failed lookup never stops a member, whatever `fail_open` says, or spending it would shut verification down. Staff
        are told instead. The one exception is a member past their own budget with no attempt limit to end it: twenty
        networks in a day isn't someone at home, and only that member pays, so the connection counts as a VPN. Returns a
        note for the attempt when no answer was had.
        """
        checks = rules["checks"]
        if not rules["core"]["external_vpn_lookup"] or self.proxycheck is None or "vpn" in bypass or net.anonymized or net.reserved:
            return None
        if not checks["vpn"]["enabled"] and not checks["threat"]["enabled"]:
            return None
        now = time.time()
        place = (guild_id, self.keys.digest(int(guild_id), "lookup", network_of(ip)))
        cached = self._lookup_cache.get(place)
        if cached is not None and cached[0] > now:
            self._apply_detections(net, cached[1])
            return None
        if _spent_today(self._lookup_counts, (guild_id, user_id), now)[1] >= LOOKUP_DAILY_LIMIT:
            if checks["max_attempts"]["enabled"] and "max_attempts" not in bypass:
                return "skipped"
            net.vpn = True
            return "over_limit"
        # Asked before anything is charged, so a member on a spent network doesn't use up their own budget getting nothing.
        wide = (guild_id, self.keys.digest(int(guild_id), "lookup-network", wide_network_of(ip)))
        if _spent_today(self._lookup_networks, wide, now)[1] >= LOOKUP_NETWORK_LIMIT:
            return "skipped"
        _charge(self._lookup_networks, wide, now)
        answer = await self.proxycheck(ip, await self.lookup_key(guild_id))
        if answer is None:
            await self._lookup_failed(guild_id, rules, now)
            return "unavailable"
        # A member's count is for answers. A service that's down or out of quota says nothing about how many networks they use.
        self._lookup_allowed(guild_id, user_id, now)
        self._lookup_failures.pop(guild_id, None)
        self._remember_lookup(place, answer)
        self._apply_detections(net, answer)
        return None

    def _apply_detections(self, net: NetInfo, answer: dict) -> None:
        net.vpn = net.vpn or bool(answer.get("vpn") or answer.get("proxy"))
        net.tor = net.tor or bool(answer.get("tor"))
        net.hosting = net.hosting or bool(answer.get("hosting"))

    def _remember_lookup(self, place: tuple, answer: dict) -> None:
        self._lookup_cache[place] = (time.time() + LOOKUP_CACHE_SECONDS, answer)
        self._lookup_cache.move_to_end(place)
        while len(self._lookup_cache) > LOOKUP_CACHE_SIZE:
            self._lookup_cache.popitem(last=False)

    def _lookup_allowed(self, guild_id: str, user_id: str, now: float) -> bool:
        """Count one lookup against a member's day, if any are left."""
        key = (guild_id, user_id)
        if _spent_today(self._lookup_counts, key, now)[1] >= LOOKUP_DAILY_LIMIT:
            return False
        _charge(self._lookup_counts, key, now)
        return True

    async def _lookup_failed(self, guild_id: str, rules: dict, now: float) -> None:
        message = last_refusal.get() or "proxycheck.io couldn't be reached."
        self._lookup_failures[guild_id] = {"at": now, "message": message}
        if now - self._lookup_warned.get(guild_id, 0) >= LOOKUP_WARNING_SECONDS:
            self._lookup_warned[guild_id] = now
            await self._log(guild_id, rules, ["general"], notices.staff_log(
                "The outside VPN lookup isn't answering", f"Members are getting through without it until it does. proxycheck.io said: {notices.escape_text(message)}", notices.AMBER))

    async def public_bot(self, application_info) -> bool | None:
        """Whether anyone can add this bot, as Discord says now, asked at most every five minutes. None if it has never answered.

        `application_info` is the call set at startup that returns Discord's application object, or None before there is one.
        """
        now = time.monotonic()
        until, known = self._public_bot
        if application_info is None or now < until:
            return known
        try:
            known = bool((await application_info()).bot_public)
        except Exception as exc:
            log.warning("Couldn't read the application's settings: %s", type(exc).__name__)
            return known  # asked again at the next look, and the last answer stands until then
        self._public_bot = (now + PUBLIC_BOT_SECONDS, known)
        return known

    def lookup_refused(self, guild_id: str) -> dict | None:
        """The last failed outside lookup, `{at, message}`, until the next one that works. For the Health page."""
        return self._lookup_failures.get(guild_id)

    def _digests(self, guild_id: str, ip: str, device_id: str | None, verdict) -> dict[str, str]:
        """Replace every raw identifier with a keyed hash. Only the hashes go past this line."""
        gid = int(guild_id)
        digests = {"ip": self.keys.digest(gid, "ip", network_of(ip))}
        if device_id:
            digests["cookie"] = self.keys.digest(gid, "cookie", device_id)
        if verdict.fingerprint:
            digests["fingerprint"] = self.keys.digest(gid, "fingerprint", verdict.fingerprint)
        if verdict.device:
            digests["device"] = self.keys.digest(gid, "device", verdict.device)
        return digests

    def _profile(self, guild_id: str, verdict) -> dict[str, str]:
        """Keyed hashes of the system and browser family. They describe a link for staff and add no score."""
        gid = int(guild_id)
        return {kind: self.keys.digest(gid, kind, value) for kind, value in (("os", verdict.os), ("browser", verdict.browser)) if value}

    async def _store_digests(self, guild_id: str, user_id: str, digests: dict, privacy: dict) -> None:
        now = time.time()
        for kind, digest in digests.items():
            days = privacy["ip_days"] if kind == "ip" else privacy["identifier_days"]
            await self.db.store_identifier(guild_id, user_id, kind, digest, now + days * 86400)

    # --- outcomes ---------------------------------------------------------------------------

    async def _conclude(self, guild_id: str, rules: dict, account: engine.Account, decision: engine.Decision, *, mode: str,
                        session: dict | None, started: float | None, notes: dict | None = None,
                        browser: signals.BrowserVerdict | None = None) -> Result:
        if decision.cooldown_left > 0:
            return Result("cooldown", "Please wait", FAILURE_TEXT["cooldown"], reason="cooldown",
                          help_slug=HELP_SLUG["cooldown"], seconds_left=decision.cooldown_left, retry=True)
        user_id = account.id
        seconds = time.time() - started if started else None
        bypassed = list(session["bypass"]) if session else []
        guild = await self.port.guild(guild_id)
        guild_name = guild.name if guild else "this server"
        avatar_url = _avatar_url(user_id, account.avatar)

        if decision.passed:
            problem = await self._grant(guild_id, rules, user_id, "Passed verification")
            if problem == MEMBER_GONE:
                return Result("problem", "You're not in the server", "Rejoin the server, then verify again.", reason="left_server", help_slug="left-server")
            if problem:
                told = await self._log(guild_id, rules, ["general"], notices.staff_log(
                    "Couldn't give the verified role", f"<@{user_id}> passed, but: {problem}", notices.RED))
                # They passed, so no timer should remove them while this waits. The record is what opens help and appeals.
                await self.db.update_member(guild_id, user_id, **NO_KICK_TIMES)
                await self.db.add_attempt(guild_id, user_id, "role_problem", check_id="role_problem", mode=mode, seconds=seconds, bypassed=bool(bypassed),
                                          detail=_attempt_detail(decision, bypassed, notes))
                too_low = problem == ROLE_TOO_LOW
                desk = rules["core"]["help_desk"]
                return Result("problem", "Almost there", _role_problem_text("You passed", problem, told),
                              reason="role_too_low" if too_low else "role_problem",
                              help_slug="role-too-low" if too_low else "role-problem", retry=True,
                              appeal=rules["appeals"]["enabled"], staff_help=desk["enabled"] and desk["redirect"])
            # Straight after the role, or a crash below leaves someone holding it who no alt check can see.
            await self.db.mark_verified(guild_id, user_id, mode)
            await self.db.add_attempt(guild_id, user_id, "passed", mode=mode, seconds=seconds, bypassed=bool(bypassed),
                                      detail=_attempt_detail(decision, bypassed, notes))
            main_note = await self._act_on_link(guild_id, rules, user_id, decision, guild_name)
            await self._close_help_thread(guild_id, rules, user_id)
            if mode != INSTANT or rules["core"]["auto_dm"]:
                await self.port.dm(user_id, notices.verified_notice(guild_name))
            modules = ["success"] + [finding.check_id for finding in decision.findings]
            await self._log(guild_id, rules, modules, notices.attempt_log(
                user_id, account.username, avatar_url, decision, took="Verified" + main_note, bypassed=bypassed, mode=mode,
                role_given=rules["core"]["verified_role"], guild_name=guild_name))
            await self._emit(guild_id, "member.verified", {"user_id": user_id, "mode": mode,
                                                           "watched": [finding.check_id for finding in decision.findings]})
            return Result("verified", "You're verified", f"You now have access to {guild_name}.")

        now = time.time()
        # Failing today's rules ends any earlier pass, or a rejoin would hand the role straight back.
        await self.db.run("UPDATE members SET fails = fails + 1, last_fail_at = ?, status = 'pending', verified_at = NULL WHERE guild_id = ? AND user_id = ?",
                          (now, guild_id, user_id))
        await self.db.run("DELETE FROM sessions WHERE guild_id = ? AND user_id = ? AND state = 'done'", (guild_id, user_id))
        record = await self.db.member(guild_id, user_id)
        fails = record["fails"] if record else 1
        # The same test the engine runs on the next attempt, so bypassing the limit also keeps a member from reaching it.
        limit = rules["checks"]["max_attempts"]
        limited = limit["enabled"] and mode in BY_ID["max_attempts"].modes and "max_attempts" not in bypassed
        reached_at = (record or {}).get("limit_reached_at")
        reached_now = limited and fails >= limit["attempts"] and not reached_at
        if reached_now:
            reached_at = now
            limit_action = limit["action"]
            await self.db.update_member(guild_id, user_id, limit_reached_at=now)
            if limit["role"] and limit_action in (WATCH, DENY):
                problem = await self.port.add_role(guild_id, user_id, limit["role"], "Reached the attempt limit")
                await self._note_role_problem(guild_id, rules, user_id, f"give <@&{limit['role']}>", problem)
            back = {"attempts_back_at": now + limit["reset_minutes"] * 60} if limit["reset_minutes"] else {}
            found = next((finding for finding in decision.findings if finding.check_id == "max_attempts"), None)
            if found is not None:  # a count already past a limit that never stamped it, so its finding had no date to give
                found.detail.update(back)
            else:
                # This speaks for the attempt, with the stronger of its action and the one the failed check had. A limit on Watch stops nobody.
                stronger = max(limit_action, decision.action, key=SEVERITY.get)
                decision.findings.insert(0, engine.Finding("max_attempts", WATCH if limit["action"] == WATCH else stronger, "max_attempts", {"attempts": limit["attempts"], **back}))
        primary = decision.primary
        action = decision.action
        stops = limited and limit["action"] != WATCH
        attempts_left = limit["attempts"] - fails if stops and not reached_at else None
        # An account that gets old enough still can't come back once its attempts are gone for good.
        retry_on = None if stops and reached_at and not limit["reset_minutes"] else primary.retry_at
        attempt_id = await self.db.add_attempt(guild_id, user_id, "failed", check_id=primary.check_id, action=action, mode=mode, seconds=seconds,
                                               bypassed=bool(bypassed), detail=_attempt_detail(decision, bypassed, notes))

        appeals_on = rules["appeals"]["enabled"]
        appeal_url = f"{self.public_url}/appeal/{guild_id}" if appeals_on else None
        text = primary.message
        # What to do about every check that stopped them, with this device's steps first. A ban leaves nothing to fix, and
        # with reasons hidden the steps would name the check.
        found_fixes = (fixes.for_findings(decision.enforced, system=browser.os if browser else None, browser=browser.browser if browser else None)
                       if rules["core"]["show_reason"] and action != BAN else [])
        can_retry = action == DENY and primary.check_id not in NO_RETRY_CHECKS
        # This has to go first, because Discord refuses a DM once the two share no server. So it can claim a removal that then fails.
        delivered = await self.port.dm(user_id, notices.failed_notice(guild_name, primary.reason, text, action, self.public_url, appeal_url,
                                                                      rules["core"]["show_reason"], retry_on, attempts_left=attempts_left, instant=mode == INSTANT,
                                                                      fixes=found_fixes, retry=can_retry, channel_id=rules["core"]["channel"]))
        took = {DENY: "Denied", KICK: "Kicked", BAN: "Banned"}[action]
        if delivered is not True:
            took += ", couldn't tell them by DM"
        reason_text = f"AltWarden: {notices.check_name(primary.check_id)}"
        done = action  # what really happened, because the page mustn't say someone was removed when they're still here
        if action == KICK:
            removed = await self.port.kick(guild_id, user_id, reason_text)
        elif action == BAN:
            removed = await self.port.ban(guild_id, user_id, reason_text)
            if removed:
                await self.db.record_ban(guild_id, user_id, by_altwarden=True, keep_days=rules["privacy"]["banned_days"])
        else:
            removed = True
        if not removed:
            took += " (failed, usually a missing permission)"
            done = DENY
            await self.db.run("UPDATE attempts SET action = ? WHERE id = ?", (DENY, attempt_id))
            if delivered is True:
                await self.port.dm(user_id, notices.not_removed_notice(guild_name))
        took += await self._act_on_link(guild_id, rules, user_id, decision, guild_name)
        modules = [finding.check_id for finding in decision.findings]
        await self._log(guild_id, rules, modules, notices.attempt_log(user_id, account.username, avatar_url, decision, took=took,
                                                                      bypassed=bypassed, mode=mode, guild_name=guild_name))
        await self._emit(guild_id, "member.failed", {"user_id": user_id, "check": primary.check_id, "action": done,
                                                     "checks": modules})
        return _failed_result(rules, primary, done, retry_on=retry_on, attempts_left=attempts_left, fixes=found_fixes)

    async def _grant(self, guild_id: str, rules: dict, user_id: str, reason: str) -> str | None:
        core = rules["core"]
        problem = await self.port.add_role(guild_id, user_id, core["verified_role"], reason)
        if problem:
            return problem
        # The member is in by now. A role left on them can still hide channels, so staff need to know.
        taken = [core["unverified_role"] if core["unverified_enabled"] else None, rules["checks"]["max_attempts"]["role"]]
        for role in filter(None, taken):
            await self._note_role_problem(guild_id, rules, user_id, f"take <@&{role}> away", await self.port.remove_role(guild_id, user_id, role, reason))
        return None

    async def _act_on_link(self, guild_id: str, rules: dict, user_id: str, decision: engine.Decision, guild_name: str) -> str:
        """Record a matched pair, then apply the server's action to the earlier account. Returns a note for the log."""
        link = decision.alt_link
        if link is None:
            return ""
        main, alt = (link.other_id, user_id) if link.other_is_main else (user_id, link.other_id)
        # A retry from a phone hotspot mustn't wipe out what the first try showed staff.
        await self.db.run("INSERT INTO links (guild_id, main_id, alt_id, confidence, score, methods, at) VALUES (?, ?, ?, ?, ?, ?, ?) "
                          "ON CONFLICT (guild_id, main_id, alt_id) DO UPDATE SET confidence = excluded.confidence, score = excluded.score, methods = excluded.methods, at = excluded.at "
                          "WHERE excluded.score >= links.score",
                          (guild_id, main, alt, link.confidence, link.score, json.dumps(link.methods), time.time()))
        action = decision.main_action
        if action not in (KICK, BAN) or main == user_id:
            return ""
        try:
            gone = await self.port.member(guild_id, main) is None
        except DiscordUnavailable:
            gone = False  # go on as if they're here: a kick that can't land says so below
        if gone and action == KICK:
            # Nothing happened to them, so there's nothing on record to appeal. An alt retrying would otherwise add a failure each time.
            await self.db.update_member(guild_id, main, status="pending", verified_at=None)
            return ", earlier account had already left"
        delivered = None
        if not gone:  # with no shared server left, Discord wouldn't deliver it
            appeal_url = f"{self.public_url}/appeal/{guild_id}" if rules["appeals"]["enabled"] else None
            delivered = await self.port.dm(main, notices.failed_notice(guild_name, "alt_account", FAILURE_TEXT["alt_account"], action, self.public_url,
                                                                       appeal_url, rules["core"]["show_reason"]))
        reason = f"AltWarden: main account of <{user_id}>"
        if action == KICK:
            done = await self.port.kick(guild_id, main, reason)
        else:
            done = await self.port.ban(guild_id, main, reason)
            if done:
                await self.db.record_ban(guild_id, main, by_altwarden=True, keep_days=rules["privacy"]["banned_days"])
        if not done:
            if delivered is True:
                await self.port.dm(main, notices.not_removed_notice(guild_name))
            return ", couldn't act on the earlier account"
        # The attempt is what lets this account appeal, and the status keeps a rejoin from restoring the role.
        await self.db.add_attempt(guild_id, main, "failed", check_id="alt_account", action=action, detail={"findings": [
            {"check": "alt_account", "action": action, "detail": {"account": alt, "confidence": link.confidence, "earlier_account": True}}]})
        await self.db.update_member(guild_id, main, status="pending", verified_at=None)
        return f", earlier account {'kicked' if action == KICK else 'banned'}"

    async def _end_thread(self, guild_id: str, rules: dict, user_id: str, thread_id: str, why: str) -> None:
        if not await self.port.close_thread(thread_id):  # the link stays, so the member's next press finds the thread or starts a new one
            await self._log(guild_id, rules, ["help_desk"], notices.staff_log("Couldn't close a help thread", f"<#{thread_id}> should have closed: {why}.", notices.AMBER), alert_for=[])
            return
        await self.db.update_member(guild_id, user_id, help_thread_id=None)
        await self._log(guild_id, rules, ["help_desk"], notices.staff_log("Help thread closed", f"<#{thread_id}> closed: {why}."), alert_for=[])

    async def _close_help_thread(self, guild_id: str, rules: dict, user_id: str) -> None:
        record = await self.db.member(guild_id, user_id)
        if record and record["help_thread_id"] and rules["core"]["help_desk"]["auto_close"]:
            await self._end_thread(guild_id, rules, user_id, record["help_thread_id"], f"<@{user_id}> verified")

    # --- staff actions ----------------------------------------------------------------------

    async def manual_verify(self, guild_id: str, user_id: str, actor_id: str, actor_name: str = "") -> str | None:
        document = await self.get_settings(guild_id)
        if document is None:
            return NOT_SET_UP
        async with self._lock(guild_id, user_id):  # a check already running finishes first, so it can't undo this
            problem = await self._grant(guild_id, document, user_id, f"Verified by staff ({actor_name or actor_id})")
            if problem:
                return problem
            await self.db.touch_member(guild_id, user_id)
            await self.db.mark_verified(guild_id, user_id, "staff")
            # A link they still hold would otherwise run the checks again, and could kick someone staff just let in.
            await self.db.run("DELETE FROM sessions WHERE guild_id = ? AND user_id = ? AND state != 'done'", (guild_id, user_id))
        await self.db.add_attempt(guild_id, user_id, "manual", mode="staff", detail={"by": actor_id})
        await self.db.add_audit(guild_id, "manual_verify", actor_id=actor_id, actor_name=actor_name, detail={"user": user_id})
        await self._close_help_thread(guild_id, document, user_id)
        picture = _avatar_url(user_id, (await self.db.member(guild_id, user_id) or {}).get("avatar"))
        await self._log(guild_id, document, ["general"], notices.staff_log("Member verified", f"Staff member <@{actor_id}> verified <@{user_id}>.", notices.GREEN,
                                                                           **({"thumbnail": {"url": picture}} if picture else {}), **({"footer": {"text": actor_name}} if actor_name else {})))
        await self._emit(guild_id, "member.verified", {"user_id": user_id, "mode": "staff"})
        return None

    async def staff_refusal(self, guild_id: str, actor: MemberInfo, target_id: str, action: str) -> str | None:
        """Why this staff member can't do `action` to this account, or None if they can. `action` is verify, reset, bypass, trust or unban.

        The bot holds power its users may not, so this asks what Discord would ask of the person themselves. Administrators
        and the owner pass. A banned account's records are what catch its next account, so those take Ban Members.
        """
        if actor.is_owner or "administrator" in actor.permissions:
            return None
        try:
            guild = await self.port.guild(guild_id)
            target = await self.port.member(guild_id, target_id)
        except DiscordUnavailable:
            return DISCORD_BUSY
        if guild is None:
            return "AltWarden can't see this server's roles right now. Try again in a moment."
        # Discord sorts equal positions by ID, and the higher ID sits lower.
        ranks = {role["id"]: (role["position"], -int(role["id"])) for role in guild.roles}
        lowest = (0, 0)

        def top(role_ids) -> tuple:
            return max((ranks.get(role, lowest) for role in role_ids), default=lowest)
        mine = top(actor.role_ids)
        if target is not None and (target.is_owner or target_id == guild.owner_id or top(target.role_ids) >= mine):
            return "That member's highest role is at or above yours, so you can't do that to them."
        if action == "verify":
            document = await self.get_settings(guild_id)
            if document is None:
                return NOT_SET_UP
            if ranks.get(document["core"]["verified_role"], lowest) >= mine:
                return "The verified role sits at or above your highest role, so you can't give it."
        if action in ("reset", "trust", "unban") and "ban_members" not in actor.permissions and await self._is_banned(guild_id, target_id):
            return "That account is banned, and changing its records takes Ban Members."
        return None

    async def _is_banned(self, guild_id: str, user_id: str) -> bool:
        """By AltWarden's record or Discord's, for what mustn't be undone by a ban AltWarden never saw. If Discord can't say, the record decides."""
        return await self.db.is_banned(guild_id, user_id) or await self._discord_ban(guild_id, user_id) is True

    async def reset_member(self, guild_id: str, user_id: str, actor_id: str, actor_name: str = "") -> ResetResult:
        """Clear a member's records here, so they verify again.

        The first verified date stays, because it decides which of two linked accounts is the main one. A banned
        account's hashes stay, because they are what catches its next account. A connection hash among them still ends on its own date.
        """
        document = await self.get_settings(guild_id)
        if document is None:
            return ResetResult(problem=NOT_SET_UP)
        core = document["core"]
        instant = core["mode"] == INSTANT
        reason = "Verification reset by staff"
        problems = []
        async with self._lock(guild_id, user_id):  # a check already running finishes first, so it can't undo this
            member = await self.port.member(guild_id, user_id)  # first, so Discord failing here leaves everything as it was
            kept_hashes = await self._is_banned(guild_id, user_id)
            await self.db.run("DELETE FROM attempts WHERE guild_id = ? AND user_id = ?", (guild_id, user_id))
            if not kept_hashes:
                await self.db.run("DELETE FROM identifiers WHERE guild_id = ? AND user_id = ?", (guild_id, user_id))
            await self.db.run("DELETE FROM links WHERE guild_id = ? AND (main_id = ? OR alt_id = ?)", (guild_id, user_id, user_id))
            await self.db.run("DELETE FROM sessions WHERE guild_id = ? AND user_id = ?", (guild_id, user_id))
            await self.db.touch_member(guild_id, user_id)
            kick_minutes = core["auto_kick"]["minutes"] if member is not None and core["auto_kick"]["enabled"] else None
            await self.db.update_member(guild_id, user_id, status="pending", method=None, verified_at=None, fails=0, last_fail_at=None,
                                        limit_reached_at=None, **(_kick_times(document, time.time()) if kick_minutes else NO_KICK_TIMES))
            if member is not None:
                problems.append(await self.port.remove_role(guild_id, user_id, core["verified_role"], reason))
                limit_role = document["checks"]["max_attempts"]["role"]
                if limit_role:
                    problems.append(await self.port.remove_role(guild_id, user_id, limit_role, reason))
                if core["unverified_enabled"] and core["unverified_role"] and not instant:
                    problems.append(await self.port.add_role(guild_id, user_id, core["unverified_role"], reason))
        problem = next((found for found in problems if found and found != MEMBER_GONE), None)
        told = False
        if member is not None and core["auto_dm"]:
            guild = await self.port.guild(guild_id)
            url = None
            if core["mode"] == WEB:
                url, _ = await self.new_link(guild_id, user_id, document)
            delivered = await self.port.dm(user_id, notices.reset_notice(guild.name if guild else "this server", url, core["channel"], instant, kick_minutes))
            told = delivered is True
            if delivered is False and core["notify_closed_dms"]["enabled"] and core["channel"] and not instant:
                told = bool(await self.port.send(core["channel"], notices.closed_dms_notice(user_id, core["notify_closed_dms"]["seconds"], kick_minutes), guild_id=guild_id))
        await self.db.add_audit(guild_id, "reset", actor_id=actor_id, actor_name=actor_name, detail={"user": user_id, "kept_hashes": kept_hashes})
        await self._log(guild_id, document, ["general"], notices.staff_log("Verification reset", f"<@{actor_id}> reset <@{user_id}>."
                        + (" Their hashes stay, because the account is banned." if kept_hashes else "")
                        + (f" A role change failed: {problem}" if problem else "")))
        return ResetResult(told=told, problem=problem, kept_hashes=kept_hashes)

    async def create_bypass(self, guild_id: str, user_id: str, skip: list, hours: int, notify: str, actor_id: str,
                            actor_name: str = "", channel_id: str | None = None) -> tuple[str, bool]:
        """A link for one member that skips the checks staff chose. Returns the link and whether it was delivered.

        Bypass links always use the web page, so every check that wasn't skipped still runs. The log
        records that a link exists, but never the link, so a logs channel can't leak one.
        """
        document = await self.get_settings(guild_id)
        allowed = [check for check in skip if check in CHECK_IDS or check == "cooldown"]
        hours = max(1, min(MAX_BYPASS_HOURS, hours))
        url, minutes = await self.new_link(guild_id, user_id, document, bypass=allowed, bypass_by=actor_id, hours=hours)
        # A link that runs out unused mustn't leave them with no deadline, so their time starts when it ends.
        await self.db.update_member(guild_id, user_id, **(_kick_times(document, time.time() + hours * 3600) if document["core"]["auto_kick"]["enabled"] else NO_KICK_TIMES))
        guild = await self.port.guild(guild_id)
        name = guild.name if guild else "this server"
        told = False
        if notify in ("dm", "both"):
            told = await self.port.dm(user_id, notices.link_notice(name, url, minutes=minutes, kick_minutes=None, bypass=True)) is True
        verify_channel = document["core"]["channel"]
        where = verify_channel or channel_id  # a staff room is no use, because the member may not be able to read it
        if notify in ("channel", "both") and where:
            # The link never goes in a channel. Pressing Verify hands the member a link that keeps these skips.
            button = f"in <#{verify_channel}>" if verify_channel else "on the verification message"
            posted = await self.port.send(where, Notice(content=f"<@{user_id}> staff made a verification link for you. Check your DMs, "
                                                                f"or press **Verify** {button} to get it.", mention_users=[user_id]), guild_id=guild_id)
            told = told or bool(posted)
        await self.db.add_audit(guild_id, "bypass", actor_id=actor_id, actor_name=actor_name,
                                detail={"user": user_id, "skip": allowed, "hours": hours})
        await self._log(guild_id, document, ["general"], notices.staff_log(
            "Bypass link created", f"<@{actor_id}> created a link for <@{user_id}>. It expires <t:{int(time.time() + hours * 3600)}:f>.",
            notices.AMBER, fields=[{"name": "Skips", "value": ", ".join(notices.check_name(check) for check in allowed) or "Nothing", "inline": False}]))
        return url, told

    async def import_members(self, guild_id: str, user_ids: list, actor_id: str, actor_name: str = "", *, holding_role: bool = False) -> int:
        """Mark members who already hold access as verified, so a switch from another bot asks nothing of them.

        `holding_role` says they were picked by the verified role itself. Picked by another role, they don't hold it yet, and pressing Verify gives it.
        """
        now = time.time()
        method = "imported" if holding_role else IMPORTED_WITHOUT_ROLE
        count_verified = "SELECT COUNT(*) FROM members WHERE guild_id = ? AND status = 'verified'"
        before = await self.db.scalar(count_verified, (guild_id,))
        # A big server can have hundreds of thousands. Batches keep the import quick and let other writes in between.
        for start in range(0, len(user_ids), 5000):
            await self.db.run_many(
                "INSERT INTO members (guild_id, user_id, status, method, verified_at, first_verified_at, joined_at) VALUES (?, ?, 'verified', ?, ?, ?, ?) "
                "ON CONFLICT (guild_id, user_id) DO UPDATE SET status = 'verified', method = excluded.method, verified_at = excluded.verified_at, "
                "first_verified_at = COALESCE(members.first_verified_at, excluded.first_verified_at), kick_at = NULL, kick_warn_at = NULL, "
                "fails = 0, last_fail_at = NULL, limit_reached_at = NULL "
                "WHERE members.status != 'verified'", [(guild_id, user_id, method, now, now, now) for user_id in user_ids[start:start + 5000]])
            await asyncio.sleep(0)
        count = await self.db.scalar(count_verified, (guild_id,)) - before
        document = await self.get_settings(guild_id)
        await self.db.add_audit(guild_id, "import_members", actor_id=actor_id, actor_name=actor_name, detail={"count": count})
        await self._log(guild_id, document, ["general"], notices.staff_log(
            "Members imported", f"<@{actor_id}> marked {count} existing members as verified."))
        return count

    async def import_failed(self, guild_id: str) -> None:
        await self._log(guild_id, await self.get_settings(guild_id), ["general"], notices.staff_log("Import failed", "The member import didn't finish. Run it again.", notices.RED))

    # --- events from Discord ----------------------------------------------------------------

    async def on_ban(self, guild_id: str, user_id: str) -> None:
        # A link staff made must not outlive a ban, and a finished one would still say they're verified.
        await self.db.run("DELETE FROM sessions WHERE guild_id = ? AND user_id = ?", (guild_id, user_id))
        document = await self.get_settings(guild_id)
        if document is not None:
            await self.db.record_ban(guild_id, user_id, keep_days=document["privacy"]["banned_days"])
            await self.db.update_member(guild_id, user_id, status="pending", verified_at=None)

    async def on_unban(self, guild_id: str, user_id: str) -> None:
        await self.db.clear_ban(guild_id, user_id)
        record = await self.db.member(guild_id, user_id)
        if record and record["forget_on_unban"]:  # they asked for their data gone, and only the ban was keeping it
            await self.db.run("DELETE FROM identifiers WHERE guild_id = ? AND user_id = ?", (guild_id, user_id))
            await self.db.run("DELETE FROM members WHERE guild_id = ? AND user_id = ?", (guild_id, user_id))

    async def on_leave(self, guild_id: str, user_id: str) -> None:
        await self.db.run("UPDATE members SET kick_at = NULL, kick_warn_at = NULL WHERE guild_id = ? AND user_id = ?", (guild_id, user_id))
        await self.db.run("DELETE FROM sessions WHERE guild_id = ? AND user_id = ? AND state = 'done'", (guild_id, user_id))
        record = await self.db.member(guild_id, user_id)
        if record and record["help_thread_id"]:
            rules = await self.get_settings(guild_id) or settings_module.defaults()
            await self._end_thread(guild_id, rules, user_id, record["help_thread_id"], f"<@{user_id}> left the server")

    async def honeypot_hit(self, guild_id: str, user_id: str, channel_id: str, message_id: str, *,
                           role_ids: tuple, is_webhook: bool = False, is_bot: bool = False, parent_id: str | None = None) -> None:
        """A post in the trap, or in a thread under it. The message always goes, and the author is acted on once.

        A bot or a webhook is only deleted and logged. Any member can make another bot reply in the trap, so acting on
        it would let them aim the ban. A member is told by DM before the action, and may appeal it.
        """
        document = await self.get_settings(guild_id)
        pot = document["honeypot"] if document else None
        if not pot or not pot["enabled"] or pot["channel"] not in (channel_id, parent_id):
            return
        if not is_webhook and set(role_ids) & set(pot["whitelist_roles"]):
            return
        deleted = await self.port.delete_message(channel_id, message_id)
        now = time.monotonic()
        key = (guild_id, user_id)
        if not is_webhook and now - self._honeypot_seen.get(key, -HONEYPOT_REPEAT) < HONEYPOT_REPEAT:
            return
        self._honeypot_seen[key] = now
        if len(self._honeypot_seen) > 5000:
            self._honeypot_seen.clear()
        automated = is_webhook or is_bot
        action = "log" if automated else pot["action"]
        reason = "AltWarden: posted in the honeypot channel"
        took = {"log": "Logged", "timeout": "Timed out", "kick": "Kicked", "softban": "Softbanned", "ban": "Banned"}[action]
        guild_name = "this server"
        delivered = None
        if action != "log":
            guild = await self.port.guild(guild_id)
            guild_name = guild.name if guild else guild_name
            appeal_url = f"{self.public_url}/appeal/{guild_id}" if document["appeals"]["enabled"] else None
            # First, because Discord refuses a DM once the two share no server.
            delivered = await self.port.dm(user_id, notices.honeypot_notice(guild_name, action, pot["timeout_minutes"], appeal_url))
        done = True
        if action == "timeout":
            done = await self.port.timeout(guild_id, user_id, pot["timeout_minutes"], reason)
        elif action == "kick":
            done = await self.port.kick(guild_id, user_id, reason)
        elif action == "ban":
            done = await self.port.ban(guild_id, user_id, reason, delete_seconds=3600)
        elif action == "softban":
            done = await self.port.ban(guild_id, user_id, reason, delete_seconds=3600)
            if done and not (await self.port.unban(guild_id, user_id, reason) or await self.port.unban(guild_id, user_id, reason)):
                took = "Banned, and the unban failed, so they're still banned"
        if done and action in ("kick", "softban", "ban"):
            await self.db.update_member(guild_id, user_id, status="pending", verified_at=None)  # or a rejoin would restore the role
        if not done and delivered is True:
            await self.port.dm(user_id, notices.timeout_failed_notice(guild_name) if action == "timeout" else notices.not_removed_notice(guild_name))
        if not automated:
            # An action that didn't land has no action on record, which is also what leaves nothing to appeal.
            await self.db.add_attempt(guild_id, user_id, "honeypot", check_id="honeypot", action=action if done else None, detail={})
        who = "A webhook" if is_webhook else f"A bot (<@{user_id}>)" if is_bot else f"<@{user_id}>"
        await self._log(guild_id, document, ["honeypot"], notices.staff_log(
            "Honeypot triggered", f"{who} posted in <#{channel_id}>. {took}{'' if done else ' (failed, usually a missing permission)'}."
            + ("" if deleted else " The message is still there, because AltWarden needs Manage Messages in that channel."),
            notices.RED))

    # --- help desk --------------------------------------------------------------------------

    async def open_help(self, member: MemberInfo) -> tuple[str | None, str]:
        """Open or find a member's help thread. Returns its ID, or None, and a message for them."""
        guild_id, user_id = member.guild_id, member.user_id
        document = await self.get_settings(guild_id)
        if document is None:  # an old button, after /uninstall
            return None, NOT_SET_UP
        desk = document["core"]["help_desk"]
        if not desk["enabled"]:
            return None, "The help desk is off in this server."
        async with self._lock(guild_id, user_id):  # a second press waits, and finds the thread the first one opened
            return await self._open_help(member, document)

    async def _open_help(self, member: MemberInfo, document: dict) -> tuple[str | None, str]:
        guild_id, user_id = member.guild_id, member.user_id
        desk = document["core"]["help_desk"]
        await self.db.touch_member(guild_id, user_id, username=member.username, avatar=member.avatar)
        record = await self.db.member(guild_id, user_id)
        # What stopped their last attempt. With reasons hidden, the steps would name the check.
        found = fixes.every_way(await self._last_failure(guild_id, user_id)) if document["core"]["show_reason"] else []
        where = " The steps for what stopped you are in it." if found else ""
        if record["help_thread_id"]:
            if await self.port.reopen_thread(record["help_thread_id"], user_id):
                if found and (record["help_reminded_at"] or 0) < (record["last_fail_at"] or 0):
                    # The pinned steps can be for an older attempt, so the current ones go at the bottom, where the member will type.
                    await self.port.send(record["help_thread_id"], notices.help_reminder(user_id, found, document["core"]["channel"]), guild_id=guild_id)
                    await self.db.update_member(guild_id, user_id, help_reminded_at=time.time())
                return record["help_thread_id"], f"Your help thread is <#{record['help_thread_id']}>.{where}"
            await self.db.update_member(guild_id, user_id, help_thread_id=None)  # Someone deleted it, so start a new one.
        attempts = await self.db.all(f"SELECT check_id, at FROM attempts WHERE guild_id = ? AND user_id = ? AND {APPEALABLE} ORDER BY at DESC LIMIT 10",
                                     (guild_id, user_id))
        if desk["require_attempt"] and not attempts:
            return None, "Try verifying first. If it fails, press this button again."
        guild = await self.port.guild(guild_id)
        first = notices.plain_message(document["messages"]["help_desk"], guild.name if guild else "this server", self.public_url)
        # Discord's limit covers every embed in a message, and the server's own text can use nearly all of it.
        records = notices.records_embed(attempts, document["core"]["show_reason"], notices.EMBED_LIMIT - sum(map(notices.embed_size, first.embeds)))
        steps = None
        if found:
            # A short checklist leads, then the steps, so the member sees the obvious answers before asking. Records take their room first.
            first.content = notices.help_thread_lead(found, document["core"]["channel"]) + (f"\n\n{first.content}" if first.content else "")
            room = notices.EMBED_LIMIT - sum(map(notices.embed_size, first.embeds)) - (notices.embed_size(records) if records else 0)
            steps = notices.steps_embed(found, room)
        first.embeds += [embed for embed in (steps, records) if embed]
        first.buttons.extend(notices.help_thread_buttons(user_id))
        thread_id = await self.port.open_help_thread(document["core"]["channel"], member.username or user_id, user_id,
                                                      desk["support_role"], first, guild_id=guild_id)
        if thread_id is None:
            told = await self._log(guild_id, document, ["help_desk"], notices.staff_log(
                "Help desk can't open threads", "AltWarden is missing a permission in the verification channel.", notices.RED))
            return None, ("The help desk can't open a thread right now. Staff have been told." if told else "The help desk can't open a thread right now. Please tell the server's staff.")
        # The opening message isn't a reminder. Many members write before they read, so their first post still gets one.
        await self.db.update_member(guild_id, user_id, help_thread_id=thread_id, help_reminded_at=None)
        await self._log(guild_id, document, ["help_desk"], notices.staff_log("Help thread opened", f"<@{user_id}> opened <#{thread_id}>."))
        return thread_id, f"Your help thread is <#{thread_id}>.{where}"

    async def remind_in_help_thread(self, guild_id: str, thread_id: str, user_id: str) -> bool:
        """A member's first post in their own help thread after a failure gets the checklist and the steps again, while staff come."""
        document = await self.get_settings(guild_id)
        if document is None or not document["core"]["help_desk"]["enabled"] or not document["core"]["show_reason"]:
            return False
        async with self._lock(guild_id, user_id):  # two quick posts get one reminder
            record = await self.db.member(guild_id, user_id)
            if record is None or record["help_thread_id"] != thread_id:
                return False
            if record["help_reminded_at"] is not None and record["help_reminded_at"] >= (record["last_fail_at"] or 0):
                return False
            found = fixes.every_way(await self._last_failure(guild_id, user_id))
            if not found:
                return False
            await self.db.update_member(guild_id, user_id, help_reminded_at=time.time())
        return await self.port.send(thread_id, notices.help_reminder(user_id, found, document["core"]["channel"]), guild_id=guild_id) is not None

    async def _last_failure(self, guild_id: str, user_id: str) -> list:
        """What stopped a member's latest attempt, or nothing if they got in since."""
        row = await self.db.one("SELECT outcome, detail FROM attempts WHERE guild_id = ? AND user_id = ? AND outcome IN ('failed', 'passed', 'manual') "
                                "ORDER BY at DESC, id DESC LIMIT 1", (guild_id, user_id))
        if row is None or row["outcome"] != "failed":
            return []
        stored = json.loads(row["detail"] or "{}").get("findings", [])
        # Before 1.4.1 an attempt didn't store a finding's reason, which only the email check's two outcomes need.
        return [engine.Finding(item["check"], item["action"], item.get("reason") or item["check"], item.get("detail") or {})
                for item in stored if isinstance(item, dict) and item.get("check") and item.get("action") != WATCH]

    async def close_help(self, guild_id: str, thread_id: str, actor: MemberInfo) -> tuple[bool, str]:
        document = await self.get_settings(guild_id)
        if document is None:  # an old button, after /uninstall
            return False, NOT_SET_UP
        desk = document["core"]["help_desk"]
        owner = await self.db.one("SELECT user_id FROM members WHERE guild_id = ? AND help_thread_id = ?", (guild_id, thread_id))
        is_staff = desk["support_role"] in actor.role_ids or "manage_threads" in actor.permissions or actor.is_owner
        is_opener = owner is not None and owner["user_id"] == actor.user_id
        if not is_staff and not (is_opener and desk["member_close"]):
            return False, "Only staff can close this thread."
        if not await self.port.close_thread(thread_id):
            return False, "AltWarden couldn't close this thread. Try again, or close it by hand."
        if owner:
            await self.db.update_member(guild_id, owner["user_id"], help_thread_id=None)
        await self._log(guild_id, document, ["help_desk"], notices.staff_log("Help thread closed", f"<@{actor.user_id}> closed <#{thread_id}>."), alert_for=[])
        return True, "Closed."

    # --- appeals ----------------------------------------------------------------------------

    async def submit_appeal(self, guild_id: str, user_id: str, username: str, text: str) -> str | None:
        """Returns an error message, or None when the appeal is saved. Staff see it on the Appeals page even if the post below fails."""
        document = await self.get_settings(guild_id)
        if document is None or not document["appeals"]["enabled"]:
            return "This server doesn't take appeals."
        text = text.strip()[:MAX_APPEAL_CHARS]
        if len(text) < 10:
            return "Please explain what happened in a sentence or two."
        # Saved here, nobody could ever see it or decide it.
        if await self.port.guild(guild_id) is None:
            return "Discord is still loading this server. Try again in a few minutes." if await self.port.guild_loading(guild_id) else "AltWarden isn't in this server any more."
        last, problem = await self._appeal_problem(guild_id, user_id)
        if problem:
            return problem
        appeal_id = await self.db.open_appeal(guild_id, user_id, last["check_id"], text)
        if appeal_id is None:  # another submit got there after the check above
            return "You already have an appeal waiting."
        linked = await self.db.scalar("SELECT 1 FROM links WHERE guild_id = ? AND (main_id = ? OR alt_id = ?)", (guild_id, user_id, user_id))
        card = notices.appeal_card(appeal_id, user_id, username, last["check_id"], text, linked=bool(linked))
        appeals = document["appeals"]
        target = appeals["channel"] or document["core"]["logs"]["modules"].get("appeals") or document["core"]["logs"]["modules"].get("general")
        role = appeals["role"] or settings_module.alert_role(document, "appeals")
        if role:
            card.content = f"<@&{role}>"
            card.mention_roles = [role]
        if target:
            message_id = await self.port.send(target, card, guild_id=guild_id)
            await self.db.run("UPDATE appeals SET channel_id = ?, message_id = ? WHERE id = ?", (target, message_id, appeal_id))
        await self._emit(guild_id, "appeal.opened", {"user_id": user_id, "appeal": appeal_id})
        return None

    async def _appeal_problem(self, guild_id: str, user_id: str) -> tuple[dict | None, str | None]:
        """A member's latest attempt that can be appealed, and why a new appeal would be refused, if it would."""
        last = await self.db.one(f"SELECT check_id, at FROM attempts WHERE guild_id = ? AND user_id = ? AND {APPEALABLE} ORDER BY at DESC LIMIT 1",
                                 (guild_id, user_id))
        record = await self.db.member(guild_id, user_id)
        # A try past a used-up limit writes no attempt. It leaves its time on the member, and it counts as a new failed attempt.
        if record and record["limit_reached_at"] and record["last_fail_at"] and (last is None or record["last_fail_at"] > last["at"]):
            last = {"check_id": "max_attempts", "at": record["last_fail_at"]}
        if last is None or time.time() - last["at"] > APPEAL_WINDOW:
            return last, "There is no recent failed attempt to appeal."
        if await self.db.scalar("SELECT 1 FROM appeals WHERE guild_id = ? AND user_id = ? AND status IN ('open', 'deciding')", (guild_id, user_id)):
            return last, "You already have an appeal waiting."
        decided = await self.db.scalar("SELECT MAX(decided_at) FROM appeals WHERE guild_id = ? AND user_id = ? AND status IN ('approved', 'denied')", (guild_id, user_id))
        # A try past a used-up limit is free and leaves a new time, so without this gap each denial could bring a new ping at once.
        if decided and record and record["limit_reached_at"] and time.time() - decided < REAPPEAL_SECONDS:
            return last, "Staff already decided your appeal about this. You can appeal again tomorrow."
        if decided and last["at"] <= decided:
            return last, "Staff already decided your appeal about this. A new failed attempt can be appealed."
        return last, None

    async def appeal_state(self, guild_id: str, user_id: str) -> dict:
        """What the appeal page needs: whether a new appeal would go through, and the latest decision. It names no check, which reasons-hidden servers keep private."""
        document = await self.get_settings(guild_id)
        last, problem = await self._appeal_problem(guild_id, user_id)
        waiting = await self.db.scalar("SELECT 1 FROM appeals WHERE guild_id = ? AND user_id = ? AND status IN ('open', 'deciding')", (guild_id, user_id))
        latest = await self.db.one("SELECT status, note, decided_at FROM appeals WHERE guild_id = ? AND user_id = ? AND status IN ('approved', 'denied') ORDER BY decided_at DESC LIMIT 1",
                                   (guild_id, user_id))
        return {"enabled": bool(document and document["appeals"]["enabled"]), "present": await self.port.guild(guild_id) is not None,
                "failed_at": last["at"] if last else None, "problem": problem, "open": bool(waiting), "latest": latest}

    async def decide_appeal(self, guild_id: str, appeal_id: int, decision: str, actor_id: str, actor_name: str = "",
                            note: str | None = None, *, can_unban: bool = True) -> str | None:
        """settle_appeal, for a caller that needs only the problem, or None."""
        return (await self.settle_appeal(guild_id, appeal_id, decision, actor_id, actor_name, note, can_unban=can_unban))["problem"]

    async def settle_appeal(self, guild_id: str, appeal_id: int, decision: str, actor_id: str, actor_name: str = "",
                            note: str | None = None, *, can_unban: bool = True) -> dict:
        """Decide an appeal. Returns `{problem, told}`: why it was refused, or None, and whether the member got the DM.

        Discord won't deliver a DM to someone who shares no server with the bot, which is every kicked or banned member.
        """
        def refused(problem: str) -> dict:
            return {"problem": problem, "told": False}
        appeal = await self.db.one("SELECT * FROM appeals WHERE id = ? AND guild_id = ?", (appeal_id, guild_id))
        if appeal is None:
            return refused("That appeal doesn't exist.")
        document = await self.get_settings(guild_id)
        if document is None:  # an old button, after /uninstall
            return refused(NOT_SET_UP)
        if appeal["status"] != "open":
            return refused("That appeal was already decided.")
        user_id = appeal["user_id"]
        approved = decision in ("approve", "trust")
        banned = False
        if approved:
            on_discord = await self._discord_ban(guild_id, user_id)
            banned = await self.db.is_banned(guild_id, user_id) or bool(on_discord)
            if on_discord is None and not banned:
                return refused("Discord didn't answer, so the appeal is still open. Try again in a moment.")
        if banned and not can_unban:
            return refused("Approving this lifts a ban, which takes Ban Members.")
        # Only one decision can win, however many staff press a button at the same moment. "deciding" holds it
        # while Discord answers, and a restart hands it back, so a crash here can't leave it half done.
        claimed = await self.db.run("UPDATE appeals SET status = 'deciding' WHERE id = ? AND status = 'open'", (appeal_id,))
        if not claimed:
            return refused("That appeal was already decided.")

        async def undo(problem: str) -> dict:
            await self.db.run("UPDATE appeals SET status = 'open' WHERE id = ?", (appeal_id,))
            return refused(problem)
        try:
            if approved:
                if banned:
                    if not await self.port.unban(guild_id, user_id, f"Appeal approved by {actor_name or actor_id}"):
                        return await undo("AltWarden couldn't lift the ban. It needs Ban Members.")
                    await self.on_unban(guild_id, user_id)
                try:
                    present = await self.port.member(guild_id, user_id) is not None
                except DiscordUnavailable:
                    if not banned:
                        raise
                    present = False  # the ban is already gone, so this finishes, and the role comes when they rejoin or press Verify
                await self.db.touch_member(guild_id, user_id)
                if present:
                    problem = await self.manual_verify(guild_id, user_id, actor_id, actor_name)
                    if problem:
                        return await undo(f"The role couldn't be given, so the appeal is still open: {problem}")
                    if appeal["check_id"] == "honeypot":
                        # Staff said the post in the trap was no reason to stop this member, so a timeout from it ends too.
                        await self.port.clear_timeout(guild_id, user_id, f"Appeal approved by {actor_name or actor_id}")
                else:
                    await self.db.update_member(guild_id, user_id, status="approved")
                    # A link they still hold could fail a check, and undo what staff just decided.
                    await self.db.run("DELETE FROM sessions WHERE guild_id = ? AND user_id = ? AND state != 'done'", (guild_id, user_id))
                if decision == "trust":
                    rows = await self.db.all("SELECT main_id, alt_id FROM links WHERE guild_id = ? AND (main_id = ? OR alt_id = ?)", (guild_id, user_id, user_id))
                    for row in rows:
                        await self.db.trust_pair(guild_id, row["main_id"], row["alt_id"], actor_id)
                        await self._clear_limits(guild_id, document, row["main_id"], row["alt_id"])
            await self.db.run("UPDATE appeals SET status = ?, decided_by = ?, decided_at = ?, note = ? WHERE id = ?",
                              ("approved" if approved else "denied", actor_id, time.time(), note, appeal_id))
        except DiscordUnavailable:
            return await undo("Discord didn't answer, so the appeal is still open. Try again in a moment.")
        except Exception:
            await undo("")
            raise
        guild = await self.port.guild(guild_id)
        told = await self.port.dm(user_id, notices.appeal_result_notice(guild.name if guild else "this server", approved, note)) is True
        await self.db.add_audit(guild_id, "appeal", actor_id=actor_id, actor_name=actor_name,
                                detail={"appeal": appeal_id, "user": user_id, "decision": decision, "told": told})
        if appeal["channel_id"] and appeal["message_id"]:
            verdict = {"approve": "Approved", "trust": "Approved, link trusted", "deny": "Turned down"}[decision]
            await self.port.edit_message(appeal["channel_id"], appeal["message_id"], Notice(embeds=[{
                "title": f"Appeal: {verdict}", "description": notices.escape_text(appeal["text"][:1500]),
                "color": notices.GREEN if approved else notices.GRAY,
                "fields": [{"name": "Account", "value": f"<@{user_id}>", "inline": True},
                           {"name": "Decided by", "value": f"<@{actor_id}>", "inline": True},
                           {"name": "Member told", "value": "Yes" if told else "No", "inline": True}]}]))
        await self._emit(guild_id, "appeal.decided", {"user_id": user_id, "appeal": appeal_id, "decision": decision})
        return {"problem": None, "told": told}

    # --- posting ----------------------------------------------------------------------------

    async def staff_post(self, guild_id: str, which: str, poster, *, actor_id: str, actor_name: str) -> str:
        """Post a message again for a member of staff, from the dashboard or /post-message. Returns posted or failed.

        `poster` does the posting and answers False if it couldn't. Only the layer holding the bot has one to give.
        """
        if await poster(guild_id, which) is False:
            return "failed"
        await self.db.add_audit(guild_id, "post_message", actor_id=actor_id, actor_name=actor_name, detail={"message": which})
        return "posted"

    # --- members' own data ------------------------------------------------------------------

    async def _servers_holding(self, user_id: str) -> list[str]:
        """Every server with any record of this person, including staff who never verified and accounts only ever banned."""
        # Searching every attempt's detail takes a moment on a big server, so it runs off the main connection.
        rows = await self.db.read_all(
            "SELECT guild_id FROM members WHERE user_id = ?1 UNION SELECT guild_id FROM attempts WHERE user_id = ?1 "
            "UNION SELECT guild_id FROM identifiers WHERE user_id = ?1 UNION SELECT guild_id FROM sessions WHERE user_id = ?1 OR bypass_by = ?1 "
            "UNION SELECT guild_id FROM appeals WHERE user_id = ?1 OR decided_by = ?1 UNION SELECT guild_id FROM links WHERE main_id = ?1 OR alt_id = ?1 "
            "UNION SELECT guild_id FROM trusted_pairs WHERE first_id = ?1 OR second_id = ?1 OR by_id = ?1 UNION SELECT guild_id FROM bans WHERE user_id = ?1 "
            "UNION SELECT guild_id FROM audit WHERE actor_id = ?1 OR detail LIKE ?2 UNION SELECT guild_id FROM attempts WHERE detail LIKE ?2 "
            "UNION SELECT guild_id FROM guilds WHERE settings LIKE ?2",
            (user_id, f'%"{user_id}"%'))
        return [row["guild_id"] for row in rows]

    async def my_data(self, user_id: str) -> list[dict]:
        """Everything held about one person, per server, in words."""
        result = []
        for guild_id in await self._servers_holding(user_id):
            row = await self.db.member(guild_id, user_id) or {}
            kinds = await self.db.all("SELECT kind, COUNT(*) AS count, MAX(expires_at) AS expires_at FROM identifiers "
                                      "WHERE guild_id = ? AND user_id = ? GROUP BY kind", (guild_id, user_id))
            attempts = await self.db.all("SELECT at, outcome, check_id, action, mode, seconds, detail FROM attempts WHERE guild_id = ? AND user_id = ? ORDER BY at DESC LIMIT 200",
                                         (guild_id, user_id))
            for attempt in attempts:
                attempt["detail"] = _own_detail(json.loads(attempt["detail"]))
            appeals = await self.db.all("SELECT created_at, status, text, note FROM appeals WHERE guild_id = ? AND user_id = ? ORDER BY created_at DESC", (guild_id, user_id))
            # Links are counted and never named, because the other account is someone else's data.
            links = await self.db.scalar("SELECT COUNT(*) FROM links WHERE guild_id = ? AND (main_id = ? OR alt_id = ?)", (guild_id, user_id, user_id))
            guild = await self.port.guild(guild_id)
            staff = await self.db.scalar("SELECT COUNT(*) FROM audit WHERE guild_id = ? AND actor_id = ?", (guild_id, user_id))
            ban = await self.db.one("SELECT at FROM bans WHERE guild_id = ? AND user_id = ?", (guild_id, user_id))
            result.append({"guild_id": guild_id, "guild_name": guild.name if guild else "A server",
                           **{name: row.get(name) for name in ("status", "verified_at", "method", "username", "avatar", "first_verified_at", "joined_at",
                                                               "kick_at", "fails", "last_fail_at", "limit_reached_at", "help_thread_id")},
                           "stored_hashes": kinds, "attempts": attempts,
                           "attempt_count": await self.db.scalar("SELECT COUNT(*) FROM attempts WHERE guild_id = ? AND user_id = ?", (guild_id, user_id)),
                           "appeals": appeals, "linked_accounts": links, "staff_actions": staff,
                           "trusted_pairs": await self.db.scalar("SELECT COUNT(*) FROM trusted_pairs WHERE guild_id = ? AND (first_id = ? OR second_id = ?)", (guild_id, user_id, user_id)),
                           "audit_about": await self._audit_rows_about(guild_id, user_id),
                           "live_links": await self.db.scalar("SELECT COUNT(*) FROM sessions WHERE guild_id = ? AND user_id = ? AND state != 'done' AND expires_at > ?", (guild_id, user_id, time.time())),
                           "banned": ban is not None, "banned_at": ban["at"] if ban else None})
        return result

    async def _audit_rows_about(self, guild_id: str, user_id: str) -> int:
        # The search reads every row, so it runs off the main connection.
        rows = await self.db.read_all("SELECT COUNT(*) AS total FROM audit WHERE guild_id = ? AND detail LIKE ?", (guild_id, f'%"{user_id}"%'))
        return rows[0]["total"]

    async def delete_my_data(self, user_id: str, guild_id: str | None = None) -> dict:
        """Delete a person's records. Two things stay, and the privacy page states both.

        Hashes tied to an active ban stay until the ban ends or expires, or a banned account could
        erase the only thing that catches its next account. A connection hash ends sooner, on its own date. A failed-attempt count and timers stay
        with no name on them, or deleting would reset the attempt limit, cooldown and Auto Kick.
        Each server's staff get one line saying a deletion happened, with no name in it.
        """
        targets = [target for target in await self._servers_holding(user_id) if guild_id is None or target == guild_id]
        kept, removed = [], []
        for target in targets:
            # A check already running finishes first, or it would write its hashes and attempt after this has gone through. One still
            # waiting finds its session gone when its turn comes, and stops there.
            async with self._lock(target, user_id):
                (kept if await self._delete_in(target, user_id) else removed).append(target)
        # Staff who delete their record for one server keep their sign-in, and their dashboards for every other server.
        if guild_id is None:
            await self.db.run("DELETE FROM command_syncs WHERE user_id = ?", (user_id,))
            await self.db.run("DELETE FROM web_sessions WHERE user_id = ?", (user_id,))
        else:
            await self.db.run("DELETE FROM command_syncs WHERE user_id = ? AND guild_id = ?", (user_id, guild_id))
        await self.db.checkpoint()  # the log file still holds what was just deleted
        return {"removed": removed, "kept_for_ban": kept}

    async def _delete_in(self, target: str, user_id: str) -> bool:
        """Delete a person's records in one server. Returns whether hashes stayed because of a ban."""
        document = await self.get_settings(target)
        banned = await self._is_banned(target, user_id)
        if banned and not await self.db.is_banned(target, user_id):
            await self.on_ban(target, user_id)  # a ban AltWarden never saw, on record now so the purge keeps the hashes too
        record = await self.db.member(target, user_id)
        await self.db.run("DELETE FROM attempts WHERE guild_id = ? AND user_id = ?", (target, user_id))
        await self.db.run("DELETE FROM appeals WHERE guild_id = ? AND user_id = ?", (target, user_id))
        await self.db.run("DELETE FROM sessions WHERE guild_id = ? AND user_id = ?", (target, user_id))
        await self.db.run("DELETE FROM links WHERE guild_id = ? AND (main_id = ? OR alt_id = ?)", (target, user_id, user_id))
        await self.db.run("DELETE FROM trusted_pairs WHERE guild_id = ? AND (first_id = ? OR second_id = ?)", (target, user_id, user_id))
        # Staff actions about this person go. A settings row is about the setting, so it stays with the ID taken out.
        # Staff actions by this person lose their name, and keep a stand-in, so one person's actions still read as one person's.
        await self.db.run("DELETE FROM audit WHERE guild_id = ? AND kind != 'settings' AND detail LIKE ?", (target, f'%"{user_id}"%'))
        await self.db.run("UPDATE audit SET detail = REPLACE(detail, ?, '\"deleted\"') WHERE guild_id = ? AND kind = 'settings' AND detail LIKE ?",
                          (f'"{user_id}"', target, f'%"{user_id}"%'))
        stand_in = f"Deleted account {self.keys.digest(int(target), 'deleted-staff', user_id)[:8]}"
        staff_actions = await self.db.run("UPDATE audit SET actor_id = NULL, actor_name = ? WHERE guild_id = ? AND actor_id = ?", (stand_in, target, user_id))
        await self.db.run("UPDATE appeals SET decided_by = NULL WHERE guild_id = ? AND decided_by = ?", (target, user_id))
        await self.db.run("UPDATE sessions SET bypass_by = NULL WHERE guild_id = ? AND bypass_by = ?", (target, user_id))
        # The search reads every attempt, so it runs off the main connection and only the matches get written.
        mentions = await self.db.read_all("SELECT id FROM attempts WHERE guild_id = ? AND detail LIKE ?", (target, f'%"{user_id}"%'))
        for row in mentions:
            await self.db.run("UPDATE attempts SET detail = REPLACE(detail, ?, '\"deleted\"') WHERE id = ?", (f'"{user_id}"', row["id"]))
        await self.db.run("UPDATE trusted_pairs SET by_id = '' WHERE guild_id = ? AND by_id = ?", (target, user_id))
        if document is not None and f'"{user_id}"' in json.dumps(document):
            await self.edit_settings(target, lambda current: _without_person(current, user_id), section="rules", record=False)
        if banned:
            await self.db.touch_member(target, user_id)  # with no row, nothing would remember to forget them at the unban
            await self.db.run("UPDATE members SET username = '', avatar = NULL, status = 'pending', verified_at = NULL, first_verified_at = NULL, forget_on_unban = 1 "
                              "WHERE guild_id = ? AND user_id = ?", (target, user_id))
            await self._note_deletion(target, document, False, staff_actions, True)
            return True
        await self.db.run("DELETE FROM identifiers WHERE guild_id = ? AND user_id = ?", (target, user_id))
        if record and _still_enforced(document, record):
            await self.db.run("UPDATE members SET username = '', avatar = NULL, status = 'pending', method = NULL, verified_at = NULL, first_verified_at = NULL, help_thread_id = NULL "
                              "WHERE guild_id = ? AND user_id = ?", (target, user_id))
        else:
            await self.db.run("DELETE FROM members WHERE guild_id = ? AND user_id = ?", (target, user_id))
        role_taken = False
        if document is not None and record is not None:  # no member record means AltWarden gave them no role, so it takes none away
            try:
                present = await self.port.member(target, user_id) is not None
            except DiscordUnavailable:
                log.warning("Couldn't reach Discord to take a role back after a deletion in %s", target)
                present = False
            if present:
                core = document["core"]
                reason = "Member deleted their verification data"
                problem = await self.port.remove_role(target, user_id, core["verified_role"], reason)
                role_taken = problem is None
                await self._note_role_problem(target, document, None, f"take <@&{core['verified_role']}> away", problem)
                if core["unverified_enabled"] and core["unverified_role"]:
                    problem = await self.port.add_role(target, user_id, core["unverified_role"], reason)
                    await self._note_role_problem(target, document, None, f"give <@&{core['unverified_role']}>", problem)
                # Someone who was let in is now here unverified, and needs the same deadline a reset gives them. A timer already running stays.
                if core["auto_kick"]["enabled"] and record["status"] in ("verified", "approved") and not record["kick_at"]:
                    await self.db.touch_member(target, user_id)
                    await self.db.update_member(target, user_id, **_kick_times(document, time.time()))
        await self._note_deletion(target, document, role_taken, staff_actions, False)
        return False

    async def _note_deletion(self, guild_id: str, document: dict | None, role_taken: bool, staff_actions: int, kept_for_ban: bool) -> None:
        """Tell a server's staff, because a deletion can take an evader's hashes or a moderator's name, and they should know it happened."""
        await self.db.add_audit(guild_id, "data_deleted", detail={"staff_actions": staff_actions, "kept_for_ban": kept_for_ban})
        if document is not None:
            await self._log(guild_id, document, ["general"], notices.staff_log("Member records deleted", "A member deleted their records."
                            + (" Their verified role was removed." if role_taken else "")
                            + (" Their hashes stay, because the account is banned." if kept_for_ban else "")
                            + (f" {staff_actions} staff action{'s' if staff_actions != 1 else ''} lost {'their' if staff_actions != 1 else 'its'} name." if staff_actions else ""), notices.AMBER))

    # --- background work --------------------------------------------------------------------

    async def tick(self) -> None:
        """Run every minute: auto kick reminders and kicks, returning attempts and raid endings. All read the database, so a restart loses none.

        A member whose lock is held is in the middle of something that can take a while, and everyone after them shouldn't wait for it. They're still due at the next run.
        """
        now = time.time()
        # A kick due now tells them itself, so it needs no reminder first.
        for row in await self.db.all("SELECT guild_id, user_id FROM members WHERE kick_warn_at IS NOT NULL AND kick_warn_at <= ? AND (kick_at IS NULL OR kick_at > ?)", (now, now)):
            lock = self._lock(row["guild_id"], row["user_id"])
            if lock.locked():
                continue
            try:
                async with lock:
                    await self._kick_reminder(row["guild_id"], row["user_id"])
            except Exception:  # the reminder stays for the next run, and mustn't hold up anyone else's
                log.exception("Auto kick reminder failed in %s", row["guild_id"])
        for row in await self.db.all("SELECT guild_id, user_id FROM members WHERE kick_at IS NOT NULL AND kick_at <= ?", (now,)):
            lock = self._lock(row["guild_id"], row["user_id"])
            if lock.locked():  # a check letting them in right now finishes first
                continue
            try:
                async with lock:
                    await self._auto_kick(row["guild_id"], row["user_id"])
            except Exception:  # one failure leaves its timer for the next run, and mustn't hold up everyone else's
                log.exception("Auto kick failed in %s", row["guild_id"])
        await self._return_attempts(now)
        for row in await self.db.all("SELECT guild_id FROM guilds WHERE raid_until > 0 AND raid_until <= ?", (now,)):
            document = await self.get_settings(row["guild_id"])
            await self.db.set_guild_field(row["guild_id"], "raid_until", 0)
            self.raid.forget(row["guild_id"])
            await self.db.add_audit(row["guild_id"], "raid_stop", detail={"why": "Its time ran out"})
            await self._log(row["guild_id"], document, ["raid", "general"], notices.staff_log("Raid mode ended", "Normal rules apply again.", notices.GREEN), alert_for=[])
            await self._emit(row["guild_id"], "raid.ended", {})

    async def _return_attempts(self, now: float) -> None:
        """Attempts come back on time whether or not the member tries again, since a limit role can hide the way to try."""
        for guild in await self.db.all("SELECT guild_id FROM guilds"):
            guild_id = guild["guild_id"]
            document = await self.get_settings(guild_id)
            reset = document["checks"]["max_attempts"]["reset_minutes"] if document else 0
            if not reset:
                continue
            for row in await self.db.all("SELECT user_id FROM members WHERE guild_id = ? AND limit_reached_at IS NOT NULL AND limit_reached_at <= ?", (guild_id, now - reset * 60)):
                lock = self._lock(guild_id, row["user_id"])
                if lock.locked():
                    continue
                try:
                    async with lock:
                        await self._give_attempts_back(guild_id, document, row["user_id"])
                except Exception:
                    log.exception("Couldn't give attempts back in %s", guild_id)

    async def _kick_reminder(self, guild_id: str, user_id: str) -> None:
        """One DM halfway through a member's time to verify, so a real member isn't removed for missing the first one."""
        if await self.port.guild_loading(guild_id):
            return
        document = await self.get_settings(guild_id)
        record = await self.db.member(guild_id, user_id)
        if document is None or record is None or not document["core"]["auto_kick"]["enabled"] or record["status"] == "verified" or not record["kick_at"]:
            await self.db.update_member(guild_id, user_id, kick_warn_at=None)
            return
        member = await self.port.member(guild_id, user_id, fresh=True)  # raises when Discord can't answer, which keeps the reminder
        await self.db.update_member(guild_id, user_id, kick_warn_at=None)
        core = document["core"]
        # A member held by Membership Screening gets a new window each time this comes round, and a DM for each would be spam.
        if member is None or member.pending or core["verified_role"] in member.role_ids or not core["auto_dm"]:
            return
        guild = await self.port.guild(guild_id)
        await self.port.dm(user_id, notices.kick_reminder_notice(guild.name if guild else "the server", record["kick_at"], core["mode"], core["channel"]))

    async def _auto_kick(self, guild_id: str, user_id: str) -> None:
        # While Discord is still handing the server over, a member's roles can read as empty.
        if await self.port.guild_loading(guild_id):
            return
        document = await self.get_settings(guild_id)
        record = await self.db.member(guild_id, user_id)
        if document is None or record is None or not document["core"]["auto_kick"]["enabled"] or record["status"] == "verified":
            await self.db.update_member(guild_id, user_id, **NO_KICK_TIMES)
            return
        member = await self.port.member(guild_id, user_id, fresh=True)  # raises when Discord can't answer, which keeps the timer
        if member is None or document["core"]["verified_role"] in member.role_ids:
            await self.db.update_member(guild_id, user_id, **NO_KICK_TIMES)
            return
        if member.pending:  # Membership Screening lets them do nothing yet, so their time hasn't really started
            await self.db.update_member(guild_id, user_id, **_kick_times(document, time.time()))
            return
        # Hourly retries of a kick that can't land say all this once.
        told = await self.db.scalar("SELECT 1 FROM attempts WHERE guild_id = ? AND user_id = ? AND outcome = 'auto_kick_failed' AND at >= ?",
                                    (guild_id, user_id, record["joined_at"] or 0))
        guild = await self.port.guild(guild_id)
        name = guild.name if guild else "the server"
        delivered = None
        if document["core"]["auto_dm"] and not told:
            delivered = await self.port.dm(user_id, notices.timed_out_notice(name))  # first, because Discord refuses a DM once the two share no server
        kicked = await self.port.kick(guild_id, user_id, "AltWarden: didn't verify in time")
        if kicked:
            await self.db.update_member(guild_id, user_id, **NO_KICK_TIMES)
            await self.db.add_attempt(guild_id, user_id, "auto_kick", action="kick")
            await self._log(guild_id, document, ["auto_kick"], notices.staff_log("Auto kick", f"<@{user_id}> didn't verify in time.", notices.AMBER))
            return
        await self.db.update_member(guild_id, user_id, kick_at=time.time() + KICK_RETRY_SECONDS, kick_warn_at=None)
        if told:
            return
        await self.db.add_attempt(guild_id, user_id, "auto_kick_failed")
        if delivered is True:
            await self.port.dm(user_id, notices.kick_retry_notice(name))
        await self._log(guild_id, document, ["auto_kick"], notices.staff_log(
            "Auto kick", f"<@{user_id}> didn't verify in time. The kick failed, usually a missing permission. AltWarden tries again in an hour.", notices.AMBER))

    async def purge(self) -> dict:
        rows = await self.db.all("SELECT guild_id FROM guilds")
        documents = {}
        for row in rows:
            document = await self.get_settings(row["guild_id"])
            if document is not None:
                documents[row["guild_id"]] = document
        known = set(documents)
        removed = await self.db.purge_expired(documents)
        for guild_id in known - set(documents):  # the purge took this server's rows, so its settings can't linger in memory
            self.forget_cached(guild_id)
        return removed

    # --- logs and webhooks ------------------------------------------------------------------

    async def _log(self, guild_id: str, rules: dict, modules: list[str], embed: dict, *, alert_for: list | None = None,
                   alert_role: str | None = None) -> bool:
        """Post to each module's log channel, and return whether any post went up. That's what lets a message say staff were told.

        A module's alert role is pinged only in that module's channel. `alert_for` narrows which modules ping, and
        `alert_role` pings once, in the first channel.
        """
        logs = rules["core"]["logs"]
        if not logs["enabled"]:
            return False
        channels: dict[str, list[str]] = {}
        for name in modules:
            if name in logs["modules"]:
                channels.setdefault(logs["modules"][name], []).append(name)
        posted = False
        for index, (channel_id, names) in enumerate(channels.items()):
            # Raid mode's own role, when it has one, replaces the main role for the raid's channel.
            roles = [role for name in names if (alert_for is None or name in alert_for) and not (name == "raid" and alert_role) and (role := settings_module.alert_role(rules, name))]
            if alert_role and index == 0:
                roles.append(alert_role)
            roles = list(dict.fromkeys(roles))
            content = " ".join(f"<@&{role}>" for role in roles)
            posted = bool(await self.port.send(channel_id, Notice(content=content, embeds=[embed], mention_roles=roles), guild_id=guild_id)) or posted
        return posted

    async def _emit(self, guild_id: str, event: str, payload: dict) -> None:
        if self.webhook_sender is not None:
            task = asyncio.ensure_future(self.webhook_sender(guild_id, event, payload))
            self._background.add(task)
            task.add_done_callback(self._background.discard)


NO_KICK_TIMES = {"kick_at": None, "kick_warn_at": None}


def _kick_times(document: dict, start: float) -> dict:
    """The member fields that start a member's time to verify at `start`: the kick when it's up, and a reminder halfway."""
    minutes = document["core"]["auto_kick"]["minutes"]
    return {"kick_at": start + minutes * 60, "kick_warn_at": start + minutes * 30}


def _spent_today(table: OrderedDict, key: tuple, now: float) -> tuple[float, int]:
    """When a key's day began, and how many lookups it has spent in that day."""
    began, count = table.get(key, (now, 0))
    return (now, 0) if now - began >= DAY else (began, count)


def _charge(table: OrderedDict, key: tuple, now: float) -> None:
    """Count one lookup against a key's day. The key used longest ago goes first, so the table can't grow without end."""
    began, count = _spent_today(table, key, now)
    table[key] = (began, count + 1)
    table.move_to_end(key)
    while len(table) > LOOKUP_COUNT_SIZE:
        table.popitem(last=False)


def _past_deny_limit(decision: engine.Decision, record: dict) -> engine.Finding | None:
    """The limit's finding, if this member is past a limit that only denies and its time has been stamped.

    Nothing new can come of another try, so it gets the same answer and nothing else: no DM, log, ping, webhook, attempt
    row, lookup or stored hashes. A limit that kicks or bans still acts, because each try then costs a rejoin. A member over
    the limit with no stamp got there by another road: staff lowered the limit or turned it on, or a bypass link skipped it.
    That try goes on to _conclude, which stamps it, because only a stamp gives attempts back.
    """
    if not record["limit_reached_at"]:
        return None
    return next((finding for finding in decision.findings if finding.check_id == "max_attempts" and finding.action == DENY), None)


def _failed_result(rules: dict, primary: engine.Finding, done: str, *, retry_on: float | None = None, attempts_left: int | None = None,
                   fixes: list | None = None) -> Result:
    """What the member sees after a failure. `done` is what really happened, because the page mustn't say someone was removed when they're still here."""
    show = rules["core"]["show_reason"]
    desk = rules["core"]["help_desk"]
    return Result("failed", "You weren't verified", primary.message if show else "You didn't pass this server's checks.",
                  reason=primary.reason if show else None, action=done,
                  help_slug=HELP_SLUG.get(primary.reason) if show else "verification",
                  # With reasons hidden, leaving this off would say which kind of check it was.
                  retry=done == DENY and (not show or primary.check_id not in NO_RETRY_CHECKS),
                  appeal=rules["appeals"]["enabled"], template=FAILURE_TEXT[primary.reason] if show else None,
                  args=primary.text_args if show else None, retry_on=retry_on if show else None,
                  # After a kick or a ban there's no member to open a thread for.
                  staff_help=done == DENY and desk["enabled"] and desk["redirect"], attempts_left=attempts_left,
                  fixes=(fixes or None) if show and done != BAN else None)


def _without_person(value, user_id: str):
    """A copy of a settings value with a person's member overrides and message credits taken out."""
    if isinstance(value, list):
        return [_without_person(item, user_id) for item in value if not (isinstance(item, dict) and item.get("type") == "user" and item.get("id") == user_id)]
    if isinstance(value, dict):
        return {key: None if key == "author" and item == user_id else _without_person(item, user_id) for key, item in value.items()}
    return value


def _own_detail(detail: dict) -> dict:
    """What an attempt recorded, for its own member. The other account in a match, and the staff member who acted, are someone else's data."""
    findings = [{**finding, "detail": {key: value for key, value in finding.get("detail", {}).items() if key != "account"}} for finding in detail.get("findings", [])]
    return {**{key: value for key, value in detail.items() if key != "by"}, **({"findings": findings} if findings else {})}


def _still_enforced(document: dict | None, record: dict) -> bool:
    """Whether a member's row is holding a limit or a timer that deleting mustn't reset."""
    if document is None:
        return False
    cooldown = document["core"]["cooldown"]
    return bool(record["kick_at"] or (document["checks"]["max_attempts"]["enabled"] and record["fails"])
                or (cooldown["enabled"] and record["last_fail_at"] and record["last_fail_at"] + cooldown["seconds"] > time.time()))


def _attempt_detail(decision: engine.Decision, bypassed: list, notes: dict | None = None) -> dict:
    """What gets stored about an attempt. Labels and scores only, never a raw value."""
    return {"findings": [{"check": finding.check_id, "action": finding.action, "reason": finding.reason, "detail": finding.detail}
                         for finding in decision.findings], "bypassed": bypassed, **(notes or {})}


def _avatar_url(user_id: str, avatar: str | None) -> str | None:
    return f"https://cdn.discordapp.com/avatars/{user_id}/{avatar}.png?size=128" if avatar else None


def _short(value) -> str:
    """A setting's value, for inside a code span in the log. A backtick in it would end the span and let the rest format the embed."""
    text = json.dumps(value) if not isinstance(value, str) else value
    return text[:80].replace("`", "'")


def _role_problem_text(what_happened: str, problem: str, told: bool) -> str:
    if problem == DISCORD_BUSY:  # nothing about the server's roles is wrong, and asking again is the remedy
        return f"{what_happened}, but Discord didn't answer. Try again in a moment."
    return f"{what_happened}, but the server's roles need fixing. {'Staff have been told.' if told else 'Please tell the server' + chr(39) + 's staff.'}"

