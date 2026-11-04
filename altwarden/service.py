"""Everything that happens to a member, from joining to verified, kicked, appealed or forgotten.

The bot and the web server both call in here. Nothing in this file imports discord.py or aiohttp's
server parts, so the whole flow runs in tests against a fake Discord.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass

from . import altmatch, engine, health, notices, settings as settings_module, signals
from .catalog import BAN, CHECK_IDS, DENY, FAILURE_TEXT, HELP_SLUG, INSTANT, KICK, WATCH, WEB
from .crypto import Keyring, network_of, new_token, token_hash
from .db import Database
from .netintel import NetIntel
from .ports import ROLE_TOO_LOW, DiscordPort, MemberInfo, Notice

log = logging.getLogger("altwarden.service")

LINK_MINUTES = 60
MAX_BYPASS_HOURS = 168
APPEAL_WINDOW = 7 * 86400
MAX_APPEAL_CHARS = 1500
POW_BITS = 17
HONEYPOT_REPEAT = 60  # a flood of posts from one account gets one action


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

    def as_dict(self) -> dict:
        return {"status": self.status, "title": self.title, "message": self.message, "reason": self.reason,
                "action": self.action, "help": self.help_slug, "retry": self.retry, "appeal": self.appeal,
                "seconds_left": round(self.seconds_left), "template": self.template, "args": self.args,
                "retry_on": self.retry_on, "staff_help": self.staff_help}

    def discord_text(self) -> str:
        """The message for a reply in Discord, where timestamps show in each reader's own time zone."""
        text = self.message
        if self.seconds_left > 0:
            text += f" You can try again <t:{int(time.time() + self.seconds_left)}:R>."
        if self.retry_on:
            text += f"\n\nYou can try again after <t:{int(self.retry_on)}:f>."
        return text


class RaidWatch:
    """Counts joins in a sliding window. Held in memory because a raid is over by any restart."""

    def __init__(self) -> None:
        self.joins: dict[str, deque] = defaultdict(deque)

    def joined(self, guild_id: str, now: float, window: int, limit: int) -> bool:
        joins = self.joins[guild_id]
        joins.append(now)
        while joins and joins[0] < now - window:
            joins.popleft()
        return len(joins) >= limit


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
        self.proxycheck = None      # set when an outside lookup is configured
        self._settings: dict[str, dict] = {}
        self._honeypot_seen: dict[tuple, float] = {}
        self._background: set = set()  # asyncio keeps only a weak reference, so a running task needs one here

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

    async def save_settings(self, guild_id: str, document: dict, *, actor_id: str | None = None,
                            actor_name: str | None = None, setup_done: bool | None = None) -> list[dict]:
        """Store a document and record exactly what changed, with old and new values."""
        before = await self.get_settings(guild_id)
        clean = settings_module.normalize(document)
        await self.db.save_settings(guild_id, clean, setup_done=setup_done)
        self._settings[guild_id] = clean
        # Who wrote a message is bookkeeping for its footer line, and it would keep a member's ID in the log.
        changes = [change for change in settings_module.diff(before, clean) if not change["path"].endswith(".author")] if before else []
        if changes:
            await self.db.add_audit(guild_id, "settings", actor_id=actor_id, actor_name=actor_name, detail={"changes": changes[:200]})
            await self._log(guild_id, clean, ["settings"], notices.staff_log(
                "Settings changed", f"<@{actor_id}> changed {len(changes)} setting{'s' if len(changes) != 1 else ''}." if actor_id
                else f"{len(changes)} settings changed.", notices.GRAY, fields=[
                    {"name": change["path"][:250], "value": f"`{_short(change['before'])}` → `{_short(change['after'])}`", "inline": False}
                    for change in changes[:8]]))
        return changes

    def forget_cached(self, guild_id: str) -> None:
        self._settings.pop(guild_id, None)

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

    async def on_join(self, member: MemberInfo) -> None:
        guild_id, user_id = member.guild_id, member.user_id
        if member.is_bot or not await self.is_set_up(guild_id):
            return
        document = await self.get_settings(guild_id)
        await self._note_join(guild_id, document)
        await self.db.touch_member(guild_id, user_id, username=member.username, avatar=member.avatar)
        await self.db.update_member(guild_id, user_id, joined_at=time.time())
        record = await self.db.member(guild_id, user_id)
        core = document["core"]

        if record["status"] == "approved" or (record["status"] == "verified" and core["remember_rejoin"]):
            await self._grant(guild_id, document, user_id, "Already verified in this server")
            await self.db.update_member(guild_id, user_id, status="verified", kick_at=None)
            return
        await self.db.update_member(guild_id, user_id, status="pending")

        mode = core["mode"]
        kick_minutes = None
        if core["auto_kick"]["enabled"]:
            kick_minutes = core["auto_kick"]["minutes"]
            await self.db.update_member(guild_id, user_id, kick_at=time.time() + kick_minutes * 60)
        if mode == INSTANT:
            await self._check_on_join(member)
            return
        if core["unverified_enabled"] and core["unverified_role"]:
            problem = await self.port.add_role(guild_id, user_id, core["unverified_role"], "Waiting to verify")
            if problem:
                await self._log(guild_id, document, ["general"], notices.staff_log(
                    "Couldn't give the unverified role", f"<@{user_id}> joined, but: {problem}", notices.RED))
        if not core["auto_dm"]:
            return
        guild = await self.port.guild(guild_id)
        name = guild.name if guild else "this server"
        if mode == WEB:
            url, minutes = await self.new_link(guild_id, user_id, document)
            delivered = await self.port.dm(user_id, notices.link_notice(name, url, minutes=minutes, kick_minutes=kick_minutes))
        else:
            delivered = await self.port.dm(user_id, notices.go_to_channel_notice(name, core["channel"]))
        notify = core["notify_closed_dms"]
        if not delivered and notify["enabled"] and core["channel"]:
            await self.port.send(core["channel"], notices.closed_dms_notice(user_id, notify["seconds"]))

    async def _check_on_join(self, member: MemberInfo) -> None:
        """Instant mode has no page or button to show a result on, so anything unresolved goes by DM."""
        result = await self.run_quick(member, INSTANT)
        if result.status not in ("cooldown", "problem"):
            return
        guild = await self.port.guild(member.guild_id)
        name = guild.name if guild else "this server"
        if result.status == "cooldown":
            await self.port.dm(member.user_id, notices.wait_notice(name, time.time() + result.seconds_left))
        else:
            await self.port.dm(member.user_id, notices.problem_notice(name, result.title, result.message))

    async def _note_join(self, guild_id: str, document: dict) -> None:
        raid = document["raid"]
        if not raid["enabled"]:
            return
        now = time.time()
        if self.raid.joined(guild_id, now, raid["seconds"], raid["joins"]) and not await self.raid_active(guild_id):
            await self.start_raid(guild_id, document, f"{raid['joins']} joins within {raid['seconds']} seconds")

    async def start_raid(self, guild_id: str, document: dict, why: str, *, actor_id: str | None = None,
                         minutes: int | None = None) -> None:
        raid = document["raid"]
        until = time.time() + (minutes or raid["duration_minutes"]) * 60
        await self.db.set_guild_field(guild_id, "raid_until", until)
        await self.db.add_audit(guild_id, "raid_start", actor_id=actor_id, detail={"why": why})
        await self._log(guild_id, document, ["raid", "general"], notices.staff_log(
            "Raid mode on", f"{why}. Rules are tightened until <t:{int(until)}:t>.", notices.RED), alert_role=raid["alert_role"])
        await self._emit(guild_id, "raid.started", {"until": until})

    async def stop_raid(self, guild_id: str, document: dict, *, actor_id: str | None = None) -> None:
        await self.db.set_guild_field(guild_id, "raid_until", 0)
        await self.db.add_audit(guild_id, "raid_stop", actor_id=actor_id)
        await self._log(guild_id, document, ["raid", "general"], notices.staff_log("Raid mode off", "Normal rules apply again.", notices.GREEN))
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
        await self.db.run("DELETE FROM sessions WHERE guild_id = ? AND user_id = ? AND state != 'done'", (guild_id, user_id))
        token = new_token()
        await self.db.run(
            "INSERT INTO sessions (token_hash, guild_id, user_id, bypass, bypass_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (token_hash(token), guild_id, user_id, skipped, bypass_by, now, expires_at))
        return f"{self.public_url}/v/{token}", minutes

    async def _live_bypass(self, guild_id: str, user_id: str) -> dict | None:
        return await self.db.one("SELECT bypass, bypass_by, expires_at FROM sessions WHERE guild_id = ? AND user_id = ? AND bypass != '[]' "
                                 "AND state IN ('open', 'signed_in') AND expires_at > ?", (guild_id, user_id, time.time()))

    async def session(self, token: str) -> dict | None:
        row = await self.db.one("SELECT * FROM sessions WHERE token_hash = ?", (token_hash(token),))
        if row is None:
            return None
        row["bypass"] = json.loads(row["bypass"])
        row["account"] = json.loads(row["account"]) if row["account"] else None
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
        mode = core["mode"]
        if mode == WEB or await self._live_bypass(guild_id, user_id):
            url, _ = await self.new_link(guild_id, user_id, document)
            return url
        if mode == INSTANT:
            return Result("problem", "Rejoin to verify", "This server checks members when they join. Leave and rejoin to try again.")
        return await self.run_quick(member, mode)

    async def run_quick(self, member: MemberInfo, mode: str) -> Result:
        """Button and instant modes: only what Discord itself can tell us."""
        guild_id = member.guild_id
        document = await self.get_settings(guild_id)
        rules = await self.effective(guild_id, document)
        record = await self._prepared_member(guild_id, member.user_id, rules)
        account = engine.Account(member.user_id, member.username, member.avatar)
        decision = engine.run_checks(engine.Attempt(rules, mode, account, record), self.regions)
        return await self._conclude(guild_id, rules, account, decision, mode=mode, session=None, started=None)

    async def _prepared_member(self, guild_id: str, user_id: str, rules: dict) -> dict:
        """Load a member, giving back their attempts if the server's reset time has passed."""
        await self.db.touch_member(guild_id, user_id)
        record = await self.db.member(guild_id, user_id)
        limit = rules["checks"]["max_attempts"]
        reset = limit["reset_minutes"]
        if reset and record["limit_reached_at"] and time.time() >= record["limit_reached_at"] + reset * 60:
            await self.db.update_member(guild_id, user_id, fails=0, limit_reached_at=None)
            record = await self.db.member(guild_id, user_id)
        return record

    async def attach_account(self, token: str, account: dict) -> str | None:
        """Save the sign-in result on the session. Returns an error key, or None if it's fine."""
        row = await self.session(token)
        if row is None or row["expires_at"] <= time.time() or row["state"] in ("done", "closed"):
            return "link_expired"
        if account["id"] != row["user_id"]:
            return "wrong_account"
        await self.db.run("UPDATE sessions SET account = ?, state = 'signed_in', opened_at = COALESCE(opened_at, ?) WHERE token_hash = ?",
                          (json.dumps(account), time.time(), token_hash(token)))
        if row["opened_at"] is None:
            await self.db.add_attempt(row["guild_id"], row["user_id"], "started", mode=WEB)
        await self.db.touch_member(row["guild_id"], row["user_id"], username=account.get("username"), avatar=account.get("avatar"))
        return None

    async def issue_challenge(self, token: str) -> dict | None:
        row = await self.session(token)
        if row is None or row["state"] != "signed_in" or row["expires_at"] <= time.time():
            return None
        nonce, salt = new_token(16), new_token(12)
        await self.db.run("UPDATE sessions SET nonce = ?, pow_salt = ?, pow_bits = ? WHERE token_hash = ?",
                          (nonce, salt, POW_BITS, token_hash(token)))
        return {"nonce": nonce, "salt": salt, "bits": POW_BITS}

    async def claim_submission(self, token: str, nonce: str) -> dict | None:
        """Take a session for one submission. A second submission with the same nonce finds nothing."""
        changed = await self.db.run(
            "UPDATE sessions SET nonce = NULL, state = 'checking' WHERE token_hash = ? AND state = 'signed_in' AND nonce = ? AND expires_at > ?",
            (token_hash(token), nonce, time.time()))
        return await self.session(token) if changed else None

    async def release(self, token: str) -> None:
        """Hand a session back after a failure, so one crash can't strand a member's link."""
        await self.db.run("UPDATE sessions SET state = 'signed_in' WHERE token_hash = ? AND state = 'checking'", (token_hash(token),))

    async def submit_web(self, token: str, row: dict, report: dict, *, ip: str, headers: dict, device_id: str | None) -> Result:
        """Web mode: account, network and browser together."""
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
        if await self.port.member(guild_id, user_id) is None:
            await self.release(token)
            return Result("problem", "You're not in the server", "Rejoin the server, then verify again.", reason="left_server", help_slug="left-server")
        rules = await self.effective(guild_id, document)
        if not self.net.ready and not rules["core"]["fail_open"]:
            await self.db.run("UPDATE sessions SET state = 'signed_in' WHERE token_hash = ?", (token_hash(token),))
            return Result("problem", "Try again in a moment", "The connection check isn't available right now.",
                          reason="connection_check", help_slug="connection-check", retry=True)
        record = await self._prepared_member(guild_id, user_id, rules)
        stored = row["account"]
        account = engine.Account(user_id, stored.get("username", ""), stored.get("avatar"), stored.get("mfa"),
                                 stored.get("email_verified"), stored.get("email_disposable"))
        net = self.net.lookup(ip)
        if rules["core"]["external_vpn_lookup"] and self.proxycheck is not None:
            answer = await self.proxycheck(ip)
            if answer and answer.get("proxy") == "yes":
                net.vpn = True
        verdict = signals.evaluate(report, headers)
        zone = report.get("tz", {}).get("name") if isinstance(report.get("tz"), dict) else None
        expected = self.zone_countries.get(zone)
        mismatch = bool(expected and net.country and net.country not in expected and not net.anonymized)
        suspect, hits = signals.suspect_score(verdict, net, account_days=account.age_days, has_avatar=bool(account.avatar),
                                              disposable=account.email_disposable is True, timezone_mismatch=mismatch)
        connection = report.get("conn") if isinstance(report.get("conn"), dict) else {}
        digests = self._digests(guild_id, ip, device_id, verdict)
        profile = self._profile(guild_id, verdict)
        privacy = rules["privacy"]
        methods = rules["checks"]["alt_account"]["methods"]
        links = await altmatch.find_links(self.db, guild_id, user_id, digests, methods=methods, weak_fingerprint=verdict.weak_fingerprint,
                                          weak_ip=net.shared or net.anonymized or net.reserved)
        for link in links:
            if not link.banned and await self.port.is_banned(guild_id, link.other_id):
                link.banned = True
                await self.db.record_ban(guild_id, link.other_id, keep_days=privacy["banned_days"])
        await altmatch.compare_profiles(self.db, guild_id, links, profile)
        attempt = engine.Attempt(rules, WEB, account, record, net, verdict, links, suspect, hits,
                                 cellular=connection.get("type") == "cellular", bypass=frozenset(row["bypass"]))
        decision = engine.run_checks(attempt, self.regions)
        if decision.cooldown_left <= 0:
            await self._store_digests(guild_id, user_id, {**digests, **profile}, privacy)
        result = await self._conclude(guild_id, rules, account, decision, mode=WEB, session=row, started=row["opened_at"])
        # "closed" means the link is spent without a pass, so the page can't claim the member got in.
        final = "done" if result.status == "verified" else "closed" if result.action in (KICK, BAN) else "signed_in"
        await self.db.run("UPDATE sessions SET state = ?, finished_at = ? WHERE token_hash = ?", (final, time.time(), token_hash(token)))
        return result

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
                        session: dict | None, started: float | None) -> Result:
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
            if problem:
                await self._log(guild_id, rules, ["general"], notices.staff_log(
                    "Couldn't give the verified role", f"<@{user_id}> passed, but: {problem}", notices.RED))
                too_low = problem == ROLE_TOO_LOW
                return Result("problem", "Almost there", "You passed, but the server's roles need fixing. Staff have been told.",
                              reason="role_too_low" if too_low else "role_problem",
                              help_slug="role-too-low" if too_low else "role-problem", retry=True)
            await self.db.add_attempt(guild_id, user_id, "passed", mode=mode, seconds=seconds, bypassed=bool(bypassed),
                                      detail=_attempt_detail(decision, bypassed))
            main_note = await self._act_on_link(guild_id, rules, user_id, decision, guild_name)
            await self.db.update_member(guild_id, user_id, status="verified", method=mode, verified_at=time.time(), kick_at=None,
                                        fails=0, limit_reached_at=None)
            await self._close_help_thread(guild_id, rules, user_id)
            if mode != INSTANT or rules["core"]["auto_dm"]:
                await self.port.dm(user_id, notices.verified_notice(guild_name))
            modules = ["success"] + [finding.check_id for finding in decision.findings]
            await self._log(guild_id, rules, modules, notices.attempt_log(
                user_id, account.username, avatar_url, decision, took="Verified" + main_note, bypassed=bypassed, mode=mode),
                alert_for=[finding.check_id for finding in decision.findings])
            await self._emit(guild_id, "member.verified", {"user_id": user_id, "mode": mode,
                                                           "watched": [finding.check_id for finding in decision.findings]})
            return Result("verified", "You're verified", f"You now have access to {guild_name}.")

        primary = decision.primary
        action = decision.action
        await self.db.add_attempt(guild_id, user_id, "failed", check_id=primary.check_id, action=action, mode=mode, seconds=seconds,
                                  bypassed=bool(bypassed), detail=_attempt_detail(decision, bypassed))
        record = await self.db.member(guild_id, user_id)
        fails = (record["fails"] if record else 0) + 1
        now = time.time()
        await self.db.update_member(guild_id, user_id, fails=fails, last_fail_at=now)
        limit = rules["checks"]["max_attempts"]
        if limit["enabled"] and fails >= limit["attempts"] and not (record or {}).get("limit_reached_at"):
            await self.db.update_member(guild_id, user_id, limit_reached_at=now)
            if limit["role"] and limit["action"] in (WATCH, DENY):
                await self.port.add_role(guild_id, user_id, limit["role"], "Reached the attempt limit")

        appeals_on = rules["appeals"]["enabled"]
        appeal_url = f"{self.public_url}/appeal/{guild_id}" if appeals_on else None
        text = primary.message
        await self.port.dm(user_id, notices.failed_notice(guild_name, primary.reason, text, action, self.public_url, None,
                                                          appeal_url, rules["core"]["show_reason"], primary.retry_at))
        took = {DENY: "Denied", KICK: "Kicked", BAN: "Banned"}[action]
        reason_text = f"AltWarden: {notices.check_name(primary.check_id)}"
        if action == KICK and not await self.port.kick(guild_id, user_id, reason_text):
            took += " (failed: missing permission)"
        elif action == BAN:
            if await self.port.ban(guild_id, user_id, reason_text):
                await self.db.record_ban(guild_id, user_id, by_altwarden=True, keep_days=rules["privacy"]["banned_days"])
            else:
                took += " (failed: missing permission)"
        took += await self._act_on_link(guild_id, rules, user_id, decision, guild_name)
        modules = [finding.check_id for finding in decision.findings]
        await self._log(guild_id, rules, modules, notices.attempt_log(user_id, account.username, avatar_url, decision, took=took,
                                                                      bypassed=bypassed, mode=mode), alert_for=modules)
        await self._emit(guild_id, "member.failed", {"user_id": user_id, "check": primary.check_id, "action": action,
                                                     "checks": modules})
        show = rules["core"]["show_reason"]
        return Result("failed", "You weren't verified", text if show else "You didn't pass this server's checks.",
                      reason=primary.reason if show else None, action=action,
                      help_slug=HELP_SLUG.get(primary.reason) if show else "verification",
                      retry=action == DENY, appeal=appeals_on, template=FAILURE_TEXT[primary.reason] if show else None,
                      args=primary.text_args if show else None, retry_on=primary.retry_at if show else None,
                      staff_help=rules["core"]["help_desk"]["enabled"] and rules["core"]["help_desk"]["redirect"])

    async def _grant(self, guild_id: str, rules: dict, user_id: str, reason: str) -> str | None:
        core = rules["core"]
        problem = await self.port.add_role(guild_id, user_id, core["verified_role"], reason)
        if problem:
            return problem
        if core["unverified_enabled"] and core["unverified_role"]:
            await self.port.remove_role(guild_id, user_id, core["unverified_role"], reason)
        return None

    async def _act_on_link(self, guild_id: str, rules: dict, user_id: str, decision: engine.Decision, guild_name: str) -> str:
        """Record a matched pair, then apply the server's action to the earlier account. Returns a note for the log."""
        link = decision.alt_link
        if link is None:
            return ""
        await altmatch.assign_roles(self.db, guild_id, user_id, link)
        main, alt = (link.other_id, user_id) if link.other_is_main else (user_id, link.other_id)
        await self.db.run("INSERT OR REPLACE INTO links VALUES (?, ?, ?, ?, ?, ?, ?)",
                          (guild_id, main, alt, link.confidence, link.score, json.dumps(link.methods), time.time()))
        action = decision.main_action
        if action not in (KICK, BAN) or main == user_id:
            return ""
        await self.port.dm(main, notices.failed_notice(guild_name, "alt_account", FAILURE_TEXT["alt_account"], action, self.public_url,
                                                       None, None, rules["core"]["show_reason"]))
        reason = f"AltWarden: main account of <{user_id}>"
        if action == KICK:
            done = await self.port.kick(guild_id, main, reason)
        else:
            done = await self.port.ban(guild_id, main, reason)
            if done:
                await self.db.record_ban(guild_id, main, by_altwarden=True, keep_days=rules["privacy"]["banned_days"])
        if not done:
            return ", couldn't act on the earlier account"
        return f", earlier account {'kicked' if action == KICK else 'banned'}"

    async def _end_thread(self, guild_id: str, rules: dict, user_id: str, thread_id: str, why: str) -> None:
        await self.db.update_member(guild_id, user_id, help_thread_id=None)
        await self._log(guild_id, rules, ["help_desk"], notices.staff_log("Help thread closed", f"<#{thread_id}> closed: {why}."))
        await self.port.close_thread(thread_id)

    async def _close_help_thread(self, guild_id: str, rules: dict, user_id: str) -> None:
        record = await self.db.member(guild_id, user_id)
        if record and record["help_thread_id"] and rules["core"]["help_desk"]["auto_close"]:
            await self._end_thread(guild_id, rules, user_id, record["help_thread_id"], f"<@{user_id}> verified")

    # --- staff actions ----------------------------------------------------------------------

    async def manual_verify(self, guild_id: str, user_id: str, actor_id: str, actor_name: str = "") -> str | None:
        document = await self.get_settings(guild_id)
        problem = await self._grant(guild_id, document, user_id, f"Verified by staff ({actor_name or actor_id})")
        if problem:
            return problem
        await self.db.touch_member(guild_id, user_id)
        await self.db.update_member(guild_id, user_id, status="verified", method="staff", verified_at=time.time(), kick_at=None,
                                    fails=0, limit_reached_at=None)
        await self.db.add_attempt(guild_id, user_id, "manual", mode="staff", detail={"by": actor_id})
        await self.db.add_audit(guild_id, "manual_verify", actor_id=actor_id, actor_name=actor_name, detail={"user": user_id})
        await self._close_help_thread(guild_id, document, user_id)
        await self._log(guild_id, document, ["general"], notices.staff_log("Member verified", f"<@{actor_id}> verified <@{user_id}>."))
        await self._emit(guild_id, "member.verified", {"user_id": user_id, "mode": "staff"})
        return None

    async def reset_member(self, guild_id: str, user_id: str, actor_id: str, actor_name: str = "") -> bool:
        """Clear a member's records here, so they verify again. Returns whether they were told."""
        document = await self.get_settings(guild_id)
        core = document["core"]
        await self.db.run("DELETE FROM attempts WHERE guild_id = ? AND user_id = ?", (guild_id, user_id))
        await self.db.run("DELETE FROM identifiers WHERE guild_id = ? AND user_id = ?", (guild_id, user_id))
        await self.db.run("DELETE FROM links WHERE guild_id = ? AND (main_id = ? OR alt_id = ?)", (guild_id, user_id, user_id))
        await self.db.run("DELETE FROM sessions WHERE guild_id = ? AND user_id = ?", (guild_id, user_id))
        await self.db.touch_member(guild_id, user_id)
        await self.db.update_member(guild_id, user_id, status="pending", method=None, verified_at=None, fails=0, last_fail_at=None,
                                    limit_reached_at=None)
        member = await self.port.member(guild_id, user_id)
        told = False
        if member is not None:
            await self.port.remove_role(guild_id, user_id, core["verified_role"], "Verification reset by staff")
            limit_role = document["checks"]["max_attempts"]["role"]
            if limit_role:
                await self.port.remove_role(guild_id, user_id, limit_role, "Verification reset by staff")
            instant = core["mode"] == INSTANT
            if core["unverified_enabled"] and core["unverified_role"] and not instant:
                await self.port.add_role(guild_id, user_id, core["unverified_role"], "Verification reset by staff")
            if core["auto_dm"]:
                guild = await self.port.guild(guild_id)
                url = None
                if core["mode"] == WEB:
                    url, _ = await self.new_link(guild_id, user_id, document)
                told = await self.port.dm(user_id, notices.reset_notice(guild.name if guild else "this server", url, core["channel"], instant))
                if not told and core["notify_closed_dms"]["enabled"] and core["channel"] and not instant:
                    told = bool(await self.port.send(core["channel"], notices.closed_dms_notice(user_id, core["notify_closed_dms"]["seconds"])))
        await self.db.add_audit(guild_id, "reset", actor_id=actor_id, actor_name=actor_name, detail={"user": user_id})
        await self._log(guild_id, document, ["general"], notices.staff_log("Verification reset", f"<@{actor_id}> reset <@{user_id}>."))
        return told

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
        await self.db.update_member(guild_id, user_id, kick_at=None)
        guild = await self.port.guild(guild_id)
        name = guild.name if guild else "this server"
        told = False
        if notify in ("dm", "both"):
            told = await self.port.dm(user_id, notices.link_notice(name, url, minutes=minutes, kick_minutes=None, bypass=True))
        verify_channel = document["core"]["channel"]
        where = channel_id or verify_channel
        if notify in ("channel", "both") and where:
            # The link never goes in a channel. Pressing Verify hands the member a link that keeps these skips.
            posted = await self.port.send(where, Notice(content=f"<@{user_id}> staff made a verification link for you. Check your DMs, "
                                                                f"or press **Verify** in <#{verify_channel}> to get it.", mention_users=[user_id]))
            told = told or bool(posted)
        await self.db.add_audit(guild_id, "bypass", actor_id=actor_id, actor_name=actor_name,
                                detail={"user": user_id, "skip": allowed, "hours": hours})
        await self._log(guild_id, document, ["general"], notices.staff_log(
            "Bypass link created", f"<@{actor_id}> created a link for <@{user_id}>. It expires <t:{int(time.time() + hours * 3600)}:f>.",
            notices.AMBER, fields=[{"name": "Skips", "value": ", ".join(notices.check_name(check) for check in allowed) or "Nothing", "inline": False}]))
        return url, told

    async def import_members(self, guild_id: str, user_ids: list, actor_id: str, actor_name: str = "") -> int:
        """Mark members who already hold access as verified, so a switch from another bot asks nothing of them."""
        now = time.time()
        count = 0
        for user_id in user_ids:
            await self.db.touch_member(guild_id, user_id)
            record = await self.db.member(guild_id, user_id)
            if record["status"] != "verified":
                await self.db.update_member(guild_id, user_id, status="verified", method="imported", verified_at=now, kick_at=None)
                count += 1
        document = await self.get_settings(guild_id)
        await self.db.add_audit(guild_id, "import_members", actor_id=actor_id, actor_name=actor_name, detail={"count": count})
        await self._log(guild_id, document, ["general"], notices.staff_log(
            "Members imported", f"<@{actor_id}> marked {count} existing members as verified."))
        return count

    # --- events from Discord ----------------------------------------------------------------

    async def on_ban(self, guild_id: str, user_id: str) -> None:
        document = await self.get_settings(guild_id)
        if document is not None:
            await self.db.record_ban(guild_id, user_id, keep_days=document["privacy"]["banned_days"])

    async def on_unban(self, guild_id: str, user_id: str) -> None:
        await self.db.clear_ban(guild_id, user_id)

    async def on_leave(self, guild_id: str, user_id: str) -> None:
        await self.db.run("UPDATE members SET kick_at = NULL WHERE guild_id = ? AND user_id = ?", (guild_id, user_id))
        record = await self.db.member(guild_id, user_id)
        if record and record["help_thread_id"]:
            rules = await self.get_settings(guild_id) or settings_module.defaults()
            await self._end_thread(guild_id, rules, user_id, record["help_thread_id"], f"<@{user_id}> left the server")

    async def honeypot_hit(self, guild_id: str, user_id: str, username: str, channel_id: str, message_id: str, *,
                           role_ids: tuple, is_webhook: bool = False, parent_id: str | None = None) -> None:
        """A post in the trap, or in a thread under it. The message always goes, and the author is acted on once."""
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
        action = "log" if is_webhook else pot["action"]
        reason = "AltWarden: posted in the honeypot channel"
        took = {"log": "Logged", "timeout": "Timed out", "kick": "Kicked", "softban": "Softbanned", "ban": "Banned"}[action]
        done = True
        if action == "timeout":
            done = await self.port.timeout(guild_id, user_id, pot["timeout_minutes"], reason)
        elif action == "kick":
            done = await self.port.kick(guild_id, user_id, reason)
        elif action == "ban":
            done = await self.port.ban(guild_id, user_id, reason, delete_seconds=3600)
        elif action == "softban":
            done = await self.port.ban(guild_id, user_id, reason, delete_seconds=3600)
            if done:
                await self.port.unban(guild_id, user_id, reason)
        await self.db.add_attempt(guild_id, user_id, "honeypot", action=action, detail={})
        await self._log(guild_id, document, ["honeypot"], notices.staff_log(
            "Honeypot triggered", f"{'A webhook' if is_webhook else f'<@{user_id}>'} posted in <#{channel_id}>. {took}{'' if done else ' (failed: missing permission)'}."
            + ("" if deleted else " The message is still there, because AltWarden needs Manage Messages in that channel."),
            notices.RED))

    # --- help desk --------------------------------------------------------------------------

    async def open_help(self, member: MemberInfo) -> tuple[str | None, str]:
        """Open or find a member's help thread. Returns its ID, or None, and a message for them."""
        guild_id, user_id = member.guild_id, member.user_id
        document = await self.get_settings(guild_id)
        desk = document["core"]["help_desk"]
        if not desk["enabled"]:
            return None, "The help desk is off in this server."
        await self.db.touch_member(guild_id, user_id, username=member.username, avatar=member.avatar)
        record = await self.db.member(guild_id, user_id)
        if record["help_thread_id"]:
            if await self.port.reopen_thread(record["help_thread_id"]):
                return record["help_thread_id"], f"Your help thread is <#{record['help_thread_id']}>."
            await self.db.update_member(guild_id, user_id, help_thread_id=None)  # Someone deleted it, so start a new one.
        attempts = await self.db.all("SELECT check_id, at FROM attempts WHERE guild_id = ? AND user_id = ? AND outcome = 'failed' ORDER BY at DESC LIMIT 10",
                                     (guild_id, user_id))
        if desk["require_attempt"] and not attempts:
            return None, "Try verifying first. If it fails, press this button again."
        guild = await self.port.guild(guild_id)
        first = notices.plain_message(document["messages"]["help_desk"], guild.name if guild else "this server", self.public_url)
        if attempts:
            first.embeds.append({"title": "Verification records", "color": notices.GRAY, "description": "\n".join(
                f"<t:{int(row['at'])}:R> {notices.check_name(row['check_id'])}" for row in attempts)})
        first.buttons.append(_close_button())
        thread_id = await self.port.open_help_thread(document["core"]["channel"], member.username or user_id, user_id,
                                                      desk["support_role"], first)
        if thread_id is None:
            await self._log(guild_id, document, ["help_desk"], notices.staff_log(
                "Help desk can't open threads", "AltWarden is missing a permission in the verification channel.", notices.RED))
            return None, "The help desk can't open a thread right now. Staff have been told."
        await self.db.update_member(guild_id, user_id, help_thread_id=thread_id)
        await self._log(guild_id, document, ["help_desk"], notices.staff_log("Help thread opened", f"<@{user_id}> opened <#{thread_id}>."))
        return thread_id, f"Your help thread is <#{thread_id}>."

    async def close_help(self, guild_id: str, thread_id: str, actor: MemberInfo) -> tuple[bool, str]:
        document = await self.get_settings(guild_id)
        desk = document["core"]["help_desk"]
        owner = await self.db.one("SELECT user_id FROM members WHERE guild_id = ? AND help_thread_id = ?", (guild_id, thread_id))
        is_staff = desk["support_role"] in actor.role_ids or "manage_threads" in actor.permissions or actor.is_owner
        is_opener = owner is not None and owner["user_id"] == actor.user_id
        if not is_staff and not (is_opener and desk["member_close"]):
            return False, "Only staff can close this thread."
        if owner:
            await self.db.update_member(guild_id, owner["user_id"], help_thread_id=None)
        await self._log(guild_id, document, ["help_desk"], notices.staff_log("Help thread closed", f"<@{actor.user_id}> closed <#{thread_id}>."))
        await self.port.close_thread(thread_id)
        return True, "Closed."

    # --- appeals ----------------------------------------------------------------------------

    async def submit_appeal(self, guild_id: str, user_id: str, username: str, text: str) -> str | None:
        """Returns an error message, or None when the appeal reached staff."""
        document = await self.get_settings(guild_id)
        if document is None or not document["appeals"]["enabled"]:
            return "This server doesn't take appeals."
        text = text.strip()[:MAX_APPEAL_CHARS]
        if len(text) < 10:
            return "Please explain what happened in a sentence or two."
        last = await self.db.one("SELECT check_id, at FROM attempts WHERE guild_id = ? AND user_id = ? AND outcome = 'failed' ORDER BY at DESC LIMIT 1",
                                 (guild_id, user_id))
        if last is None or time.time() - last["at"] > APPEAL_WINDOW:
            return "There is no recent failed attempt to appeal."
        if await self.db.scalar("SELECT 1 FROM appeals WHERE guild_id = ? AND user_id = ? AND status = 'open'", (guild_id, user_id)):
            return "You already have an appeal waiting."
        appeal_id = await self.db.insert("INSERT INTO appeals (guild_id, user_id, check_id, text, created_at) VALUES (?, ?, ?, ?, ?)",
                                         (guild_id, user_id, last["check_id"], text, time.time()))
        card = notices.appeal_card(appeal_id, user_id, username, last["check_id"], text)
        appeals = document["appeals"]
        target = appeals["channel"] or document["core"]["logs"]["modules"].get("appeals") or document["core"]["logs"]["modules"].get("general")
        if appeals["role"]:
            card.content = f"<@&{appeals['role']}>"
            card.mention_roles = [appeals["role"]]
        if target:
            message_id = await self.port.send(target, card)
            await self.db.run("UPDATE appeals SET channel_id = ?, message_id = ? WHERE id = ?", (target, message_id, appeal_id))
        await self._emit(guild_id, "appeal.opened", {"user_id": user_id, "appeal": appeal_id})
        return None

    async def decide_appeal(self, guild_id: str, appeal_id: int, decision: str, actor_id: str, actor_name: str = "",
                            note: str | None = None) -> str | None:
        appeal = await self.db.one("SELECT * FROM appeals WHERE id = ? AND guild_id = ?", (appeal_id, guild_id))
        if appeal is None:
            return "That appeal doesn't exist."
        if appeal["status"] != "open":
            return "That appeal was already decided."
        document = await self.get_settings(guild_id)
        user_id = appeal["user_id"]
        approved = decision in ("approve", "trust")
        await self.db.run("UPDATE appeals SET status = ?, decided_by = ?, decided_at = ?, note = ? WHERE id = ?",
                          ("approved" if approved else "denied", actor_id, time.time(), note, appeal_id))
        if approved:
            if await self.db.is_banned(guild_id, user_id):
                await self.port.unban(guild_id, user_id, f"Appeal approved by {actor_name or actor_id}")
                await self.db.clear_ban(guild_id, user_id)
            await self.db.touch_member(guild_id, user_id)
            if await self.port.member(guild_id, user_id) is not None:
                await self.manual_verify(guild_id, user_id, actor_id, actor_name)
            else:
                await self.db.update_member(guild_id, user_id, status="approved")
            if decision == "trust":
                rows = await self.db.all("SELECT main_id, alt_id FROM links WHERE guild_id = ? AND (main_id = ? OR alt_id = ?)", (guild_id, user_id, user_id))
                for row in rows:
                    await self.db.trust_pair(guild_id, row["main_id"], row["alt_id"], actor_id)
        guild = await self.port.guild(guild_id)
        await self.port.dm(user_id, notices.appeal_result_notice(guild.name if guild else "this server", approved, note))
        await self.db.add_audit(guild_id, "appeal", actor_id=actor_id, actor_name=actor_name,
                                detail={"appeal": appeal_id, "user": user_id, "decision": decision})
        if appeal["channel_id"] and appeal["message_id"]:
            verdict = {"approve": "Approved", "trust": "Approved, link trusted", "deny": "Turned down"}[decision]
            await self.port.edit_message(appeal["channel_id"], appeal["message_id"], Notice(embeds=[{
                "title": f"Appeal: {verdict}", "description": appeal["text"][:1500],
                "color": notices.GREEN if approved else notices.GRAY,
                "fields": [{"name": "Account", "value": f"<@{user_id}>", "inline": True},
                           {"name": "Decided by", "value": f"<@{actor_id}>", "inline": True}]}]))
        await self._emit(guild_id, "appeal.decided", {"user_id": user_id, "appeal": appeal_id, "decision": decision})
        return None

    # --- members' own data ------------------------------------------------------------------

    async def my_data(self, user_id: str) -> list[dict]:
        """Everything held about one person, per server, in words."""
        rows = await self.db.all("SELECT * FROM members WHERE user_id = ?", (user_id,))
        result = []
        for row in rows:
            guild_id = row["guild_id"]
            kinds = await self.db.all("SELECT kind, COUNT(*) AS count, MAX(expires_at) AS expires_at FROM identifiers "
                                      "WHERE guild_id = ? AND user_id = ? GROUP BY kind", (guild_id, user_id))
            attempts = await self.db.all("SELECT at, outcome, check_id, action, mode FROM attempts WHERE guild_id = ? AND user_id = ? ORDER BY at DESC LIMIT 200",
                                         (guild_id, user_id))
            appeals = await self.db.all("SELECT created_at, status, text, note FROM appeals WHERE guild_id = ? AND user_id = ? ORDER BY created_at DESC", (guild_id, user_id))
            # Links are counted and never named, because the other account is someone else's data.
            links = await self.db.scalar("SELECT COUNT(*) FROM links WHERE guild_id = ? AND (main_id = ? OR alt_id = ?)", (guild_id, user_id, user_id))
            guild = await self.port.guild(guild_id)
            result.append({"guild_id": guild_id, "guild_name": guild.name if guild else "A server", "status": row["status"],
                           "verified_at": row["verified_at"], "method": row["method"], "stored_hashes": kinds, "attempts": attempts,
                           "appeals": appeals, "linked_accounts": links, "banned": await self.db.is_banned(guild_id, user_id)})
        return result

    async def delete_my_data(self, user_id: str, guild_id: str | None = None) -> dict:
        """Delete a person's records. Hashes tied to an active ban stay until the ban ends or expires.

        Without that one exception, a banned account could erase the only thing that catches its
        next account. The privacy page states this.
        """
        rows = await self.db.all("SELECT guild_id FROM members WHERE user_id = ?" + (" AND guild_id = ?" if guild_id else ""),
                                 (user_id, guild_id) if guild_id else (user_id,))
        kept, removed = [], []
        for row in rows:
            target = row["guild_id"]
            document = await self.get_settings(target)
            banned = await self.db.is_banned(target, user_id)
            await self.db.run("DELETE FROM attempts WHERE guild_id = ? AND user_id = ?", (target, user_id))
            await self.db.run("DELETE FROM appeals WHERE guild_id = ? AND user_id = ?", (target, user_id))
            await self.db.run("DELETE FROM sessions WHERE guild_id = ? AND user_id = ?", (target, user_id))
            await self.db.run("DELETE FROM links WHERE guild_id = ? AND (main_id = ? OR alt_id = ?)", (target, user_id, user_id))
            await self.db.run("DELETE FROM trusted_pairs WHERE guild_id = ? AND (first_id = ? OR second_id = ?)", (target, user_id, user_id))
            # Staff actions about this person go, and staff actions by this person lose their name.
            await self.db.run("DELETE FROM audit WHERE guild_id = ? AND kind != 'settings' AND detail LIKE ?", (target, f'%"{user_id}"%'))
            await self.db.run("UPDATE audit SET actor_id = NULL, actor_name = 'Deleted account' WHERE guild_id = ? AND actor_id = ?", (target, user_id))
            await self.db.run("UPDATE appeals SET decided_by = NULL WHERE guild_id = ? AND decided_by = ?", (target, user_id))
            await self.db.run("UPDATE sessions SET bypass_by = NULL WHERE guild_id = ? AND bypass_by = ?", (target, user_id))
            await self.db.run("UPDATE attempts SET detail = '{}' WHERE guild_id = ? AND outcome = 'manual' AND detail LIKE ?", (target, f'%"{user_id}"%'))
            if document is not None and any(message.get("author") == user_id for message in document["messages"].values()):
                messages = {name: {**message, "author": None if message.get("author") == user_id else message.get("author")} for name, message in document["messages"].items()}
                await self.save_settings(target, {**document, "messages": messages})
            if banned:
                kept.append(target)
            else:
                await self.db.run("DELETE FROM identifiers WHERE guild_id = ? AND user_id = ?", (target, user_id))
                await self.db.run("DELETE FROM members WHERE guild_id = ? AND user_id = ?", (target, user_id))
                removed.append(target)
                if document is not None and await self.port.member(target, user_id) is not None:
                    await self.port.remove_role(target, user_id, document["core"]["verified_role"], "Member deleted their verification data")
                    if document["core"]["unverified_enabled"] and document["core"]["unverified_role"]:
                        await self.port.add_role(target, user_id, document["core"]["unverified_role"], "Member deleted their verification data")
        await self.db.run("DELETE FROM command_syncs WHERE user_id = ?", (user_id,))
        await self.db.run("DELETE FROM web_sessions WHERE user_id = ?", (user_id,))
        return {"removed": removed, "kept_for_ban": kept}

    # --- background work --------------------------------------------------------------------

    async def tick(self) -> None:
        """Run every minute: auto kicks and raid endings. Both read the database, so a restart loses neither."""
        now = time.time()
        for row in await self.db.all("SELECT guild_id, user_id FROM members WHERE kick_at IS NOT NULL AND kick_at <= ?", (now,)):
            await self._auto_kick(row["guild_id"], row["user_id"])
        for row in await self.db.all("SELECT guild_id FROM guilds WHERE raid_until > 0 AND raid_until <= ?", (now,)):
            document = await self.get_settings(row["guild_id"])
            await self.db.set_guild_field(row["guild_id"], "raid_until", 0)
            await self._log(row["guild_id"], document, ["raid", "general"], notices.staff_log("Raid mode ended", "Normal rules apply again.", notices.GREEN))

    async def _auto_kick(self, guild_id: str, user_id: str) -> None:
        await self.db.update_member(guild_id, user_id, kick_at=None)
        document = await self.get_settings(guild_id)
        record = await self.db.member(guild_id, user_id)
        if document is None or not document["core"]["auto_kick"]["enabled"] or record["status"] == "verified":
            return
        member = await self.port.member(guild_id, user_id)
        if member is None or document["core"]["verified_role"] in member.role_ids:
            return
        guild = await self.port.guild(guild_id)
        if document["core"]["auto_dm"]:
            await self.port.dm(user_id, notices.timed_out_notice(guild.name if guild else "the server"))
        kicked = await self.port.kick(guild_id, user_id, "AltWarden: didn't verify in time")
        await self.db.add_attempt(guild_id, user_id, "auto_kick", action="kick")
        await self._log(guild_id, document, ["auto_kick"], notices.staff_log(
            "Auto kick", f"<@{user_id}> didn't verify in time." + ("" if kicked else " The kick failed: missing permission."), notices.AMBER))

    async def purge(self) -> dict:
        rows = await self.db.all("SELECT guild_id FROM guilds")
        documents = {}
        for row in rows:
            document = await self.get_settings(row["guild_id"])
            if document is not None:
                documents[row["guild_id"]] = document
        return await self.db.purge_expired(documents)

    # --- logs and webhooks ------------------------------------------------------------------

    async def _log(self, guild_id: str, rules: dict, modules: list[str], embed: dict, *, alert_for: list | None = None,
                   alert_role: str | None = None) -> None:
        logs = rules["core"]["logs"]
        if not logs["enabled"]:
            return
        channels = list(dict.fromkeys(logs["modules"][name] for name in modules if name in logs["modules"]))
        if not channels:
            return
        alerts = rules["core"]["alerts"]
        roles = [alerts["roles"][name] for name in (alert_for or []) if alerts["enabled"] and name in alerts["roles"]]
        if alert_role:
            roles.append(alert_role)
        roles = list(dict.fromkeys(roles))
        content = " ".join(f"<@&{role}>" for role in roles)
        for channel_id in channels:
            await self.port.send(channel_id, Notice(content=content, embeds=[embed], mention_roles=roles))

    async def _emit(self, guild_id: str, event: str, payload: dict) -> None:
        if self.webhook_sender is not None:
            task = asyncio.ensure_future(self.webhook_sender(guild_id, event, payload))
            self._background.add(task)
            task.add_done_callback(self._background.discard)


def _attempt_detail(decision: engine.Decision, bypassed: list) -> dict:
    """What gets stored about an attempt. Labels and scores only, never a raw value."""
    return {"findings": [{"check": finding.check_id, "action": finding.action, "detail": finding.detail}
                         for finding in decision.findings], "bypassed": bypassed}


def _avatar_url(user_id: str, avatar: str | None) -> str | None:
    return f"https://cdn.discordapp.com/avatars/{user_id}/{avatar}.png?size=128" if avatar else None


def _short(value) -> str:
    text = json.dumps(value) if not isinstance(value, str) else value
    return text[:80]


def _close_button():
    from .ports import Button
    return Button("Close thread", custom_id="aw:help:close", style="secondary")
