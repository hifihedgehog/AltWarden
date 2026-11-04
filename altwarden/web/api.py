"""The dashboard's JSON API, plus the small read API for other bots.

Each call checks the same rule the Permissions page edits, so what a member can see in the
dashboard and what the API will do for them can't drift apart.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import math
import re
import socket
import time

import aiohttp
from aiohttp import web
from aiohttp.resolver import ThreadedResolver
from yarl import URL

from .. import access, analytics, catalog, health, notices, settings as settings_module
from ..crypto import new_token, token_hash
from ..engine import bypass_options
from ..ports import DiscordUnavailable, MemberInfo
from ..service import Service
from .app import ADMINISTRATOR, FLOW_COOKIE, FLOW_SECONDS, MANAGE_GUILD, SNOWFLAKE, STATIC, client_ip, csrf_ok, current_session, json_error, read_json, set_cookie

log = logging.getLogger("altwarden.api")

WEBHOOK_EVENTS = ("member.verified", "member.failed", "appeal.opened", "appeal.decided", "raid.started", "raid.ended")
MAX_WEBHOOKS = 5
MAX_API_KEYS = 5
BYPASS_NOTIFY = ("both", "dm", "channel", "none")
COMMAND_SCOPES = ["identify", "applications.commands.permissions.update"]
MAX_COMMAND_OVERRIDES = 100  # Discord's limit per command
COULD_NOT_POST = "Saved, but AltWarden couldn't post in that channel. Look at the Health page, then press Post it again on the Messages page."


class PublicResolver(ThreadedResolver):
    """Resolves webhook hosts and refuses any address outside the public internet.

    Checking at connection time, instead of when the webhook is saved, also stops a host name that
    later changes to point at this machine.
    """

    async def resolve(self, host: str, port: int = 0, family: socket.AddressFamily = socket.AF_INET) -> list:
        results = await super().resolve(host, port, family)
        public = [result for result in results if ipaddress.ip_address(result["host"]).is_global]
        if not public:
            raise OSError(f"{host} isn't a public address")
        return public


def webhook_problem(url: str) -> str | None:
    """Why this address can't take webhooks, or None. An IP literal skips the resolver, so it stops here."""
    try:
        parts = URL(url)
        host = (parts.raw_host or "").rstrip(".").lower()
    except (TypeError, ValueError):
        return "Use an https address with a public host name."
    if parts.scheme != "https" or not host or host == "localhost" or host.endswith((".localhost", ".local", ".internal", ".intranet")):
        return "Use an https address with a public host name."
    # A last label of digits or 0x hex is an address in disguise, such as 2130706433 or 127.1, and it
    # would reach the network without passing through the resolver's check.
    if re.fullmatch(r"\d+|0x[0-9a-f]*", host.rsplit(".", 1)[-1]):
        return "Use a host name, not an IP address."
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return None
    return "Use a host name, not an IP address."


def _gid(request: web.Request) -> str:
    return request.match_info["gid"]


def _whole(value, low: int, high: int, fallback: int) -> int:
    """A whole number from an untrusted request, kept in range."""
    try:
        return max(low, min(high, int(value)))
    except (TypeError, ValueError, OverflowError):
        return fallback


def _moment(value, fallback: float) -> float:
    """A timestamp from a query string. "nan" and "inf" parse as floats, so they need their own check."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return fallback
    return number if math.isfinite(number) and 0 <= number < 4e9 else fallback


async def _viewer(service: Service, session: dict, guild_id: str) -> access.Viewer | None:
    member = await service.port.member(guild_id, session["user_id"])
    if member is None:
        return None
    return access.Viewer(session["user_id"], frozenset(member.role_ids), member.permissions, member.is_owner)


async def _guard(request: web.Request, page: str, level: str = "view"):
    """Return (session, settings, viewer), or an error response. Writes also need the CSRF token."""
    session = await current_session(request)
    if session is None or session["scope"] != "dashboard":
        return json_error(401, "Sign in first.", login="/login")
    if request.method != "GET" and not csrf_ok(request, session):
        return json_error(403, "This request can't be trusted. Reload the page.")
    service: Service = request.app["service"]
    guild_id = _gid(request)
    viewer = await _viewer(service, session, guild_id)
    if viewer is None:
        return json_error(403, "You aren't in that server.")
    document = await service.get_settings(guild_id)
    if document is None:
        document = settings_module.defaults()
    # A page with nothing to edit has no edit rule, so it can't let anyone in that way.
    can_edit = "edit" in settings_module.PAGE_DEFAULTS.get(page, {}) and access.allowed(settings_module.page_rule(document, page, "edit"), viewer)
    if level == "edit" and not can_edit:
        return json_error(403, "You can view this page but not change it.")
    if level == "view" and not can_edit and not access.allowed(settings_module.page_rule(document, page, "view"), viewer):
        return json_error(403, "You don't have access to this page.")
    return session, document, viewer


def _rules_view(document: dict) -> dict:
    """The Rules page's copy of the settings. Who can do what belongs to the Access page, under its own rule."""
    return {key: value for key, value in document.items() if key != "permissions"}


def _pages_for(document: dict, viewer: access.Viewer) -> dict:
    result = {}
    for page, levels in settings_module.PAGE_DEFAULTS.items():
        can_edit = "edit" in levels and access.allowed(settings_module.page_rule(document, page, "edit"), viewer)
        can_view = can_edit or access.allowed(settings_module.page_rule(document, page, "view"), viewer)
        result[page] = {"view": can_view, "edit": can_edit}
    return result


async def me(request: web.Request) -> web.Response:
    session = await current_session(request)
    if session is None or session["scope"] != "dashboard":
        return json_error(401, "Sign in first.", login="/login")
    service: Service = request.app["service"]
    servers = []
    for guild in session["guilds"]:
        present = await service.port.guild(guild["id"]) is not None
        bits = int(guild["permissions"] or 0)
        can_invite = guild["owner"] or bool(bits & (ADMINISTRATOR | MANAGE_GUILD))
        reachable = False
        if present:
            try:
                viewer = await _viewer(service, session, guild["id"])
            except DiscordUnavailable:
                reachable = True  # one server's bad moment mustn't cost the whole list, and its own page says what's wrong
            else:
                if viewer is not None:
                    document = await service.get_settings(guild["id"]) or settings_module.defaults()
                    reachable = any(entry["view"] for entry in _pages_for(document, viewer).values())
        if reachable or can_invite:
            servers.append({"id": guild["id"], "name": guild["name"], "icon": guild["icon"], "present": present, "reachable": reachable})
    servers.sort(key=lambda item: (not item["present"], item["name"].lower()))
    client_id = request.app["oauth"].client_id
    return web.json_response({"user": {"id": session["user_id"], "name": session["username"], "avatar": session["avatar"]},
                              "csrf": session["csrf"], "guilds": servers, "invite": health.invite_url(client_id)})


async def catalog_view(request: web.Request) -> web.Response:
    return web.json_response({
        "groups": {key: {"name": name, "blurb": blurb} for key, (name, blurb) in catalog.GROUPS.items()},
        "checks": [{"id": check.id, "group": check.group, "name": check.name, "blurb": check.blurb, "modes": sorted(check.modes)}
                   for check in catalog.CHECKS],
        "actions": [{"id": action, "label": catalog.ACTION_LABEL[action], "blurb": catalog.ACTION_BLURB[action]} for action in catalog.ACTIONS],
        "honeypot_actions": list(catalog.HONEYPOT_ACTIONS),
        "presets": {name: {"label": table["label"], "blurb": table["blurb"]} for name, table in catalog.PRESETS.items()},
        "log_modules": [{"id": name, "name": catalog.EXTRA_LOG_MODULES.get(name) or catalog.BY_ID[name].name} for name in catalog.LOG_MODULES],
        "commands": list(settings_module.COMMAND_DEFAULTS),
        "pages": {page: list(levels) for page, levels in settings_module.PAGE_DEFAULTS.items()},
        "permissions": list(settings_module.PERMISSION_NAMES),
        "permission_labels": catalog.PERMISSION_LABELS,
        "webhook_events": list(WEBHOOK_EVENTS),
        "default_messages": settings_module.DEFAULT_MESSAGES,
        "name_fonts": [{"id": font, "name": name} for font, name in settings_module.NAME_FONTS.items()],
        "name_effects": [{"id": effect, "name": name, "colors": colors} for effect, (name, colors) in settings_module.NAME_EFFECTS.items()],
        "avatar_hex": settings_module.AVATAR_HEX,
    })


async def guild_view(request: web.Request) -> web.Response:
    guarded = await _any_page(request)
    if isinstance(guarded, web.Response):
        return guarded
    session, document, viewer = guarded
    service: Service = request.app["service"]
    guild_id = _gid(request)
    guild = await service.port.guild(guild_id)
    if guild is None:
        return json_error(404, "AltWarden isn't in that server.")
    row = await service.db.guild(guild_id)
    return web.json_response({
        "id": guild.id, "name": guild.name, "icon": guild.icon, "member_count": guild.member_count,
        "roles": guild.roles, "channels": guild.channels, "setup_done": bool(row and row["setup_done"]),
        "raid_until": row["raid_until"] if row else 0, "pages": _pages_for(document, viewer),
        "verifying_now": await analytics.verifying_now(service.db, guild_id),
        "healthy": health.report(guild, document)["healthy"] if row and row["setup_done"] else True,
        "avatar_colors": list(settings_module.AVATAR_COLORS),
        "help_desk": document["core"]["help_desk"]["enabled"],
    })


async def _any_page(request: web.Request):
    session = await current_session(request)
    if session is None or session["scope"] != "dashboard":
        return json_error(401, "Sign in first.", login="/login")
    service: Service = request.app["service"]
    viewer = await _viewer(service, session, _gid(request))
    if viewer is None:
        return json_error(403, "You aren't in that server.")
    document = await service.get_settings(_gid(request)) or settings_module.defaults()
    if not any(entry["view"] for entry in _pages_for(document, viewer).values()):
        return json_error(403, "You don't have access to this server.")
    return session, document, viewer


async def _no_guild(service: Service, guild_id: str) -> web.Response:
    """Why a server can't be read. Nothing is saved either way, because its roles and channels can't be checked."""
    if await service.port.guild_loading(guild_id):
        return json_error(503, "Discord is still loading this server, so nothing was saved. Try again in a moment.")
    return json_error(404, "AltWarden isn't in that server.")


async def setup(request: web.Request) -> web.Response:
    guarded = await _guard(request, "settings", "edit")
    if isinstance(guarded, web.Response):
        return guarded
    session, document, viewer = guarded
    service: Service = request.app["service"]
    body = await _body(request)
    updated = settings_module.normalize({**document, "core": {**document["core"], "verified_role": body.get("verified_role"),
                                                              "channel": body.get("channel")}})
    found = settings_module.problems(updated)
    if found:
        return json_error(400, found[0])
    guild = await service.port.guild(_gid(request))
    if guild is None:
        return await _no_guild(service, _gid(request))
    refused = health.role_refusals(guild, None, updated, viewer) + health.channel_refusals(guild, None, updated)
    if refused:
        return json_error(400, refused[0]["text"])
    await service.save_settings(_gid(request), updated, actor_id=session["user_id"], actor_name=session["username"], setup_done=True)
    posted = await request.app["post_message"](_gid(request), "verification")
    return web.json_response({"ok": True, "problem": None if posted is not False else COULD_NOT_POST})


async def settings_get(request: web.Request) -> web.Response:
    guarded = await _guard(request, "settings")
    if isinstance(guarded, web.Response):
        return guarded
    _, document, viewer = guarded
    return web.json_response({"settings": _rules_view(document), "paused": settings_module.paused_checks(document),
                              "can_edit": access.allowed(settings_module.page_rule(document, "settings", "edit"), viewer)})


async def settings_put(request: web.Request) -> web.Response:
    guarded = await _guard(request, "settings", "edit")
    if isinstance(guarded, web.Response):
        return guarded
    session, document, viewer = guarded
    service: Service = request.app["service"]
    guild_id = _gid(request)
    body = await _body(request)
    incoming = settings_module.normalize(body.get("settings"))
    # Only the Permissions page changes permissions, and only the Appearance page changes messages.
    incoming["permissions"] = document["permissions"]
    incoming["messages"] = document["messages"]
    incoming["appearance"] = document["appearance"]
    found = settings_module.problem_items(incoming)
    guild = await service.port.guild(guild_id)
    if guild is None:
        return await _no_guild(service, guild_id)
    found += health.role_refusals(guild, document, incoming, viewer) + health.channel_refusals(guild, document, incoming)
    if found:
        return json_error(400, found[0]["text"], problems=[entry["text"] for entry in found], items=found)
    before = json.dumps(document["core"]["channel"]), json.dumps(document["core"]["help_desk"]["enabled"])
    changes = await service.save_settings(guild_id, incoming, actor_id=session["user_id"], actor_name=session["username"])
    after = json.dumps(incoming["core"]["channel"]), json.dumps(incoming["core"]["help_desk"]["enabled"])
    posted = True
    if before != after:
        posted = await request.app["post_message"](guild_id, "verification") is not False
    old_pot, new_pot = document["honeypot"], incoming["honeypot"]
    if new_pot["enabled"] and (not old_pot["enabled"] or new_pot["channel"] != old_pot["channel"]):
        posted = await request.app["post_message"](guild_id, "honeypot") is not False and posted
    await service.warn_if_broken(guild_id, incoming, [module for module, old, new in (
        ("help_desk", document["core"]["help_desk"], incoming["core"]["help_desk"]), ("honeypot", old_pot, new_pot)) if old != new])
    return web.json_response({"ok": True, "changes": len(changes), "paused": settings_module.paused_checks(incoming),
                              "problem": None if posted else COULD_NOT_POST, "settings": _rules_view(await service.get_settings(guild_id))})


async def apply_preset(request: web.Request) -> web.Response:
    guarded = await _guard(request, "settings")
    if isinstance(guarded, web.Response):
        return guarded
    _, document, _ = guarded
    body = await _body(request)
    try:
        return web.json_response({"settings": _rules_view(settings_module.apply_preset(settings_module.normalize(body.get("settings", document)), body.get("preset")))})
    except ValueError:
        return json_error(400, "That preset doesn't exist.")


async def preview(request: web.Request) -> web.Response:
    guarded = await _guard(request, "settings")
    if isinstance(guarded, web.Response):
        return guarded
    service: Service = request.app["service"]
    body = await _body(request)
    return web.json_response(await analytics.preview(service.db, _gid(request), settings_module.normalize(body.get("settings")),
                                                     days=_whole(body.get("days"), 1, 90, 30)))


async def export_settings(request: web.Request) -> web.Response:
    guarded = await _guard(request, "settings")
    if isinstance(guarded, web.Response):
        return guarded
    return web.json_response({"code": settings_module.export_code(guarded[1])})


async def import_settings(request: web.Request) -> web.Response:
    guarded = await _guard(request, "settings", "edit")
    if isinstance(guarded, web.Response):
        return guarded
    _, document, _ = guarded
    body = await _body(request)
    try:
        return web.json_response({"settings": _rules_view(settings_module.import_code(document, str(body.get("code", ""))))})
    except ValueError as exc:
        return json_error(400, str(exc))


async def analytics_view(request: web.Request) -> web.Response:
    guarded = await _guard(request, "analytics")
    if isinstance(guarded, web.Response):
        return guarded
    service: Service = request.app["service"]
    now = time.time()
    end = _moment(request.query.get("to"), now)
    start = _moment(request.query.get("from"), now - 30 * 86400)
    if start >= end:
        return json_error(400, "The start date has to come before the end date.")
    zone = request.query.get("tz")
    data = await analytics.report(service.db, _gid(request), start, end, zone)
    data["verifying_now"] = await analytics.verifying_now(service.db, _gid(request))
    if request.query.get("compare") == "1":
        then_end = _moment(request.query.get("compare_to"), start)
        then_start = _moment(request.query.get("compare_from"), start - (end - start))
        data["previous"] = (await analytics.report(service.db, _gid(request), then_start, then_end, zone))["cards"]
    return web.json_response(data)


async def members_list(request: web.Request) -> web.Response:
    guarded = await _guard(request, "members")
    if isinstance(guarded, web.Response):
        return guarded
    service: Service = request.app["service"]
    guild_id = _gid(request)
    size = _whole(request.query.get("size"), 10, 50, 20)
    page = _whole(request.query.get("page"), 1, 1_000_000, 1)
    query = request.query.get("q", "").strip()
    status = request.query.get("status", "")
    where, args = "m.guild_id = ?", [guild_id]
    if query:
        where += " AND (m.user_id = ? OR m.username LIKE ? ESCAPE '\\')"
        args += [query, "%" + re.sub(r"([%_\\])", r"\\\1", query) + "%"]
    if status in ("verified", "pending", "approved"):
        where += " AND m.status = ?"
        args.append(status)
    total = (await service.db.read_all(f"SELECT COUNT(*) AS total FROM members m WHERE {where}", args))[0]["total"]
    rows = await service.db.read_all(
        f"SELECT m.user_id, m.username, m.avatar, m.status, m.method, m.verified_at, m.fails, "
        f"(SELECT MAX(at) FROM attempts a WHERE a.guild_id = m.guild_id AND a.user_id = m.user_id) AS last_at, "
        f"(SELECT check_id FROM attempts a WHERE a.guild_id = m.guild_id AND a.user_id = m.user_id AND a.outcome = 'failed' ORDER BY at DESC LIMIT 1) AS last_check "
        f"FROM members m WHERE {where} ORDER BY COALESCE(last_at, m.joined_at, 0) DESC LIMIT ? OFFSET ?", [*args, size, (page - 1) * size])
    await _add_results(service, guild_id, rows)
    return web.json_response({"total": total, "page": page, "size": size, "members": rows})


async def _add_results(service: Service, guild_id: str, rows: list[dict]) -> None:
    """Each member's results in one line of counts, such as Verified and 2 x VPN and proxy."""
    by_member: dict[str, list] = {row["user_id"]: [] for row in rows}
    row_marks = ",".join("?" * len(by_member))
    if by_member:
        counts = await service.db.all(
            f"SELECT user_id, outcome, check_id, COUNT(*) AS count, MAX(at) AS last FROM attempts WHERE guild_id = ? AND user_id IN ({row_marks}) "
            "AND outcome != 'started' GROUP BY user_id, outcome, check_id ORDER BY last DESC", [guild_id, *by_member])
        for entry in counts:
            by_member[entry["user_id"]].append({"outcome": entry["outcome"], "check": entry["check_id"], "count": entry["count"]})
    for row in rows:
        row["results"] = by_member[row["user_id"]]


async def member_detail(request: web.Request) -> web.Response:
    guarded = await _guard(request, "members")
    if isinstance(guarded, web.Response):
        return guarded
    service: Service = request.app["service"]
    guild_id, user_id = _gid(request), request.match_info["uid"]
    record = await service.db.member(guild_id, user_id)
    if record is None:
        return json_error(404, "That account has no records here.")
    attempts = await service.db.all("SELECT at, outcome, check_id, action, mode, seconds, bypassed, detail FROM attempts "
                                    "WHERE guild_id = ? AND user_id = ? ORDER BY at DESC LIMIT 100", (guild_id, user_id))
    for attempt in attempts:
        attempt["detail"] = json.loads(attempt["detail"])
    links = await service.db.all("SELECT main_id, alt_id, confidence, score, methods, at FROM links WHERE guild_id = ? AND (main_id = ? OR alt_id = ?)",
                                 (guild_id, user_id, user_id))
    for link in links:
        link["methods"] = json.loads(link["methods"])
    options = [{"id": check, "name": notices.check_name(check)} for check in bypass_options(guarded[1])]
    return web.json_response({"member": record, "attempts": attempts, "links": links, "bypass_options": options,
                              "banned": await service.db.is_banned(guild_id, user_id)})


async def member_action(request: web.Request) -> web.Response:
    guarded = await _guard(request, "members")
    if isinstance(guarded, web.Response):
        return guarded
    session, document, viewer = guarded
    service: Service = request.app["service"]
    guild_id, user_id, action = _gid(request), request.match_info["uid"], request.match_info["action"]
    command = {"verify": "verify-user", "reset": "reset-user", "bypass": "create-bypass", "trust": "trust-accounts"}.get(action)
    if command is None:
        raise web.HTTPNotFound()
    if not access.allowed(settings_module.command_rule(document, command), viewer):
        return json_error(403, "You don't have access to that action.")
    actor = (session["user_id"], session["username"])
    if action == "verify":
        problem = await service.manual_verify(guild_id, user_id, *actor)
        return json_error(400, problem) if problem else web.json_response({"ok": True})
    if action == "reset":
        return web.json_response({"ok": True, "told": await service.reset_member(guild_id, user_id, *actor)})
    body = await _body(request)
    if action == "bypass":
        member = await service.port.member(guild_id, user_id)
        if member is None:
            return json_error(400, "That person isn't in the server.")
        if member.is_bot:
            return json_error(400, "Bots don't verify.")
        if document["core"]["verified_role"] in member.role_ids:
            return json_error(400, "That member is already verified. Reset them first if they should verify again.")
        options = bypass_options(document)
        wanted = body.get("skip") if isinstance(body.get("skip"), list) else []
        skip = [check for check in wanted if check in options]
        if not skip:
            return json_error(400, "Pick at least one check to skip.")
        notify = body.get("notify") if body.get("notify") in BYPASS_NOTIFY else "dm"
        url, delivered = await service.create_bypass(guild_id, user_id, skip, _whole(body.get("hours"), 1, 168, 1), notify, *actor)
        return web.json_response({"ok": True, "url": url, "delivered": delivered})
    other = str(body.get("other", ""))
    if not re.fullmatch(r"\d{15,21}", other):
        return json_error(400, "That account ID isn't valid.")
    await service.db.trust_pair(guild_id, user_id, other, session["user_id"])
    await service.db.add_audit(guild_id, "trust", actor_id=actor[0], actor_name=actor[1], detail={"first": user_id, "second": other})
    return web.json_response({"ok": True})


async def health_view(request: web.Request) -> web.Response:
    guarded = await _guard(request, "health")
    if isinstance(guarded, web.Response):
        return guarded
    service: Service = request.app["service"]
    guild = await service.port.guild(_gid(request))
    if guild is None:
        return json_error(404, "AltWarden isn't in that server.")
    data = health.report(guild, guarded[1])
    data["lists_loaded"] = service.net.ready
    data["lists_missing"] = service.net.missing()
    data["checked_at"] = time.time()
    return web.json_response(data)


async def permissions_put(request: web.Request) -> web.Response:
    guarded = await _guard(request, "permissions", "edit")
    if isinstance(guarded, web.Response):
        return guarded
    session, document, _ = guarded
    service: Service = request.app["service"]
    body = await _body(request)
    updated = settings_module.normalize({**document, "permissions": body.get("permissions")})
    await service.save_settings(_gid(request), updated, actor_id=session["user_id"], actor_name=session["username"])
    return web.json_response({"ok": True, "permissions": updated["permissions"]})


async def permissions_get(request: web.Request) -> web.Response:
    guarded = await _guard(request, "permissions")
    if isinstance(guarded, web.Response):
        return guarded
    document = guarded[1]
    pages = {page: {level: settings_module.page_rule(document, page, level) for level in levels}
             for page, levels in settings_module.PAGE_DEFAULTS.items()}
    commands = {name: settings_module.command_rule(document, name) for name in settings_module.COMMAND_DEFAULTS}
    discord_side = await request.app["service"].port.command_permissions(_gid(request))
    return web.json_response({"pages": pages, "commands": commands, "discord": discord_side})


def clean_overrides(raw) -> list[dict]:
    """Overrides for Discord's command permissions, in the only shapes Discord accepts."""
    found: list[dict] = []
    seen = set()
    for entry in raw[:MAX_COMMAND_OVERRIDES] if isinstance(raw, list) else []:
        if not isinstance(entry, dict) or entry.get("type") not in ("role", "user", "channel"):
            continue
        target = str(entry.get("id", ""))
        if re.fullmatch(r"\d{15,21}", target) and (entry["type"], target) not in seen:
            seen.add((entry["type"], target))
            found.append({"type": entry["type"], "id": target, "allow": entry.get("allow") is True})
    return found


async def discord_permissions_start(request: web.Request) -> web.Response:
    """Hold the requested change, then send the person to Discord to approve it with their own account.

    Discord only takes these writes from a person's token, and the token is revoked as soon as the
    write is done, so none is ever stored.
    """
    guarded = await _guard(request, "permissions", "edit")
    if isinstance(guarded, web.Response):
        return guarded
    session = guarded[0]
    service: Service = request.app["service"]
    guild_id = _gid(request)
    body = await _body(request)
    wanted = body.get("changes") if isinstance(body.get("changes"), dict) else {}
    current = await service.port.command_permissions(guild_id)
    if current is None:
        return json_error(400, "Discord didn't answer. Try again in a moment.")
    names = {row["id"]: row["name"] for row in current["commands"]}
    names[current["application"]] = "All commands"
    changes = [{"id": command_id, "name": names[command_id], "overrides": clean_overrides(overrides)}
               for command_id, overrides in wanted.items() if command_id in names]
    if not changes:
        return json_error(400, "There is nothing to save.")
    state = new_token(24)
    now = time.time()
    await service.db.run("INSERT INTO login_states VALUES (?, ?, ?, ?)", (token_hash(state), "commands", f"/dashboard/{guild_id}/permissions", now + FLOW_SECONDS))
    await service.db.run("INSERT INTO command_syncs VALUES (?, ?, ?, ?, ?)", (token_hash(state), guild_id, session["user_id"], json.dumps(changes), now + FLOW_SECONDS))
    url = request.app["oauth"].authorize_url(redirect_uri=f"{service.public_url}/dashboard/callback", state=state, scopes=COMMAND_SCOPES)
    response = web.json_response({"authorize": url})
    set_cookie(response, FLOW_COOKIE, state, FLOW_SECONDS, request)
    return response


async def appearance_put(request: web.Request) -> web.Response:
    guarded = await _guard(request, "appearance", "edit")
    if isinstance(guarded, web.Response):
        return guarded
    session, document, _ = guarded
    service: Service = request.app["service"]
    guild_id = _gid(request)
    body = await _body(request)
    updated = settings_module.normalize({**document, "messages": body.get("messages", document["messages"]),
                                         "appearance": body.get("appearance", document["appearance"])})
    too_long = settings_module.message_problems(updated["messages"])
    if too_long:
        return json_error(400, too_long[0])
    for name, message in updated["messages"].items():
        message["author"] = _author_of(message, document["messages"][name], settings_module.DEFAULT_MESSAGES[name], session["user_id"])
    await service.save_settings(guild_id, updated, actor_id=session["user_id"], actor_name=session["username"])
    problem = None
    profile, style = _profile_changes(document["appearance"], updated["appearance"])
    if profile or style:
        problem = await service.port.apply_profile(guild_id, profile, style)
    if updated["messages"]["verification"] != document["messages"]["verification"]:
        await request.app["post_message"](guild_id, "verification")
    if updated["honeypot"]["enabled"] and updated["messages"]["honeypot"] != document["messages"]["honeypot"]:
        await request.app["post_message"](guild_id, "honeypot")
    return web.json_response({"ok": True, "problem": problem, "messages": updated["messages"], "appearance": updated["appearance"]})


def _profile_changes(old: dict, new: dict) -> tuple[dict, dict | None]:
    """Only what changed, in Discord's field names. Null clears a value."""
    profile: dict = {}
    if new["nickname"] != old["nickname"]:
        profile["nick"] = new["nickname"] or None
    if new["bio"] != old["bio"]:
        profile["bio"] = new["bio"] or None
    if new["avatar"] != old["avatar"]:
        profile["avatar"] = (STATIC / "img" / "avatars" / f"{new['avatar']}.png").read_bytes() if new["avatar"] else None
    style = None
    if any(new[key] != old[key] for key in ("font", "effect", "colors")):
        style = {"display_name_font_id": new["font"], "display_name_effect_id": new["effect"], "display_name_colors": new["colors"] or None}
    return profile, style


def _author_of(message: dict, before: dict, default: dict, user_id: str) -> str | None:
    """Who a message names as its writer: whoever last changed it, and nobody once it's back to the default."""
    def words(entry: dict) -> dict:
        return {key: value for key, value in entry.items() if key != "author"}
    if words(message) == words(default):
        return None
    return before.get("author") if words(message) == words(before) else user_id


async def post_message(request: web.Request) -> web.Response:
    guarded = await _guard(request, "appearance", "edit")
    if isinstance(guarded, web.Response):
        return guarded
    body = await _body(request)
    which = body.get("message")
    if which not in ("verification", "honeypot"):
        return json_error(400, "Pick a message to post.")
    if await request.app["post_message"](_gid(request), which) is False:
        return json_error(400, "Couldn't post it. Pick a channel on the Rules page, then look at the Health page.")
    return web.json_response({"ok": True})


async def appeals_list(request: web.Request) -> web.Response:
    guarded = await _guard(request, "appeals")
    if isinstance(guarded, web.Response):
        return guarded
    service: Service = request.app["service"]
    status = request.query.get("status", "open")
    rows = await service.db.all(
        "SELECT a.*, m.username, m.avatar FROM appeals a LEFT JOIN members m ON m.guild_id = a.guild_id AND m.user_id = a.user_id "
        "WHERE a.guild_id = ? AND a.status = ? ORDER BY a.created_at DESC LIMIT 100", (_gid(request), status))
    return web.json_response({"appeals": rows})


async def appeal_decide(request: web.Request) -> web.Response:
    guarded = await _guard(request, "appeals", "edit")
    if isinstance(guarded, web.Response):
        return guarded
    session, _, viewer = guarded
    service: Service = request.app["service"]
    body = await _body(request)
    decision = body.get("decision")
    if decision not in ("approve", "trust", "deny"):
        return json_error(400, "Pick a decision.")
    note = str(body["note"])[:500] if body.get("note") else None
    problem = await service.decide_appeal(_gid(request), int(request.match_info["id"]), decision, session["user_id"], session["username"], note,
                                          can_unban=viewer.is_admin or "ban_members" in viewer.permissions)
    return json_error(400, problem) if problem else web.json_response({"ok": True})


async def audit_view(request: web.Request) -> web.Response:
    guarded = await _guard(request, "audit")
    if isinstance(guarded, web.Response):
        return guarded
    service: Service = request.app["service"]
    rows = await service.db.all("SELECT at, actor_id, actor_name, kind, detail FROM audit WHERE guild_id = ? ORDER BY at DESC LIMIT 200", (_gid(request),))
    for row in rows:
        row["detail"] = json.loads(row["detail"])
    return web.json_response({"entries": rows})


async def raid_set(request: web.Request) -> web.Response:
    guarded = await _guard(request, "settings", "edit")
    if isinstance(guarded, web.Response):
        return guarded
    session, document, _ = guarded
    service: Service = request.app["service"]
    body = await _body(request)
    if body.get("active"):
        await service.start_raid(_gid(request), document, "Started by staff", actor_id=session["user_id"])
    else:
        await service.stop_raid(_gid(request), document, actor_id=session["user_id"])
    return web.json_response({"ok": True})


# --- integrations ------------------------------------------------------------------------------

async def integrations_get(request: web.Request) -> web.Response:
    guarded = await _guard(request, "integrations")
    if isinstance(guarded, web.Response):
        return guarded
    service: Service = request.app["service"]
    hooks = await service.db.all("SELECT id, url, events, created_at, last_status, last_sent_at FROM webhooks WHERE guild_id = ?", (_gid(request),))
    for hook in hooks:
        hook["events"] = json.loads(hook["events"])
    keys = await service.db.all("SELECT substr(key_hash, 1, 8) AS id, label, created_at, last_used_at FROM api_keys WHERE guild_id = ?", (_gid(request),))
    return web.json_response({"webhooks": hooks, "api_keys": keys, "events": list(WEBHOOK_EVENTS)})


async def webhook_add(request: web.Request) -> web.Response:
    guarded = await _guard(request, "integrations", "edit")
    if isinstance(guarded, web.Response):
        return guarded
    service: Service = request.app["service"]
    guild_id = _gid(request)
    body = await _body(request)
    url = str(body.get("url", ""))
    problem = webhook_problem(url)
    if problem:
        return json_error(400, problem)
    if await service.db.scalar("SELECT COUNT(*) FROM webhooks WHERE guild_id = ?", (guild_id,)) >= MAX_WEBHOOKS:
        return json_error(400, f"A server can have {MAX_WEBHOOKS} webhooks.")
    events = [event for event in body.get("events", []) if event in WEBHOOK_EVENTS] or list(WEBHOOK_EVENTS)
    secret = new_token(32)
    await service.db.insert("INSERT INTO webhooks (guild_id, url, secret, events, created_at) VALUES (?, ?, ?, ?, ?)",
                            (guild_id, url[:500], secret, json.dumps(events), time.time()))
    return web.json_response({"ok": True, "secret": secret})


async def webhook_delete(request: web.Request) -> web.Response:
    guarded = await _guard(request, "integrations", "edit")
    if isinstance(guarded, web.Response):
        return guarded
    await request.app["service"].db.run("DELETE FROM webhooks WHERE guild_id = ? AND id = ?", (_gid(request), int(request.match_info["id"])))
    return web.json_response({"ok": True})


async def key_add(request: web.Request) -> web.Response:
    guarded = await _guard(request, "integrations", "edit")
    if isinstance(guarded, web.Response):
        return guarded
    service: Service = request.app["service"]
    guild_id = _gid(request)
    if await service.db.scalar("SELECT COUNT(*) FROM api_keys WHERE guild_id = ?", (guild_id,)) >= MAX_API_KEYS:
        return json_error(400, f"A server can have {MAX_API_KEYS} keys.")
    body = await _body(request)
    key = "aw_" + new_token(32)
    await service.db.insert("INSERT INTO api_keys (key_hash, guild_id, label, created_at) VALUES (?, ?, ?, ?)",
                            (token_hash(key), guild_id, str(body.get("label", "Key"))[:40], time.time()))
    return web.json_response({"ok": True, "key": key})


async def key_delete(request: web.Request) -> web.Response:
    guarded = await _guard(request, "integrations", "edit")
    if isinstance(guarded, web.Response):
        return guarded
    await request.app["service"].db.run("DELETE FROM api_keys WHERE guild_id = ? AND substr(key_hash, 1, 8) = ?", (_gid(request), request.match_info["id"]))
    return web.json_response({"ok": True})


async def public_member(request: web.Request) -> web.Response:
    """GET /api/v1/guilds/{gid}/members/{uid}: is this member verified? Nothing else is exposed."""
    service: Service = request.app["service"]
    header = request.headers.get("Authorization", "")
    key = header[7:] if header.startswith("Bearer ") else ""
    row = await service.db.one("SELECT guild_id FROM api_keys WHERE key_hash = ?", (token_hash(key),)) if key else None
    if row is None or row["guild_id"] != _gid(request):
        return json_error(401, "That key isn't valid for this server.")
    await service.db.run("UPDATE api_keys SET last_used_at = ? WHERE key_hash = ?", (time.time(), token_hash(key)))
    record = await service.db.member(_gid(request), request.match_info["uid"])
    verified = bool(record and record["status"] == "verified") and not await service.db.is_banned(_gid(request), request.match_info["uid"])
    return web.json_response({"verified": verified, "verified_at": record["verified_at"] if verified else None})


async def send_webhooks(app: web.Application, guild_id: str, event: str, payload: dict) -> None:
    """Post an event to each subscribed address, signed so the receiver can trust it."""
    service: Service = app["service"]
    hooks = await service.db.all("SELECT id, url, secret, events FROM webhooks WHERE guild_id = ?", (guild_id,))
    session: aiohttp.ClientSession = app["webhook_http"]
    for hook in hooks:
        if event not in json.loads(hook["events"]) or webhook_problem(hook["url"]):
            continue
        stamp = str(int(time.time()))
        body = json.dumps({"event": event, "guild_id": guild_id, "at": float(stamp), "data": payload}, separators=(",", ":"))
        signature = hmac.new(hook["secret"].encode(), f"{stamp}.{body}".encode(), hashlib.sha256).hexdigest()
        status = 0
        try:
            async with session.post(hook["url"], data=body, timeout=aiohttp.ClientTimeout(total=5), allow_redirects=False, headers={
                    "Content-Type": "application/json", "User-Agent": "AltWarden-Webhook",
                    "X-AltWarden-Signature": f"t={stamp},v1={signature}"}) as response:
                status = response.status
        except Exception as exc:
            log.warning("Webhook delivery failed: %s", type(exc).__name__)
        await service.db.run("UPDATE webhooks SET last_status = ?, last_sent_at = ? WHERE id = ?", (status, time.time(), hook["id"]))


async def _body(request: web.Request) -> dict:
    body = await read_json(request)
    if not isinstance(body, dict):
        raise web.HTTPBadRequest(text="That request wasn't valid.")
    return body


def routes(app: web.Application) -> None:
    get, post, put, delete = app.router.add_get, app.router.add_post, app.router.add_put, app.router.add_delete
    gid = f"/api/guilds/{{gid:{SNOWFLAKE}}}"
    get("/api/session", me)
    get("/api/catalog", catalog_view)
    get(gid, guild_view)
    post(f"{gid}/setup", setup)
    get(f"{gid}/settings", settings_get)
    put(f"{gid}/settings", settings_put)
    post(f"{gid}/settings/preset", apply_preset)
    post(f"{gid}/settings/preview", preview)
    post(f"{gid}/settings/export", export_settings)
    post(f"{gid}/settings/import", import_settings)
    get(f"{gid}/analytics", analytics_view)
    get(f"{gid}/members", members_list)
    get(f"{gid}/members/{{uid:{SNOWFLAKE}}}", member_detail)
    post(f"{gid}/members/{{uid:{SNOWFLAKE}}}/{{action}}", member_action)
    get(f"{gid}/health", health_view)
    get(f"{gid}/permissions", permissions_get)
    put(f"{gid}/permissions", permissions_put)
    post(f"{gid}/permissions/discord", discord_permissions_start)
    put(f"{gid}/appearance", appearance_put)
    post(f"{gid}/post-message", post_message)
    get(f"{gid}/appeals", appeals_list)
    post(f"{gid}/appeals/{{id:\\d+}}", appeal_decide)
    get(f"{gid}/audit", audit_view)
    post(f"{gid}/raid", raid_set)
    get(f"{gid}/integrations", integrations_get)
    post(f"{gid}/webhooks", webhook_add)
    delete(f"{gid}/webhooks/{{id:\\d+}}", webhook_delete)
    post(f"{gid}/keys", key_add)
    delete(f"{gid}/keys/{{id}}", key_delete)
    get(f"/api/v1/guilds/{{gid:{SNOWFLAKE}}}/members/{{uid:{SNOWFLAKE}}}", public_member)


__all__ = ["MemberInfo", "PublicResolver", "client_ip", "notices", "routes", "send_webhooks", "webhook_problem"]
