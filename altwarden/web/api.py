"""The dashboard's JSON API, plus the small read API for other bots.

Each call checks the same rule the Permissions page edits, so what a member can see in the
dashboard and what the API will do for them can't drift apart.
"""
from __future__ import annotations

import asyncio
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
from ..ports import DISCORD_BUSY, DiscordUnavailable, MemberInfo
from ..service import Service
from .app import (FLOW_COOKIE, FLOW_SECONDS, SNOWFLAKE, STATIC, client_ip, csrf_ok, current_session, is_snowflake, json_error, limited, read_json,
                  save_login_state, set_cookie)

log = logging.getLogger("altwarden.api")

WEBHOOK_EVENTS = ("member.verified", "member.failed", "appeal.opened", "appeal.decided", "raid.started", "raid.ended")
MAX_WEBHOOKS = 5
UNREADABLE_WEBHOOK = "This address can't be read. Remove it and add it again."
MAX_API_KEYS = 5
MAX_WEBHOOK_URL = 500
MIN_KEY_FOR_ENDING = 16  # four characters of anything shorter gives away too much of it
LAST_USED_SECONDS = 60
DISCORD_READ_SECONDS = 5
# Row IDs for a route. Long enough for any real row, and short enough that int() can't fail on one.
ROW_ID = "[0-9]{1,18}"
CONFLICT = "Someone else changed these settings. Reload to see their changes."
# The Access page's names for the pages it lists.
PAGE_NAMES = {"settings": "Rules", "permissions": "Access", "appearance": "Messages"}
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


async def _viewer(service: Service, session: dict, guild_id: str, *, fresh: bool = False) -> access.Viewer | None:
    """Who is asking, in this server. A write asks Discord afresh, or someone just demoted could go on changing things until the cache runs out."""
    member = await (service.port.member(guild_id, session["user_id"], fresh=True) if fresh else service.port.member(guild_id, session["user_id"]))
    if member is None:
        return None
    return access.Viewer(session["user_id"], frozenset(member.role_ids), member.permissions, member.is_owner)


async def _signed_in(request: web.Request):
    """Return (session, settings, viewer), or an error response. Writes also need the CSRF token."""
    session = await current_session(request)
    if session is None or session["scope"] != "dashboard":
        return json_error(401, "Sign in first.", login="/login")
    writing = request.method != "GET"
    if writing and not csrf_ok(request, session):
        return json_error(403, "This request can't be trusted. Reload the page.")
    # Each write asks Discord afresh, before any rule runs, and that call waits in line with staff saves and kick timers.
    if writing and not request.app["limits"].allow(f"write:{session['user_id']}", per_minute=120, burst=60):
        return json_error(429, "Too many requests. Wait a moment and try again.")
    service: Service = request.app["service"]
    guild_id = _gid(request)
    viewer = await _viewer(service, session, guild_id, fresh=writing)
    if viewer is None:
        return json_error(403, "You aren't in that server.")
    document = await service.get_settings(guild_id)
    if document is None:
        document = settings_module.defaults()
    return session, document, viewer


async def _command_guard(request: web.Request, command: str):
    """The same, for a route that does what a slash command does, under that command's rule on the Access page."""
    guarded = await _signed_in(request)
    if isinstance(guarded, web.Response):
        return guarded
    if not access.allowed(settings_module.command_rule(guarded[1], command), guarded[2]):
        return json_error(403, "You don't have access to that action.")
    return guarded


async def _guard(request: web.Request, page: str, level: str = "view"):
    """The same, for a page under that page's rule on the Access page."""
    guarded = await _signed_in(request)
    if isinstance(guarded, web.Response):
        return guarded
    _, document, viewer = guarded
    # A page with nothing to edit has no edit rule, so it can't let anyone in that way.
    can_edit = "edit" in settings_module.PAGE_DEFAULTS.get(page, {}) and access.allowed(settings_module.page_rule(document, page, "edit"), viewer)
    if level == "edit" and not can_edit:
        return json_error(403, "You can view this page but not change it.")
    if level == "view" and not can_edit and not access.allowed(settings_module.page_rule(document, page, "view"), viewer):
        return json_error(403, "You don't have access to this page.")
    return guarded


def _conflict() -> web.Response:
    return json_error(409, CONFLICT, conflict=True)


def _base(body: dict) -> str | None:
    """The revision a page last read. With none, the save isn't checked against anyone else's."""
    base = body.get("base")
    return base if isinstance(base, str) else None


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


LATE_SERVER_LOOKUPS = 25


async def me(request: web.Request) -> web.Response:
    session = await current_session(request)
    if session is None or session["scope"] != "dashboard":
        return json_error(401, "Sign in first.", login="/login")
    service: Service = request.app["service"]
    # The list from sign-in can't name a server added since, and the token that read it is gone, so the bot's own list fills in the rest.
    known = {guild["id"] for guild in session["guilds"]}
    late = []
    for guild_id in [guild_id for guild_id in service.port.guild_ids() if guild_id not in known][:LATE_SERVER_LOOKUPS]:
        view = await service.port.guild(guild_id)
        if view is not None:
            late.append({"id": view.id, "name": view.name, "icon": view.icon})
    servers = []
    for guild in [*session["guilds"], *late]:
        if await service.port.guild(guild["id"]) is None and not await service.port.guild_loading(guild["id"]):
            continue  # the bot only runs where its owner put it, so nothing here offers to add it
        try:
            viewer = await _viewer(service, session, guild["id"])
        except DiscordUnavailable:
            # One server's bad moment mustn't cost the whole list, and its own page says what's wrong. A late one has nothing yet saying this person is in it.
            reachable = guild["id"] in known
        else:
            reachable = False
            if viewer is not None:
                document = await service.get_settings(guild["id"]) or settings_module.defaults()
                reachable = await _can_open(service, guild["id"], document, viewer)
        if reachable:
            servers.append({"id": guild["id"], "name": guild["name"], "icon": guild["icon"]})
    servers.sort(key=lambda item: item["name"].lower())
    return web.json_response({"user": {"id": session["user_id"], "name": session["username"], "avatar": session["avatar"]},
                              "csrf": session["csrf"], "guilds": servers})


async def catalog_view(request: web.Request) -> web.Response:
    return web.json_response({
        "groups": {key: {"name": name, "blurb": blurb} for key, (name, blurb) in catalog.GROUPS.items()},
        "checks": [{"id": check.id, "group": check.group, "name": check.name, "blurb": check.blurb, "modes": sorted(check.modes)}
                   for check in catalog.CHECKS],
        "actions": [{"id": action, "label": catalog.ACTION_LABEL[action], "blurb": catalog.ACTION_BLURB[action]} for action in catalog.ACTIONS],
        "honeypot_actions": list(catalog.HONEYPOT_ACTIONS),
        "presets": catalog.PRESETS,  # the whole tables, so the Rules page can name the active preset the way detect_preset does
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
    pages = _pages_for(document, viewer)
    set_up = bool(row and row["setup_done"])
    # The same test as the setup route, so the screen and the route can't disagree.
    can_setup = not set_up and access.allowed(settings_module.command_rule(document, "setup"), viewer)
    # The names of private channels and roles go only to people on a page that picks them, or finishing setup, which picks two.
    can_import = access.allowed(settings_module.command_rule(document, "import-members"), viewer)
    picks = can_setup or can_import or any(pages[page]["view"] for page in ("settings", "permissions", "appearance"))
    return web.json_response({
        "id": guild.id, "name": guild.name, "icon": guild.icon, "member_count": guild.member_count,
        "roles": guild.roles if picks else [], "channels": guild.channels if picks else [], "bot_top_role": guild.bot_top_role,
        "setup_done": set_up, "can_setup": can_setup, "can_import": can_import,
        "raid_until": row["raid_until"] if row else 0, "pages": pages,
        "verifying_now": await analytics.verifying_now(service.db, guild_id),
        "healthy": (await health.full_report(service, guild_id, guild, document))["healthy"] if set_up else True,
        "avatar_colors": list(settings_module.AVATAR_COLORS),
        "help_desk": document["core"]["help_desk"]["enabled"],
    })


async def _any_page(request: web.Request):
    guarded = await _signed_in(request)
    if isinstance(guarded, web.Response):
        return guarded
    if not await _can_open(request.app["service"], _gid(request), guarded[1], guarded[2]):
        return json_error(403, "You don't have access to this server.")
    return guarded


async def _can_open(service: Service, guild_id: str, document: dict, viewer: access.Viewer) -> bool:
    """A page to view, or a setup left to finish. Someone a server gave only the setup rule has no page until it's done."""
    if any(entry["view"] for entry in _pages_for(document, viewer).values()):
        return True
    return not await service.is_set_up(guild_id) and access.allowed(settings_module.command_rule(document, "setup"), viewer)


async def _no_guild(service: Service, guild_id: str) -> web.Response:
    """Why a server can't be read. Nothing is saved either way, because its roles and channels can't be checked."""
    if await service.port.guild_loading(guild_id):
        return json_error(503, "Discord is still loading this server, so nothing was saved. Try again in a moment.")
    return json_error(404, "AltWarden isn't in that server.")


async def setup(request: web.Request) -> web.Response:
    """The first save, under the same rule as /setup. After that, changes go through the Rules page and its rule."""
    guarded = await _command_guard(request, "setup")
    if isinstance(guarded, web.Response):
        return guarded
    session, document, viewer = guarded
    service: Service = request.app["service"]
    row = await service.db.guild(_gid(request))
    if row and row["setup_done"]:
        return json_error(409, "This server is already set up. Change it on the Rules page.")
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
    chosen = {"verified_role": updated["core"]["verified_role"], "channel": updated["core"]["channel"]}
    await service.edit_settings(_gid(request), lambda current: {**current, "core": {**current["core"], **chosen}}, section="rules",
                                actor_id=session["user_id"], actor_name=session["username"], setup_done=True)
    posted = await request.app["post_message"](_gid(request), "verification")
    return web.json_response({"ok": True, "problem": None if posted is not False else COULD_NOT_POST})


async def import_members(request: web.Request) -> web.Response:
    """What /import-members does. It runs in the background, and the log says when it's done."""
    guarded = await _command_guard(request, "import-members")
    if isinstance(guarded, web.Response):
        return guarded
    session, _, _ = guarded
    service: Service = request.app["service"]
    guild_id = _gid(request)
    guild = await service.port.guild(guild_id)
    if guild is None:
        return await _no_guild(service, guild_id)
    role = (await _body(request)).get("role")
    if not any(item["id"] == role for item in guild.roles):
        return json_error(400, "Pick a role from this server.")
    if not request.app["import_role"](guild_id, role, session["user_id"], session["username"]):
        return json_error(409, "An import is already running on this server.")
    return web.json_response({"started": True})


async def settings_get(request: web.Request) -> web.Response:
    guarded = await _guard(request, "settings")
    if isinstance(guarded, web.Response):
        return guarded
    _, document, viewer = guarded
    key = await request.app["service"].lookup_key(_gid(request))
    return web.json_response({"settings": _rules_view(document), "paused": settings_module.paused_checks(document), "lookup_key": _lookup_key_view(key),
                              "can_edit": access.allowed(settings_module.page_rule(document, "settings", "edit"), viewer),
                              "revision": settings_module.revision(document, "rules")})


def _lookup_key_view(key: str | None) -> dict:
    """The page learns that a key is saved and how it ends. The key itself never goes back to a browser."""
    return {"saved": bool(key), "ending": key[-4:] if key and len(key) >= MIN_KEY_FOR_ENDING else None}


async def lookup_key_put(request: web.Request) -> web.Response:
    guarded = await _guard(request, "settings", "edit")
    if isinstance(guarded, web.Response):
        return guarded
    body = await _body(request)
    key = str(body.get("key") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{6,100}", key):
        return json_error(400, "That doesn't look like a proxycheck.io key.")
    session = guarded[0]
    # A key proxycheck.io doesn't know would do nothing for every member, with nobody told.
    known = await request.app["check_lookup_key"](key)
    if known is False:
        return json_error(400, "proxycheck.io doesn't recognize that key.")
    await request.app["service"].set_lookup_key(_gid(request), key, actor_id=session["user_id"], actor_name=session["username"])
    answer = {"ok": True, "lookup_key": _lookup_key_view(key)}
    if known is None:
        answer["warning"] = "Saved, but proxycheck.io couldn't be reached to check it."
    return web.json_response(answer)


async def lookup_key_delete(request: web.Request) -> web.Response:
    guarded = await _guard(request, "settings", "edit")
    if isinstance(guarded, web.Response):
        return guarded
    session = guarded[0]
    await request.app["service"].set_lookup_key(_gid(request), None, actor_id=session["user_id"], actor_name=session["username"])
    return web.json_response({"ok": True, "lookup_key": _lookup_key_view(None)})


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
    previous: dict = {}

    def build(current: dict) -> dict:
        previous.update(current)
        return {**incoming, **{key: current[key] for key in settings_module.OTHER_SECTIONS}}
    try:
        changes = await service.edit_settings(guild_id, build, section="rules", base=_base(body), actor_id=session["user_id"], actor_name=session["username"])
    except settings_module.Conflict:
        return _conflict()
    before = json.dumps(previous["core"]["channel"]), json.dumps(previous["core"]["help_desk"]["enabled"])
    after = json.dumps(incoming["core"]["channel"]), json.dumps(incoming["core"]["help_desk"]["enabled"])
    posted = True
    if before != after:
        posted = await request.app["post_message"](guild_id, "verification") is not False
    old_pot, new_pot = previous["honeypot"], incoming["honeypot"]
    if new_pot["enabled"] and (not old_pot["enabled"] or new_pot["channel"] != old_pot["channel"]):
        posted = await request.app["post_message"](guild_id, "honeypot") is not False and posted
    if old_pot["enabled"] and not new_pot["enabled"]:
        await _take_down_honeypot_post(service, guild_id)
    await service.warn_if_broken(guild_id, incoming, [module for module, old, new in (
        ("help_desk", previous["core"]["help_desk"], incoming["core"]["help_desk"]), ("honeypot", old_pot, new_pot)) if old != new])
    stored = await service.get_settings(guild_id)
    return web.json_response({"ok": True, "changes": len(changes), "paused": settings_module.paused_checks(incoming),
                              "problem": None if posted else COULD_NOT_POST, "settings": _rules_view(stored), "revision": settings_module.revision(stored, "rules")})


async def _take_down_honeypot_post(service: Service, guild_id: str) -> None:
    """A warning about a trap that's off would tell members something untrue. If it can't be deleted, the next post removes it."""
    row = await service.db.guild(guild_id)
    channel_id, _, message_id = ((row["honeypot_message_id"] if row else None) or "").partition(":")
    if not message_id:
        return
    if await service.port.delete_message(channel_id, message_id):
        await service.db.set_guild_field(guild_id, "honeypot_message_id", None)
    else:
        log.warning("Couldn't delete the honeypot warning in %s", guild_id)


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
        merged = _rules_view(settings_module.import_code(document, str(body.get("code", ""))))
    except ValueError as exc:
        return json_error(400, str(exc))
    # Nothing is saved yet. A code from someone else can turn down retention or switch on the outside lookup, so the page lists what would change.
    return web.json_response({"settings": merged, "changes": settings_module.diff(_rules_view(document), merged)})


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
                                    "WHERE guild_id = ? AND user_id = ? AND outcome != 'started' ORDER BY at DESC LIMIT 1000", (guild_id, user_id))
    for attempt in attempts:
        attempt["detail"] = json.loads(attempt["detail"])
    links = await service.db.all("SELECT main_id, alt_id, confidence, score, methods, at FROM links WHERE guild_id = ? AND (main_id = ? OR alt_id = ?)",
                                 (guild_id, user_id, user_id))
    for link in links:
        link["methods"] = json.loads(link["methods"])
    options = [{"id": check, "name": notices.check_name(check)} for check in bypass_options(guarded[1])]
    return web.json_response({"member": record, "attempts": attempts, "links": links, "bypass_options": options,
                              "banned": await service.db.is_banned(guild_id, user_id)})


async def _refused_action(service: Service, session: dict, viewer: access.Viewer, guild_id: str, target: str, action: str) -> web.Response | None:
    """The bot holds power its users may not, so this asks what Discord would ask of the person themselves."""
    who = MemberInfo(guild_id, viewer.user_id, session["username"], role_ids=tuple(viewer.role_ids), permissions=viewer.permissions, is_owner=viewer.is_owner)
    refusal = await service.staff_refusal(guild_id, who, target, action)
    return json_error(503 if refusal == DISCORD_BUSY else 403, refusal) if refusal else None


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
    body = await _body(request) if action in ("bypass", "trust") else {}
    other = body.get("other")
    if action == "trust" and not is_snowflake(other):
        return json_error(400, "That account ID isn't valid.")
    for target in (user_id, other) if action == "trust" else (user_id,):
        refused = await _refused_action(service, session, viewer, guild_id, target, action)
        if refused:
            return refused
    if action == "verify":
        problem = await service.manual_verify(guild_id, user_id, *actor)
        return json_error(400, problem) if problem else web.json_response({"ok": True})
    if action == "reset":
        return web.json_response({"ok": True, **(await service.reset_member(guild_id, user_id, *actor)).as_dict()})
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
    await service.trust_accounts(guild_id, user_id, other, *actor)
    return web.json_response({"ok": True})


async def health_view(request: web.Request) -> web.Response:
    guarded = await _guard(request, "health")
    if isinstance(guarded, web.Response):
        return guarded
    service: Service = request.app["service"]
    guild = await service.port.guild(_gid(request))
    if guild is None:
        return json_error(404, "AltWarden isn't in that server.")
    data = await health.full_report(service, _gid(request), guild, guarded[1])
    data["lists_loaded"] = service.net.ready
    data["lists_missing"] = service.net.missing()
    public = await service.public_bot(request.app.get("application_info"))
    data["public_bot"] = bool(request.app.get("public_bot") if public is None else public)  # what startup read, until Discord has answered here
    core = guarded[1]["core"]
    data["lookup_without_key"] = core["mode"] == catalog.WEB and core["external_vpn_lookup"] and not await service.lookup_key(_gid(request))  # only the web mode looks anything up
    data["checked_at"] = time.time()
    return web.json_response(data)


async def permissions_put(request: web.Request) -> web.Response:
    guarded = await _guard(request, "permissions", "edit")
    if isinstance(guarded, web.Response):
        return guarded
    session, document, viewer = guarded
    service: Service = request.app["service"]
    body = await _body(request)
    if not isinstance(body.get("permissions"), dict):  # normalizing nothing would reset every rule to its default
        return json_error(400, "That request wasn't valid.")
    wanted = settings_module.normalize({**document, "permissions": body["permissions"]})["permissions"]

    def build(current: dict) -> dict:
        updated = {**current, "permissions": wanted}
        refusal = _rule_refusal(current, updated, viewer)
        if refusal:
            raise _RuleRefused(refusal)
        return updated
    try:
        await service.edit_settings(_gid(request), build, section="access", base=_base(body), actor_id=session["user_id"], actor_name=session["username"])
    except settings_module.Conflict:
        return _conflict()
    except _RuleRefused as refused:
        return json_error(403, str(refused))
    stored = await service.get_settings(_gid(request))
    return web.json_response({"ok": True, "permissions": stored["permissions"], "revision": settings_module.revision(stored, "access")})


class _RuleRefused(Exception):
    pass


def _rule_refusal(before: dict, after: dict, viewer: access.Viewer) -> str | None:
    """Why this person can't make this change to the Access page, or None.

    Without this, one save could hand someone every right the page guards. Someone who isn't an
    Administrator changes a rule only if they pass it now and hold every permission it asks for by default.
    """
    if viewer.is_admin:
        return None

    def may_change(rule: dict, default: list[str]) -> bool:
        return access.allowed(rule, viewer) and all(name in viewer.permissions for name in default)
    for page, levels in settings_module.PAGE_DEFAULTS.items():
        for level, default in levels.items():
            rule = settings_module.page_rule(before, page, level)
            if rule != settings_module.page_rule(after, page, level) and not may_change(rule, default):
                return f"You can't change who can {level} the {PAGE_NAMES.get(page, page.capitalize())} page. That takes passing the rule now and holding every permission it asks for by default."
    for name, default in settings_module.COMMAND_DEFAULTS.items():
        rule = settings_module.command_rule(before, name)
        if rule != settings_module.command_rule(after, name) and not may_change(rule, default):
            return f"You can't change who can use /{name}. That takes passing the rule now and holding every permission it asks for by default."
    return None


async def permissions_get(request: web.Request) -> web.Response:
    guarded = await _guard(request, "permissions")
    if isinstance(guarded, web.Response):
        return guarded
    document = guarded[1]
    pages = {page: {level: settings_module.page_rule(document, page, level) for level in levels}
             for page, levels in settings_module.PAGE_DEFAULTS.items()}
    commands = {name: settings_module.command_rule(document, name) for name in settings_module.COMMAND_DEFAULTS}
    discord_side = await _discord_commands(request.app["service"], _gid(request))
    return web.json_response({"pages": pages, "commands": commands, "discord": discord_side, "revision": settings_module.revision(document, "access")})


async def _discord_commands(service: Service, guild_id: str) -> dict | None:
    """Discord's own overrides, or None if it doesn't answer soon. AltWarden's rules on the same page don't depend on them, so they don't wait long."""
    try:
        return await asyncio.wait_for(service.port.command_permissions(guild_id), DISCORD_READ_SECONDS)
    except (TimeoutError, DiscordUnavailable):
        log.warning("Discord didn't answer with the command permissions of %s", guild_id)
        return None


def clean_overrides(raw) -> list[dict]:
    """Overrides for Discord's command permissions, in the only shapes Discord accepts."""
    found: list[dict] = []
    seen = set()
    for entry in raw[:MAX_COMMAND_OVERRIDES] if isinstance(raw, list) else []:
        if not isinstance(entry, dict) or entry.get("type") not in ("role", "user", "channel"):
            continue
        target = entry.get("id")
        if is_snowflake(target) and (entry["type"], target) not in seen:
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
    current = await _discord_commands(service, guild_id)
    if current is None:
        return json_error(503, DISCORD_BUSY)
    names = {row["id"]: row["name"] for row in current["commands"]}
    names[current["application"]] = "All commands"
    changes = [{"id": command_id, "name": names[command_id], "overrides": clean_overrides(overrides)}
               for command_id, overrides in wanted.items() if command_id in names]
    if not changes:
        return json_error(400, "There is nothing to save.")
    state = new_token(24)
    now = time.time()
    await save_login_state(service, state, "commands", f"/dashboard/{guild_id}/permissions")
    await service.db.run("INSERT INTO command_syncs (state_hash, guild_id, user_id, changes, expires_at) VALUES (?, ?, ?, ?, ?)",
                         (token_hash(state), guild_id, session["user_id"], json.dumps(changes), now + FLOW_SECONDS))
    url = request.app["oauth"].authorize_url(redirect_uri=f"{service.public_url}/dashboard/callback", state=state, scopes=COMMAND_SCOPES)
    response = web.json_response({"authorize": url})
    set_cookie(response, FLOW_COOKIE, state, FLOW_SECONDS, request)
    return response


async def appearance_get(request: web.Request) -> web.Response:
    """The Messages page's copy, under its own rule, so it doesn't need to read the whole Rules document."""
    guarded = await _guard(request, "appearance")
    if isinstance(guarded, web.Response):
        return guarded
    _, document, viewer = guarded
    return web.json_response({"messages": document["messages"], "appearance": document["appearance"], "honeypot_enabled": document["honeypot"]["enabled"],
                              "can_edit": access.allowed(settings_module.page_rule(document, "appearance", "edit"), viewer),
                              "revision": settings_module.revision(document, "look")})


async def appearance_put(request: web.Request) -> web.Response:
    guarded = await _guard(request, "appearance", "edit")
    if isinstance(guarded, web.Response):
        return guarded
    session, document, _ = guarded
    service: Service = request.app["service"]
    guild_id = _gid(request)
    body = await _body(request)
    checked = settings_module.normalize({**document, "messages": body.get("messages", document["messages"])})
    too_long = settings_module.message_problems(checked["messages"])
    if too_long:
        return json_error(400, too_long[0])
    previous: dict = {}

    def build(current: dict) -> dict:
        previous.update(current)
        updated = settings_module.normalize({**current, "messages": body.get("messages", current["messages"]),
                                             "appearance": body.get("appearance", current["appearance"])})
        for name, message in updated["messages"].items():
            message["author"] = _author_of(message, current["messages"][name], settings_module.DEFAULT_MESSAGES[name], session["user_id"])
        return updated
    try:
        await service.edit_settings(guild_id, build, section="look", base=_base(body), actor_id=session["user_id"], actor_name=session["username"])
    except settings_module.Conflict:
        return _conflict()
    updated = await service.get_settings(guild_id)
    problems = []
    profile, style = _profile_changes(previous["appearance"], updated["appearance"])
    if profile or style:
        changed = await service.port.apply_profile(guild_id, profile, style)
        if changed:
            problems.append(changed)
    posted = True
    if updated["messages"]["verification"] != previous["messages"]["verification"]:
        posted = await request.app["post_message"](guild_id, "verification") is not False
    if updated["honeypot"]["enabled"] and updated["messages"]["honeypot"] != previous["messages"]["honeypot"]:
        posted = await request.app["post_message"](guild_id, "honeypot") is not False and posted
    if not posted:
        problems.append(COULD_NOT_POST)
    return web.json_response({"ok": True, "problem": " ".join(problems) or None, "messages": updated["messages"], "appearance": updated["appearance"],
                              "revision": settings_module.revision(updated, "look")})


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
    guarded = await _command_guard(request, "post-message")
    if isinstance(guarded, web.Response):
        return guarded
    session, document, _ = guarded
    body = await _body(request)
    which = body.get("message")
    if which not in ("verification", "honeypot"):
        return json_error(400, "Pick a message to post.")
    if which == "honeypot" and not document["honeypot"]["enabled"]:
        return json_error(400, "The honeypot is off, so its warning would be untrue. Turn it on first.")
    outcome = await request.app["service"].staff_post(_gid(request), which, request.app["post_message"], actor_id=session["user_id"], actor_name=session["username"])
    if outcome == "failed":
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
    appeal_id = int(request.match_info["id"])
    if decision != "deny":  # approving gives the verified role, so it asks what giving it by hand would
        appeal = await service.db.one("SELECT user_id FROM appeals WHERE guild_id = ? AND id = ?", (_gid(request), appeal_id))
        refused = appeal and await _refused_action(service, session, viewer, _gid(request), appeal["user_id"], "verify")
        if refused:
            return refused
    outcome = await service.settle_appeal(_gid(request), appeal_id, decision, session["user_id"], session["username"], note,
                                          can_unban=viewer.is_admin or "ban_members" in viewer.permissions)
    return json_error(400, outcome["problem"]) if outcome["problem"] else web.json_response({"ok": True, "told": outcome["told"]})


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
    guarded = await _command_guard(request, "raid")
    if isinstance(guarded, web.Response):
        return guarded
    session, document, _ = guarded
    service: Service = request.app["service"]
    body = await _body(request)
    if body.get("active"):
        await service.start_raid(_gid(request), document, "Started by staff", actor_id=session["user_id"], actor_name=session["username"])
    else:
        await service.stop_raid(_gid(request), document, actor_id=session["user_id"], actor_name=session["username"])
    return web.json_response({"ok": True})


# --- integrations ------------------------------------------------------------------------------

async def integrations_get(request: web.Request) -> web.Response:
    guarded = await _guard(request, "integrations")
    if isinstance(guarded, web.Response):
        return guarded
    service: Service = request.app["service"]
    _, document, viewer = guarded
    can_edit = access.allowed(settings_module.page_rule(document, "integrations", "edit"), viewer)
    # The path of a webhook address is often the credential itself, as Discord's are, so only editors see it.
    # A row that can't be opened still counts toward the limit, so staff have to be able to see it and remove it.
    hooks = [{"id": hook["id"], "url": UNREADABLE_WEBHOOK if hook["url"] is None else hook["url"] if can_edit else _masked_url(hook["url"]), "events": json.loads(hook["events"]),
              "created_at": hook["created_at"], "last_status": hook["last_status"], "last_sent_at": hook["last_sent_at"]}
             for hook in await service.webhooks(_gid(request), unreadable=True)]
    keys = await service.db.all("SELECT substr(key_hash, 1, 8) AS id, label, created_at, last_used_at FROM api_keys WHERE guild_id = ?", (_gid(request),))
    return web.json_response({"webhooks": hooks, "api_keys": keys, "events": list(WEBHOOK_EVENTS), "can_edit": can_edit})


def _host_of(url: str) -> str:
    return URL(url).host or ""


def _masked_url(url: str) -> str:
    return f"https://{_host_of(url)}/..."


async def _note_integration(request: web.Request, session: dict, kind: str, detail: dict) -> None:
    """Webhooks receive member events and keys read member status, so each change goes in the audit log, and no secret goes with it."""
    await request.app["service"].db.add_audit(_gid(request), kind, actor_id=session["user_id"], actor_name=session["username"], detail=detail)


async def webhook_add(request: web.Request) -> web.Response:
    guarded = await _guard(request, "integrations", "edit")
    if isinstance(guarded, web.Response):
        return guarded
    service: Service = request.app["service"]
    guild_id = _gid(request)
    body = await _body(request)
    url = str(body.get("url", ""))
    if len(url) > MAX_WEBHOOK_URL:
        return json_error(400, f"That address is over {MAX_WEBHOOK_URL} characters.")
    problem = webhook_problem(url)
    if problem:
        return json_error(400, problem)
    asked = body.get("events", [])
    if not isinstance(asked, list):
        return json_error(400, "Pick events from the list.")
    events = [event for event in asked if event in WEBHOOK_EVENTS] or list(WEBHOOK_EVENTS)
    secret = new_token(32)
    async with service._lock(guild_id, "integrations"):  # or two saves at once could both pass the count
        if await service.db.scalar("SELECT COUNT(*) FROM webhooks WHERE guild_id = ?", (guild_id,)) >= MAX_WEBHOOKS:
            return json_error(400, f"A server can have {MAX_WEBHOOKS} webhooks.")
        await service.add_webhook(guild_id, url, secret, events)
    await _note_integration(request, guarded[0], "webhook_add", {"host": _host_of(url), "events": events})
    return web.json_response({"ok": True, "secret": secret})


async def webhook_delete(request: web.Request) -> web.Response:
    guarded = await _guard(request, "integrations", "edit")
    if isinstance(guarded, web.Response):
        return guarded
    service: Service = request.app["service"]
    hook_id = int(request.match_info["id"])
    host = next((_host_of(hook["url"]) for hook in await service.webhooks(_gid(request)) if hook["id"] == hook_id), "")
    if await service.db.run("DELETE FROM webhooks WHERE guild_id = ? AND id = ?", (_gid(request), hook_id)):
        await _note_integration(request, guarded[0], "webhook_delete", {"host": host})
    return web.json_response({"ok": True})


async def key_add(request: web.Request) -> web.Response:
    guarded = await _guard(request, "integrations", "edit")
    if isinstance(guarded, web.Response):
        return guarded
    service: Service = request.app["service"]
    guild_id = _gid(request)
    body = await _body(request)
    key = "aw_" + new_token(32)
    label = str(body.get("label", "Key"))[:40]
    async with service._lock(guild_id, "integrations"):  # or two saves at once could both pass the count
        if await service.db.scalar("SELECT COUNT(*) FROM api_keys WHERE guild_id = ?", (guild_id,)) >= MAX_API_KEYS:
            return json_error(400, f"A server can have {MAX_API_KEYS} keys.")
        await service.db.insert("INSERT INTO api_keys (key_hash, guild_id, label, created_at) VALUES (?, ?, ?, ?)",
                                (token_hash(key), guild_id, label, time.time()))
    await _note_integration(request, guarded[0], "key_add", {"label": label})
    return web.json_response({"ok": True, "key": key})


async def key_delete(request: web.Request) -> web.Response:
    guarded = await _guard(request, "integrations", "edit")
    if isinstance(guarded, web.Response):
        return guarded
    service: Service = request.app["service"]
    where = (_gid(request), request.match_info["id"])
    row = await service.db.one("SELECT label FROM api_keys WHERE guild_id = ? AND substr(key_hash, 1, 8) = ?", where)
    if row is not None:
        await service.db.run("DELETE FROM api_keys WHERE guild_id = ? AND substr(key_hash, 1, 8) = ?", where)
        await _note_integration(request, guarded[0], "key_delete", {"label": row["label"]})
    return web.json_response({"ok": True})


async def public_member(request: web.Request) -> web.Response:
    """GET /api/v1/guilds/{gid}/members/{uid}: is this member verified? Nothing else is exposed."""
    if limited(request, "public-api", per_minute=120, burst=60):
        return json_error(429, "Too many requests.")
    service: Service = request.app["service"]
    header = request.headers.get("Authorization", "")
    key = header[7:] if header.startswith("Bearer ") else ""
    row = await service.db.one("SELECT guild_id, last_used_at FROM api_keys WHERE key_hash = ?", (token_hash(key),)) if key else None
    if row is None or row["guild_id"] != _gid(request):
        return json_error(401, "That key isn't valid for this server.")
    now = time.time()
    if now - (row["last_used_at"] or 0) >= LAST_USED_SECONDS:  # a busy bot shouldn't cost a write on every call
        await service.db.run("UPDATE api_keys SET last_used_at = ? WHERE key_hash = ?", (now, token_hash(key)))
    record = await service.db.member(_gid(request), request.match_info["uid"])
    verified = bool(record and record["status"] == "verified") and not await service.db.is_banned(_gid(request), request.match_info["uid"])
    return web.json_response({"verified": verified, "verified_at": record["verified_at"] if verified else None})


async def send_webhooks(app: web.Application, guild_id: str, event: str, payload: dict) -> None:
    """Post an event to each subscribed address, signed so the receiver can trust it."""
    service: Service = app["service"]
    hooks = await service.webhooks(guild_id)
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
    put(f"{gid}/lookup-key", lookup_key_put)
    delete(f"{gid}/lookup-key", lookup_key_delete)
    post(f"{gid}/settings/preset", apply_preset)
    post(f"{gid}/settings/preview", preview)
    post(f"{gid}/settings/export", export_settings)
    post(f"{gid}/settings/import", import_settings)
    post(f"{gid}/import-members", import_members)
    get(f"{gid}/analytics", analytics_view)
    get(f"{gid}/members", members_list)
    get(f"{gid}/members/{{uid:{SNOWFLAKE}}}", member_detail)
    post(f"{gid}/members/{{uid:{SNOWFLAKE}}}/{{action}}", member_action)
    get(f"{gid}/health", health_view)
    get(f"{gid}/permissions", permissions_get)
    put(f"{gid}/permissions", permissions_put)
    post(f"{gid}/permissions/discord", discord_permissions_start)
    get(f"{gid}/appearance", appearance_get)
    put(f"{gid}/appearance", appearance_put)
    post(f"{gid}/post-message", post_message)
    get(f"{gid}/appeals", appeals_list)
    post(f"{gid}/appeals/{{id:{ROW_ID}}}", appeal_decide)
    get(f"{gid}/audit", audit_view)
    post(f"{gid}/raid", raid_set)
    get(f"{gid}/integrations", integrations_get)
    post(f"{gid}/webhooks", webhook_add)
    delete(f"{gid}/webhooks/{{id:{ROW_ID}}}", webhook_delete)
    post(f"{gid}/keys", key_add)
    delete(f"{gid}/keys/{{id}}", key_delete)
    get(f"/api/v1/guilds/{{gid:{SNOWFLAKE}}}/members/{{uid:{SNOWFLAKE}}}", public_member)


__all__ = ["MemberInfo", "PublicResolver", "client_ip", "notices", "routes", "send_webhooks", "webhook_problem"]
