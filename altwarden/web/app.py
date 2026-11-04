"""The website: public pages, the verification flow, and sign-in.

Every page is a static file, and all text reaches the page through JSON and `textContent`, so
there is no server-side templating to inject into. Member pages load scripts from this site and
nowhere else, and the Content Security Policy enforces that.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import re
import secrets
import time
from pathlib import Path

import aiohttp
from aiohttp import web

from .. import __version__
from ..catalog import CHECK_IDS, WEB
from ..crypto import Keyring, network_of, new_token, pow_solved, token_hash
from ..ports import DiscordUnavailable
from ..service import Service
from ..signals import MAX_REPORT_BYTES
from .oauth import DiscordOAuth, OAuthError, account_from

log = logging.getLogger("altwarden.web")

STATIC = Path(__file__).parent / "static"
DEVICE_COOKIE = "__Host-aw_device"
FLOW_COOKIE = "__Host-aw_flow"
SESSION_COOKIE = "__Host-aw_session"
BROWSER_COOKIE = "__Host-aw_browser"
FLOW_SECONDS = 900
DASHBOARD_SECONDS = 12 * 3600
MEMBER_SECONDS = 1800
TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{20,64}")
# A Discord ID as a route. int() reads "0123" as 123, so a padded ID would reach the server but miss its settings.
SNOWFLAKE = "[1-9][0-9]{14,20}"
ADMINISTRATOR = 1 << 3
MANAGE_GUILD = 1 << 5
# A path on this site. Browsers read a backslash as a slash, so "/\evil.example" would leave the site.
LOCAL_PATH = re.compile(r"/(?![/\\])[A-Za-z0-9/_.?=&%-]*")

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' https://cdn.discordapp.com data:; "
       "font-src 'self'; connect-src 'self'; worker-src 'self'; frame-src 'self'; base-uri 'none'; "
       "form-action 'self'; frame-ancestors 'none'")
# Staff can point a message's picture at any https address, and the preview has to be able to show it.
# Member pages keep the strict rule above.
DASHBOARD_CSP = CSP.replace("img-src 'self' https://cdn.discordapp.com data:", "img-src 'self' https: data:")
SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Strict-Transport-Security": "max-age=31536000",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=()",
    # Asks Chromium browsers for the hints the identity check compares with the user agent.
    "Accept-CH": "Sec-CH-UA-Platform",
}
PAGES = {"/": "index.html", "/privacy": "privacy.html", "/terms": "terms.html", "/security": "security.html", "/docs": "docs.html"}


class RateLimiter:
    """A small token bucket per key. Keys are hashed with a key that dies with the process, and live in memory only."""

    MAX_KEYS = 100_000

    def __init__(self) -> None:
        self.buckets: dict[bytes, tuple[float, float]] = {}
        self.salt = secrets.token_bytes(16)

    def allow(self, key: str, *, per_minute: int, burst: int) -> bool:
        name = hashlib.blake2b(key.encode(), key=self.salt, digest_size=16).digest()
        now = time.monotonic()
        tokens, last = self.buckets.pop(name, (float(burst), now))
        tokens = min(float(burst), tokens + (now - last) * per_minute / 60)
        permitted = tokens >= 1
        self.buckets[name] = (tokens - 1 if permitted else tokens, now)
        if len(self.buckets) > self.MAX_KEYS:
            # Every use moves a key to the end, so the first is the one unused for longest. Flooding
            # the table can't free a key that is still being refused.
            del self.buckets[next(iter(self.buckets))]
        return permitted


def client_ip(request: web.Request) -> str:
    """The member's address, which only the local proxy can vouch for.

    The proxy adds its own line after anything the client sent, and the real address is the last
    value on that line. A forged header followed by any other header arrives as an earlier line,
    so the first line can't be trusted.
    """
    peer = request.remote or ""
    if request.app["trust_proxy"]:
        try:
            if ipaddress.ip_address(peer).is_loopback:
                lines = request.headers.getall("X-Forwarded-For", [])
                if lines:
                    candidate = lines[-1].split(",")[-1].strip()
                    ipaddress.ip_address(candidate)
                    return candidate
        except ValueError:
            pass
    return peer


def set_cookie(response: web.StreamResponse, name: str, value: str, max_age: int, request: web.Request) -> None:
    response.set_cookie(name, value, max_age=max_age, path="/", secure=True, httponly=True, samesite="Lax")


def json_error(status: int, message: str, **extra) -> web.Response:
    return web.json_response({"error": message, **extra}, status=status)


def parse_json(raw: bytes):
    """Parse a request body. Python's parser lets through a lone surrogate, which the database can't store, so that goes too."""
    value = json.loads(raw)
    json.dumps(value, ensure_ascii=False).encode()
    return value


async def read_json(request: web.Request):
    try:
        return parse_json(await request.read())
    except (ValueError, RecursionError):  # ValueError covers bad JSON, bad text, and numbers too long to convert
        raise web.HTTPBadRequest(text="That request wasn't valid.")


def same_text(first: str, second: str) -> bool:
    """A constant-time compare. compare_digest refuses non-ASCII text, and a header or cookie can hold any bytes."""
    return hmac.compare_digest(first.encode("utf-8", "surrogatepass"), second.encode("utf-8", "surrogatepass"))


@web.middleware
async def errors(request: web.Request, handler):
    try:
        return await handler(request)
    except web.HTTPException:
        raise
    except Exception:
        # The route's pattern, because the path itself can hold someone's verification link.
        resource = request.match_info.route.resource
        log.exception("Unhandled error on %s %s", request.method, resource.canonical if resource else "an unknown path")
        if request.path.startswith("/api/"):
            return json_error(500, "Something went wrong on our side.")
        return web.Response(status=500, text="Something went wrong on our side.")


async def add_headers(request: web.Request, response: web.StreamResponse) -> None:
    for key, value in SECURITY_HEADERS.items():
        response.headers.setdefault(key, value)
    if request.path.startswith("/api/") or request.path.startswith("/v/"):
        response.headers["Cache-Control"] = "no-store"
    elif request.path.startswith("/static/vendor/"):
        response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    elif request.path.startswith("/static/"):
        # A browser may keep these, but has to ask first, or a deploy wouldn't reach it for as long as it held its copy.
        response.headers["Cache-Control"] = "no-cache"


def page(name: str, csp: str | None = None):
    html = (STATIC / name).read_bytes()
    headers = {"Content-Security-Policy": csp} if csp else None

    async def handler(request: web.Request) -> web.Response:
        return web.Response(body=html, content_type="text/html", charset="utf-8", headers=headers)
    return handler


def limited(request: web.Request, bucket: str, *, per_minute: int, burst: int) -> bool:
    address = client_ip(request)
    try:
        address = network_of(address)  # one IPv6 connection holds a whole /64, so it counts as one address
    except ValueError:
        pass
    return not request.app["limits"].allow(f"{bucket}:{address}", per_minute=per_minute, burst=burst)


# --- verification flow -------------------------------------------------------------------------

def _token(request: web.Request) -> str:
    token = request.match_info["token"]
    if not TOKEN_PATTERN.fullmatch(token):
        raise web.HTTPNotFound()
    return token


def _browser_hash(token: str, browser: str) -> str:
    """Hashed with the link, so one browser leaves unrelated values on links for two servers."""
    return token_hash(f"{token}.{browser}")


def _same_browser(request: web.Request, token: str, row: dict) -> bool:
    """A link only runs in the browser that signed in. Otherwise someone could sign in, send the link
    to another person, and pass on that person's browser and connection, and leave that person's
    cookie on their own record."""
    wanted = row["browser_hash"]
    return wanted is None or same_text(_browser_hash(token, request.cookies.get(BROWSER_COOKIE, "")), wanted)


async def verify_state(request: web.Request) -> web.Response:
    """What the verification page needs to draw itself."""
    if limited(request, "state", per_minute=60, burst=30):
        return json_error(429, "Too many requests.")
    token = _token(request)
    service: Service = request.app["service"]
    row = await service.session(token)
    if row is None or row["expires_at"] <= time.time() or row["state"] == "closed":
        return web.json_response({"step": "expired"})
    guild = await service.port.guild(row["guild_id"])
    try:
        member = await service.port.member(row["guild_id"], row["user_id"])
    except DiscordUnavailable:
        member = None  # only the name on the page goes missing, and the check itself finds out properly
    settings = await service.get_settings(row["guild_id"])
    step = {"open": "signin", "signed_in": "check", "checking": "check", "done": "done"}[row["state"]]
    if step == "check" and not _same_browser(request, token, row):
        step = "signin"
    return web.json_response({
        "step": step,
        "tried": row["finished_at"] is not None,
        "appeal": bool(settings and settings["appeals"]["enabled"]),
        "direct": bool(settings and settings["core"]["direct_signin"]),
        "guild": {"id": row["guild_id"], "name": guild.name if guild else "this server", "icon": guild.icon if guild else None},
        "member": {"id": row["user_id"], "name": member.username if member else "", "avatar": member.avatar if member else None},
        "expires_at": row["expires_at"],
        "bypass": bool(row["bypass"]),
    })


async def verify_signin(request: web.Request) -> web.Response:
    """Tie a new state value to this browser, then send the member to Discord."""
    token = _token(request)
    service: Service = request.app["service"]
    row = await service.session(token)
    if row is None or row["expires_at"] <= time.time() or row["state"] in ("done", "closed"):
        raise web.HTTPFound(f"/v/{token}")
    settings = await service.get_settings(row["guild_id"])
    state = new_token(24)
    await service.db.run("UPDATE sessions SET auth_state_hash = ? WHERE token_hash = ?", (token_hash(state), token_hash(token)))
    scopes = ["identify"]
    if settings and settings["checks"]["disposable_email"]["enabled"]:
        scopes.append("email")
    url = request.app["oauth"].authorize_url(redirect_uri=f"{service.public_url}/verify/callback", state=state, scopes=scopes)
    response = web.HTTPFound(url)
    set_cookie(response, FLOW_COOKIE, f"{state}.{token}", FLOW_SECONDS, request)
    raise response


async def verify_callback(request: web.Request) -> web.Response:
    """The only page that ever sees Discord's code. It loads nothing and redirects straight away."""
    service: Service = request.app["service"]
    flow = request.cookies.get(FLOW_COOKIE, "")
    state, _, token = flow.partition(".")
    given = request.query.get("state", "")
    if not state or not token or not same_text(state, given):
        raise web.HTTPFound("/help/link-expired")
    row = await service.session(token)
    if row is None or row["auth_state_hash"] != token_hash(state):
        raise web.HTTPFound("/help/link-expired")
    await service.db.run("UPDATE sessions SET auth_state_hash = NULL WHERE token_hash = ?", (token_hash(token),))
    target = f"/v/{token}"
    if "error" in request.query or "code" not in request.query:
        response = web.HTTPFound(f"{target}?signin=declined")
    else:
        settings = await service.get_settings(row["guild_id"])
        wants_email = bool(settings and settings["checks"]["disposable_email"]["enabled"])
        try:
            me, _ = await request.app["oauth"].identify(request.query["code"], f"{service.public_url}/verify/callback")
        except (OAuthError, aiohttp.ClientError) as exc:
            log.warning("Discord sign-in failed: %s", exc)
            response = web.HTTPFound(f"{target}?signin=failed")
        else:
            account = account_from(me, service.net.is_disposable, wants_email=wants_email)
            browser = request.cookies.get(BROWSER_COOKIE, "")
            if not TOKEN_PATTERN.fullmatch(browser):
                browser = new_token(24)
            problem = await service.attach_account(token, account, browser=_browser_hash(token, browser))
            response = web.HTTPFound(f"{target}?signin=wrong" if problem == "wrong_account" else target)
            if problem is None:
                response.set_cookie(BROWSER_COOKIE, browser, path="/", secure=True, httponly=True, samesite="Lax")  # gone when the browser closes
    response.del_cookie(FLOW_COOKIE, path="/", secure=True, httponly=True, samesite="Lax")
    raise response


async def verify_challenge(request: web.Request) -> web.Response:
    if limited(request, "challenge", per_minute=30, burst=10):
        return json_error(429, "Too many requests.")
    service: Service = request.app["service"]
    token = _token(request)
    row = await service.session(token)
    if row is None or not _same_browser(request, token, row):
        return json_error(409, "This link can't be used right now.")
    challenge = await service.issue_challenge(token)
    if challenge is None:
        return json_error(409, "This link can't be used right now.")
    response = web.json_response(challenge)
    keys: Keyring = request.app["keys"]
    if keys.read_device_cookie(request.cookies.get(DEVICE_COOKIE)) is None:
        settings = await service.get_settings(row["guild_id"])
        days = settings["privacy"]["identifier_days"] if settings else 365
        set_cookie(response, DEVICE_COOKIE, keys.new_device_cookie(), min(days, 400) * 86400, request)
    return response


async def verify_submit(request: web.Request) -> web.Response:
    if limited(request, "submit", per_minute=20, burst=6):
        return json_error(429, "Too many requests.")
    raw = await request.read()  # a chunked request announces no length, so the size is checked on what arrived
    if len(raw) > MAX_REPORT_BYTES:
        return json_error(413, "That report is too large.")
    token = _token(request)
    service: Service = request.app["service"]
    try:
        body = parse_json(raw)
    except (ValueError, RecursionError):
        return json_error(400, "That request wasn't valid.")
    if not isinstance(body, dict) or not isinstance(body.get("nonce"), str) or not isinstance(body.get("report"), dict):
        return json_error(400, "That request wasn't valid.")
    salt_row = await service.session(token)
    if salt_row is None or not salt_row["pow_salt"] or not _same_browser(request, token, salt_row):
        return json_error(409, "This link can't be used right now.")
    counter = body.get("counter")
    if not isinstance(counter, int) or not pow_solved(salt_row["pow_salt"], counter, salt_row["pow_bits"]):
        return json_error(400, "The security check didn't finish.", reason="security_check")
    row = await service.claim_submission(token, body["nonce"])
    if row is None:
        return json_error(409, "This attempt was already used. Reload the page to try again.")
    keys: Keyring = request.app["keys"]
    device_id = keys.read_device_cookie(request.cookies.get(DEVICE_COOKIE))
    try:
        result = await service.submit_web(token, row, body["report"], ip=client_ip(request), headers=dict(request.headers), device_id=device_id)
    except Exception:
        await service.release(token)
        raise
    return web.json_response(result.as_dict())


async def verify_help(request: web.Request) -> web.Response:
    """Open a private help thread from the result page, for servers that chose this."""
    if limited(request, "help", per_minute=6, burst=3):
        return json_error(429, "Too many requests.")
    service: Service = request.app["service"]
    token = _token(request)
    row = await service.session(token)
    # "opened_at" means they signed in. What the sign-in read may be gone by now, and they can still need help.
    if row is None or row["opened_at"] is None or row["expires_at"] <= time.time() or not _same_browser(request, token, row):
        return json_error(409, "This link can't be used right now.")
    member = await service.port.member(row["guild_id"], row["user_id"])
    if member is None:
        return json_error(409, "You're no longer in the server.")
    thread_id, message = await service.open_help(member)
    if thread_id is None:
        return json_error(400, message)
    return web.json_response({"url": f"https://discord.com/channels/{row['guild_id']}/{thread_id}"})


# --- sign-in for the dashboard, appeals and "my data" ------------------------------------------

async def login(request: web.Request) -> web.Response:
    if limited(request, "login", per_minute=20, burst=10):
        return web.Response(status=429, text="Too many sign-ins. Wait a minute and try again.")
    service: Service = request.app["service"]
    purpose = request.query.get("for", "dashboard")
    if purpose not in ("dashboard", "member"):
        raise web.HTTPBadRequest()
    # Until Discord hands the servers over, there's no telling which of a person's servers the dashboard can show.
    if purpose == "dashboard" and await service.port.guild_loading("0"):
        return web.Response(status=503, text="AltWarden is starting up. Try again in a minute.")
    next_path = request.query.get("next", "/dashboard")
    if not LOCAL_PATH.fullmatch(next_path):
        next_path = "/dashboard"
    state = new_token(24)
    await service.db.run("INSERT INTO login_states VALUES (?, ?, ?, ?)", (token_hash(state), purpose, next_path, time.time() + FLOW_SECONDS))
    scopes = ["identify", "guilds"] if purpose == "dashboard" else ["identify"]
    url = request.app["oauth"].authorize_url(redirect_uri=f"{service.public_url}/dashboard/callback", state=state, scopes=scopes)
    response = web.HTTPFound(url)
    set_cookie(response, FLOW_COOKIE, state, FLOW_SECONDS, request)
    raise response


async def login_callback(request: web.Request) -> web.Response:
    service: Service = request.app["service"]
    state = request.cookies.get(FLOW_COOKIE, "")
    if not state or not same_text(state, request.query.get("state", "")):
        raise web.HTTPFound("/")
    row = await service.db.one("SELECT * FROM login_states WHERE state_hash = ?", (token_hash(state),))
    await service.db.run("DELETE FROM login_states WHERE state_hash = ?", (token_hash(state),))
    if row is not None and row["purpose"] == "commands":
        outcome = await finish_command_sync(request, token_hash(state), row)
        response = web.HTTPFound(f"{row['next_path']}?discord={outcome}")
        response.del_cookie(FLOW_COOKIE, path="/", secure=True, httponly=True, samesite="Lax")
        raise response
    if row is None or row["expires_at"] < time.time() or "code" not in request.query:
        raise web.HTTPFound("/")
    dashboard = row["purpose"] == "dashboard"
    try:
        me, guilds = await request.app["oauth"].identify(request.query["code"], f"{service.public_url}/dashboard/callback", guilds=dashboard)
    except (OAuthError, aiohttp.ClientError) as exc:
        log.warning("Sign-in failed: %s", exc)
        raise web.HTTPFound("/")
    token = new_token()
    now = time.time()
    lifetime = DASHBOARD_SECONDS if dashboard else MEMBER_SECONDS
    # Only servers the dashboard can show. The rest of a person's server list is none of AltWarden's business.
    kept = [{"id": str(g["id"]), "name": g.get("name", ""), "icon": g.get("icon"), "owner": bool(g.get("owner")),
             "permissions": str(g.get("permissions", "0"))} for g in guilds
            if g.get("owner") or int(g.get("permissions") or 0) & (ADMINISTRATOR | MANAGE_GUILD) or await service.port.guild(str(g["id"])) is not None
            or await service.port.guild_loading(str(g["id"]))]
    await service.db.run(
        "INSERT INTO web_sessions (token_hash, user_id, username, avatar, guilds, csrf, scope, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (token_hash(token), str(me["id"]), str(me.get("global_name") or me.get("username", ""))[:40], me.get("avatar"), json.dumps(kept),
         secrets.token_urlsafe(24), row["purpose"], now, now + lifetime))
    response = web.HTTPFound(row["next_path"])
    response.del_cookie(FLOW_COOKIE, path="/", secure=True, httponly=True, samesite="Lax")
    set_cookie(response, SESSION_COOKIE, token, lifetime, request)
    raise response


async def finish_command_sync(request: web.Request, state_hash: str, login: dict) -> str:
    """Write the held command permissions with the token Discord just issued, then revoke it. Returns the result's name."""
    service: Service = request.app["service"]
    oauth: DiscordOAuth = request.app["oauth"]
    held = await service.db.one("SELECT * FROM command_syncs WHERE state_hash = ?", (state_hash,))
    await service.db.run("DELETE FROM command_syncs WHERE state_hash = ?", (state_hash,))
    session = await current_session(request)
    if held is None or login["expires_at"] < time.time() or session is None or session["user_id"] != held["user_id"]:
        return "expired"
    if "code" not in request.query:
        return "declined"
    changes = json.loads(held["changes"])
    try:
        token = await oauth.exchange(request.query["code"], f"{service.public_url}/dashboard/callback")
    except (OAuthError, aiohttp.ClientError) as exc:
        log.warning("Command permission sign-in failed: %s", exc)
        return "failed"
    done: list[str] = []
    refused = False
    try:
        me = await oauth.read(token, "/users/@me")
        if str(me["id"]) != held["user_id"]:
            return "wrong-account"
        for change in changes:
            status = await oauth.edit_command_permissions(token, held["guild_id"], change["id"], change["overrides"])
            if status == 200:
                done.append(change["name"])
            else:
                log.warning("Discord answered %s to a command permission write", status)
                refused = True
    except (OAuthError, aiohttp.ClientError) as exc:
        log.warning("Command permission write failed: %s", exc)
        refused = True
    finally:
        await oauth.revoke(token)
    if done:
        await service.note_command_sync(held["guild_id"], held["user_id"], session["username"], done)
    return "refused" if refused else "saved"


async def current_session(request: web.Request) -> dict | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    service: Service = request.app["service"]
    row = await service.db.one("SELECT * FROM web_sessions WHERE token_hash = ? AND expires_at > ?", (token_hash(token), time.time()))
    if row:
        row["guilds"] = json.loads(row["guilds"])
    return row


def csrf_ok(request: web.Request, session: dict) -> bool:
    """State-changing calls need the session's token and a same-site origin."""
    origin = request.headers.get("Origin")
    public = request.app["service"].public_url
    if origin is not None and origin != public:
        return False
    return same_text(request.headers.get("X-CSRF-Token", ""), session["csrf"])


async def logout(request: web.Request) -> web.Response:
    session = await current_session(request)
    if session is None or not csrf_ok(request, session):
        return json_error(403, "Not allowed.")
    await request.app["service"].db.run("DELETE FROM web_sessions WHERE token_hash = ?", (session["token_hash"],))
    response = web.json_response({"ok": True})
    response.del_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="Lax")
    return response


# --- members' own data and appeals -------------------------------------------------------------

async def me_data(request: web.Request) -> web.Response:
    session = await current_session(request)
    if session is None:
        return json_error(401, "Sign in first.", login=f"/login?for=member&next={request.query.get('next', '/my-data')}")
    if limited(request, "my-data", per_minute=20, burst=10):
        return json_error(429, "Too many requests.")
    service: Service = request.app["service"]
    return web.json_response({"user": {"id": session["user_id"], "name": session["username"], "avatar": session["avatar"]},
                              "csrf": session["csrf"], "records": await service.my_data(session["user_id"])})


async def me_delete(request: web.Request) -> web.Response:
    session = await current_session(request)
    if session is None or not csrf_ok(request, session):
        return json_error(403, "Sign in first.")
    if limited(request, "my-data-delete", per_minute=6, burst=3):
        return json_error(429, "Too many requests.")
    body = await read_json(request)
    guild_id = body.get("guild_id") if isinstance(body, dict) else None
    if guild_id is not None and not re.fullmatch(r"\d{15,21}", str(guild_id)):
        return json_error(400, "That request wasn't valid.")
    service: Service = request.app["service"]
    return web.json_response(await service.delete_my_data(session["user_id"], guild_id))


async def me_appeal_state(request: web.Request) -> web.Response:
    session = await current_session(request)
    guild_id = request.match_info["guild_id"]
    if session is None:
        return json_error(401, "Sign in first.", login=f"/login?for=member&next=/appeal/{guild_id}")
    if limited(request, "appeal-state", per_minute=30, burst=10):
        return json_error(429, "Too many requests.")
    service: Service = request.app["service"]
    last = await service.db.one("SELECT check_id, at FROM attempts WHERE guild_id = ? AND user_id = ? AND outcome = 'failed' ORDER BY at DESC LIMIT 1",
                                (guild_id, session["user_id"]))
    # A server's name and icon go only to someone with a reason to see them, not to anyone who guesses its ID.
    known = last is not None or await service.port.member(guild_id, session["user_id"]) is not None
    guild = await service.port.guild(guild_id) if known else None
    open_appeal = await service.db.scalar("SELECT 1 FROM appeals WHERE guild_id = ? AND user_id = ? AND status IN ('open', 'deciding')", (guild_id, session["user_id"]))
    return web.json_response({"user": {"id": session["user_id"], "name": session["username"], "avatar": session["avatar"]}, "csrf": session["csrf"],
                              "guild": {"id": guild_id, "name": guild.name if guild else "this server", "icon": guild.icon if guild else None},
                              "check": last["check_id"] if last else None, "open": bool(open_appeal)})


async def me_appeal(request: web.Request) -> web.Response:
    session = await current_session(request)
    if session is None or not csrf_ok(request, session):
        return json_error(403, "Sign in first.")
    if limited(request, "appeal", per_minute=6, burst=3):
        return json_error(429, "Too many requests.")
    body = await read_json(request)
    text = body.get("text") if isinstance(body, dict) else None
    if not isinstance(text, str):
        return json_error(400, "That request wasn't valid.")
    service: Service = request.app["service"]
    problem = await service.submit_appeal(request.match_info["guild_id"], session["user_id"], session["username"], text)
    return json_error(400, problem) if problem else web.json_response({"ok": True})


async def healthz(request: web.Request) -> web.Response:
    service: Service = request.app["service"]
    return web.json_response({"ok": True, "version": __version__, "lists_loaded": service.net.ready})


async def security_txt(request: web.Request) -> web.Response:
    url = request.app["service"].public_url
    text = (f"Contact: https://github.com/hifihedgehog/AltWarden/security/advisories/new\n"
            f"Policy: {url}/security\nPreferred-Languages: en\nCanonical: {url}/.well-known/security.txt\n")
    return web.Response(text=text, content_type="text/plain")


def build_app(service: Service, keys: Keyring, oauth: DiscordOAuth, *, trust_proxy: bool = True, debug_insecure: bool = False) -> web.Application:
    # The verification report has its own 64 KB limit. A server's access rules can run much longer.
    app = web.Application(middlewares=[errors], client_max_size=1024 * 1024)
    app["service"] = service
    app["keys"] = keys
    app["oauth"] = oauth
    app["limits"] = RateLimiter()
    app["trust_proxy"] = trust_proxy
    app.on_response_prepare.append(add_headers)

    from .api import routes as api_routes
    add = app.router.add_get
    for path, name in PAGES.items():
        add(path, page(name))
    add("/v/{token}", page("verify.html"))
    add("/v/{token}/signin", verify_signin)
    add("/verify/callback", verify_callback)
    add("/help", page("help.html"))
    add("/help/{slug}", page("help.html"))
    add("/my-data", page("mydata.html"))
    add(f"/appeal/{{guild_id:{SNOWFLAKE}}}", page("appeal.html"))
    add("/dashboard", page("dashboard.html", DASHBOARD_CSP))
    add("/dashboard/callback", login_callback)
    add("/dashboard/{tail:.*}", page("dashboard.html", DASHBOARD_CSP))
    add("/login", login)
    add("/healthz", healthz)
    add("/.well-known/security.txt", security_txt)
    add("/api/verify/{token}", verify_state)
    app.router.add_post("/api/verify/{token}/challenge", verify_challenge)
    app.router.add_post("/api/verify/{token}/submit", verify_submit)
    app.router.add_post("/api/verify/{token}/help", verify_help)
    app.router.add_post("/api/logout", logout)
    add("/api/me/data", me_data)
    app.router.add_post("/api/me/delete", me_delete)
    add(f"/api/me/appeal/{{guild_id:{SNOWFLAKE}}}", me_appeal_state)
    app.router.add_post(f"/api/me/appeal/{{guild_id:{SNOWFLAKE}}}", me_appeal)
    api_routes(app)
    app.router.add_static("/static", STATIC, show_index=False, follow_symlinks=False)
    return app


__all__ = ["CHECK_IDS", "WEB", "build_app", "client_ip", "csrf_ok", "current_session", "json_error"]
