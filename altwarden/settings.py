"""Per-server settings: defaults, validation, presets, and the shareable export.

Everything a server configures lives in one JSON document. `normalize` is the only way a
document gets in. It keeps known keys, clamps numbers to their allowed range and drops the rest,
so the dashboard, the import box and the database all pass through one gate.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import unicodedata
import zlib
from collections import Counter
from functools import cache
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .catalog import (ACTIONS, BAN, BY_ID, CHECK_IDS, DEFAULT_PRESET, DENY, HONEYPOT_ACTIONS, IMPORTANT_ALERTS, KICK, LOG_MODULES,
                      MODES, PRESETS, WATCH, WEB)

SCHEMA_VERSION = 1
CONFIDENCE_LEVELS = ("possible", "likely", "confirmed")
MAIN_ACTIONS = (WATCH, KICK, BAN)
MIN_RESET_MINUTES = 5
def alert_role(document: dict, module: str) -> str | None:
    """The role a module's alert pings: its own if it has one, or the main role for the modules that use it."""
    alerts = document["core"]["alerts"]
    if not alerts["enabled"]:
        return None
    if module in alerts["roles"]:
        return alerts["roles"][module]
    return alerts["role"] if module in IMPORTANT_ALERTS and module not in alerts["off"] else None


MAX_EXPORT_BYTES = 64 * 1024
REVISION_SECTIONS = {"rules": None, "access": ("permissions",), "look": ("messages", "appearance")}
OTHER_SECTIONS = ("permissions", "messages", "appearance")
COUNTRIES = Path(__file__).resolve().parent / "web" / "static" / "countries.json"
IMPORTED_SWITCHES = {"logs": ("enabled",), "alerts": ("enabled", "off"),
                     "help_desk": ("enabled", "require_attempt", "redirect", "auto_close", "member_close")}

DEFAULT_MESSAGES = {
    "verification": {
        "content": "",
        "title": "Verify to continue",
        "description": "This server checks new members before letting them in. Press the button to start. "
                       "It takes a few seconds.",
        "color": 0x1FB8A6,
        "thumbnail": "",
        "image": "",
        "footer": "",
        "verify_label": "Verify",
        "verify_emoji": "",
        "verify_style": "success",
        "help_label": "Get help",
        "help_emoji": "",
        "help_style": "secondary",
        "author": None,
    },
    "help_desk": {
        "content": "",
        "title": "Tell us what went wrong",
        "description": "Describe what happened, and staff will pick this up here. Your failed attempts are listed below.",
        "color": 0x1FB8A6,
        "thumbnail": "",
        "image": "",
        "footer": "",
        "author": None,
    },
    "honeypot": {
        "content": "Do not post here. This channel is a trap for spam accounts.",
        "title": "Do not post in this channel",
        "description": "Anything posted here is removed, and the account that posted it is acted on automatically.",
        "color": 0xE5484D,
        "thumbnail": "",
        "image": "",
        "footer": "",
        "author": None,
    },
}
# Emoji that Unicode files outside "Symbol, other": double and interrobang marks, info, arrows, squares, wavy dash, part mark.
EMOJI_OUTSIDE_SYMBOLS = frozenset("\u203c\u2049\u2139\u2194\u25fb\u25fc\u25fd\u25fe\u2934\u2935\u3030\u303d")
BUTTON_STYLES = ("primary", "secondary", "success", "danger")
AVATAR_COLORS = ("teal", "blue", "red", "orange", "yellow", "green", "purple", "pink")
AVATAR_HEX = {"teal": 0x29CDB9, "blue": 0x599DF8, "red": 0xF66B6B, "orange": 0xF98C37, "yellow": 0xF5C513, "green": 0x42D578,
              "purple": 0xBB7BFA, "pink": 0xF26CB1}
# Discord's name fonts and effects, with the names its own picker shows. Fonts it retired are left out.
DEFAULT_NAME_FONT = 11
NAME_FONTS = {11: "gg sans", 12: "Tempo", 3: "Sakura", 4: "Jellybean", 6: "Modern", 7: "Medieval", 8: "8Bit", 10: "Vampyre",
              13: "Monkey Bars", 14: "Mainframe", 15: "Headbang", 16: "Journal"}
SOLID_EFFECT = 1
NAME_EFFECTS = {1: ("Solid", 1), 2: ("Gradient", 2), 3: ("Neon", 1), 4: ("Toon", 1), 5: ("Pop", 1), 7: ("Prism", 5), 8: ("Gummy", 4)}
MESSAGE_NAMES = {"verification": "The verification message", "help_desk": "The help desk message", "honeypot": "The honeypot warning"}
# Discord refuses an embed over 6000 characters. This leaves room for a server's name and the writer's line.
MESSAGE_ROOM = 5800

# Dashboard pages and commands use the same rule shape: required permissions plus overrides.
PAGE_DEFAULTS = {
    "analytics": {"view": ["manage_guild"]},
    # Editing the rules can make the bot kick and ban, so it takes those permissions too.
    "settings": {"view": ["manage_guild"], "edit": ["manage_guild", "manage_roles", "manage_channels", "manage_messages", "moderate_members",
                                                    "kick_members", "ban_members"]},
    "members": {"view": ["manage_guild"]},
    "health": {"view": ["manage_guild"]},
    "permissions": {"view": ["manage_guild"], "edit": ["manage_guild", "manage_roles"]},
    "appearance": {"view": ["manage_guild"], "edit": ["manage_guild", "manage_messages", "manage_nicknames"]},
    "appeals": {"view": ["manage_roles"], "edit": ["manage_roles"]},
    "audit": {"view": ["manage_guild"]},
    "integrations": {"view": ["manage_guild"], "edit": ["manage_guild"]},
}
COMMAND_DEFAULTS = {
    "verify-user": ["manage_roles"],
    "reset-user": ["manage_roles"],
    "create-bypass": ["manage_roles"],
    "trust-accounts": ["manage_roles"],
    "lookup": ["manage_roles"],
    "setup": ["manage_guild"],
    "settings": ["manage_guild"],
    "post-message": ["manage_guild"],
    "health": ["manage_guild"],
    "uninstall": ["administrator"],
    "import-members": ["manage_guild", "manage_roles"],
    "raid": ["manage_guild", "kick_members"],
}
PERMISSION_NAMES = ("administrator", "manage_guild", "manage_roles", "manage_channels", "manage_messages",
                    "manage_nicknames", "moderate_members", "kick_members", "ban_members", "view_audit_log")


def _snowflake(value: Any) -> str | None:
    """IDs stay strings in JSON, because a 64-bit integer doesn't survive JavaScript."""
    text = str(value).strip() if value is not None else ""
    return text if re.fullmatch(r"[0-9]{15,21}", text) else None


def _int(value: Any, low: int, high: int, fallback: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):  # JSON's 1e999 arrives as infinity
        return fallback
    return max(low, min(high, number))


def _bool(value: Any, fallback: bool) -> bool:
    return value if isinstance(value, bool) else fallback


def _choice(value: Any, options: tuple, fallback: Any) -> Any:
    return value if value in options else fallback


def _text(value: Any, limit: int, fallback: str = "") -> str:
    return value[:limit] if isinstance(value, str) else fallback


def _https_url(value: Any) -> str:
    """An https address with a host and no spaces or control characters. Cutting a longer one would change where it points."""
    text = value.strip() if isinstance(value, str) else ""
    if not text.startswith("https://") or len(text) > 2000 or any(character.isspace() or not character.isprintable() for character in text):
        return ""
    try:
        return text if urlsplit(text).hostname else ""
    except ValueError:
        return ""


def _emoji_base(character: str) -> bool:
    """Whether a character can start an emoji: a symbol past Latin-1, the copyright and registered signs, or one of the few filed elsewhere."""
    return character in EMOJI_OUTSIDE_SYMBOLS or (unicodedata.category(character) == "So" and (ord(character) > 0xFF or character in "\u00a9\u00ae"))


def _single_emoji(text: str) -> bool:
    """One emoji as a person sees it: a flag, a keycap, or symbols joined by ZWJ with skin tones and VS16.

    Checks the shape from Unicode's categories, with no emoji table to keep current, so a plain symbol
    such as a check mark passes too.
    """
    if re.fullmatch("[\U0001F1E6-\U0001F1FF]{2}", text) or re.fullmatch("[0-9#*]\uFE0F?\u20E3", text):
        return True
    if re.fullmatch("\U0001F3F4[\U000E0061-\U000E007A\U000E0030-\U000E0039]+\U000E007F", text):
        return True  # the flags of England, Scotland and Wales
    parts = text.split("\u200d")
    return all(_emoji_part(part) for part in parts)


def _emoji_part(part: str) -> bool:
    found = re.fullmatch("(.)[\U0001F3FB-\U0001F3FF]?\uFE0F?", part, re.DOTALL)
    return bool(found) and _emoji_base(found.group(1))


def _emoji(value: Any) -> str:
    """A custom emoji in Discord's <:name:id> form, or one Unicode emoji.

    Anything else would make Discord refuse the whole message, which would take the Verify button
    down with it.
    """
    text = _text(value, 64).strip()
    if re.fullmatch(r"<a?:[A-Za-z0-9_]{2,32}:[0-9]{15,21}>", text):
        return text
    return text if text and _single_emoji(text) else ""


def _snowflake_list(value: Any, limit: int = 100) -> list[str]:
    if not isinstance(value, list):
        return []
    found = [_snowflake(item) for item in value[:limit]]
    return [item for item in dict.fromkeys(found) if item]


def _table_id(value: Any, table: dict) -> int | None:
    """An ID from a table of fonts or effects. Booleans are integers in Python, so they need turning away."""
    return value if isinstance(value, int) and not isinstance(value, bool) and value in table else None


def _name_style(raw: dict) -> dict:
    """A font, an effect, and exactly as many colors as the effect needs, or no style at all.

    Discord turns away a style with the wrong number of colors, so the count gets fixed here.
    """
    font = _table_id(raw.get("font"), NAME_FONTS)
    effect = _table_id(raw.get("effect"), NAME_EFFECTS)
    if font is None and effect is None:
        return {"font": None, "effect": None, "colors": []}
    effect = effect or SOLID_EFFECT
    given = raw.get("colors") if isinstance(raw.get("colors"), list) else []
    colors = [value for value in given if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 0xFFFFFF]
    colors += [value for value in AVATAR_HEX.values() if value not in colors]
    return {"font": font or DEFAULT_NAME_FONT, "effect": effect, "colors": colors[:NAME_EFFECTS[effect][1]]}


def _check_defaults() -> dict:
    """Every option of every check, before a preset is applied."""
    checks: dict[str, dict] = {check_id: {"enabled": False, "action": DENY} for check_id in CHECK_IDS}
    checks["account_age"]["days"] = 7
    checks["alt_account"].update({
        "methods": {"cookie": True, "fingerprint": True, "ip": True},
        "min_confidence": "likely",
        "main_action": WATCH,
        "alt_action": DENY,
        "banned_alt_action": BAN,
    })
    checks["max_attempts"].update({"attempts": 5, "role": None, "reset_minutes": 1440})
    checks["tampering"]["anomaly_score"] = 50
    checks["threat"].update({"bot_score": 80, "suspect_score": 70})
    checks["geogate"].update({"list": "block", "countries": [], "overrides": {}})
    return checks


def defaults() -> dict:
    """A new server's document, with the default preset applied."""
    settings = {
        "version": SCHEMA_VERSION,
        "preset": DEFAULT_PRESET,
        "core": {
            "verified_role": None,
            "channel": None,
            "mode": WEB,
            "unverified_role": None,
            "unverified_enabled": False,
            "auto_dm": True,
            "notify_closed_dms": {"enabled": True, "seconds": 30},
            "auto_kick": {"enabled": False, "minutes": 10},
            "cooldown": {"enabled": False, "seconds": 60},
            "remember_rejoin": False,
            "fail_open": False,
            "show_reason": True,
            "external_vpn_lookup": False,
            "direct_signin": False,
            "logs": {"enabled": False, "modules": {}},
            "alerts": {"enabled": True, "role": None, "off": [], "roles": {}},
            "help_desk": {"enabled": False, "support_role": None, "require_attempt": True, "redirect": False,
                          "auto_close": False, "member_close": False},
        },
        "checks": _check_defaults(),
        "honeypot": {"enabled": False, "channel": None, "action": "softban", "timeout_minutes": 60,
                     "whitelist_roles": []},
        "raid": {"enabled": True, "joins": 15, "seconds": 60, "duration_minutes": 15, "min_account_days": 7,
                 "alert_role": None},
        "appeals": {"enabled": True, "channel": None, "role": None},
        "privacy": {"identifier_days": 365, "ip_days": 30, "attempt_days": 365, "banned_days": 730},
        "messages": copy.deepcopy(DEFAULT_MESSAGES),
        "appearance": {"nickname": "", "bio": "", "avatar": "", "font": None, "effect": None, "colors": []},
        "permissions": {"pages": {}, "commands": {}},
    }
    settings["checks"]["mfa"]["enabled"] = True  # no preset touches this one, so it starts on here
    return apply_preset(settings, DEFAULT_PRESET)


def apply_preset(settings: dict, preset: str) -> dict:
    """Set every check a preset covers, with all its options, and the core settings it names. Everything else stays."""
    table = PRESETS.get(preset) if isinstance(preset, str) else None
    if table is None:
        raise ValueError(f"Unknown preset {preset!r}")
    result = copy.deepcopy(settings)
    for check_id, (enabled, action, extras) in table["checks"].items():
        check = result["checks"][check_id]
        check["enabled"] = enabled
        check["action"] = action
        check.update(copy.deepcopy(extras))
    result["core"].update(copy.deepcopy(table["core"]))
    result["core"]["auto_kick"]["enabled"] = table["auto_kick"]
    if "auto_kick_minutes" in table:
        result["core"]["auto_kick"]["minutes"] = table["auto_kick_minutes"]
    result["preset"] = preset
    return result


def detect_preset(settings: dict) -> str:
    """Name the preset this document matches, or "custom"."""
    core = settings["core"]
    for name, table in PRESETS.items():
        if core["auto_kick"]["enabled"] != table["auto_kick"] or core["auto_kick"]["minutes"] != table.get("auto_kick_minutes", core["auto_kick"]["minutes"]):
            continue
        if any(core[key] != value for key, value in table["core"].items()):
            continue
        if all(_matches(settings["checks"][check_id], entry) for check_id, entry in table["checks"].items()):
            return name
    return "custom"


def _matches(check: dict, entry: tuple) -> bool:
    enabled, action, extras = entry
    return check["enabled"] == enabled and check["action"] == action and all(check.get(key) == value for key, value in extras.items())


@cache
def _geogate_keys() -> frozenset:
    """What a country rule can name: a country code, a region or a continent from the table the page offers."""
    keys = set()
    for row in json.loads(COUNTRIES.read_text(encoding="utf-8")):
        keys.update((row["code"], f"region:{row['region']}", f"continent:{row['continent']}"))
    return frozenset(keys)


def _normalize_check(check_id: str, raw: dict, base: dict) -> dict:
    result = dict(base)
    result["enabled"] = _bool(raw.get("enabled"), base["enabled"])
    result["action"] = _choice(raw.get("action"), ACTIONS, base["action"])
    if check_id == "account_age":
        result["days"] = _int(raw.get("days"), 1, 3650, base["days"])
    elif check_id == "alt_account":
        methods = raw.get("methods") if isinstance(raw.get("methods"), dict) else {}
        result["methods"] = {key: _bool(methods.get(key), value) for key, value in base["methods"].items()}
        result["min_confidence"] = _choice(raw.get("min_confidence"), CONFIDENCE_LEVELS, base["min_confidence"])
        for key in ("alt_action", "banned_alt_action"):
            result[key] = _choice(raw.get(key), ACTIONS, base[key])
        # Deny does nothing to an account that already got in, so a stored one falls back to the default Watch.
        result["main_action"] = _choice(raw.get("main_action"), MAIN_ACTIONS, base["main_action"])
        # The check's own action is what the summary shows, so keep it equal to the alt action.
        result["action"] = result["alt_action"]
    elif check_id == "max_attempts":
        result["attempts"] = _int(raw.get("attempts"), 1, 100, base["attempts"])
        result["role"] = _snowflake(raw.get("role"))
        reset = _int(raw.get("reset_minutes"), 0, 43200, base["reset_minutes"])
        result["reset_minutes"] = reset and max(reset, MIN_RESET_MINUTES)  # 0 means attempts never come back
    elif check_id == "tampering":
        result["anomaly_score"] = _int(raw.get("anomaly_score"), 1, 100, base["anomaly_score"])
    elif check_id == "threat":
        result["bot_score"] = _int(raw.get("bot_score"), 1, 100, base["bot_score"])
        result["suspect_score"] = _int(raw.get("suspect_score"), 1, 100, base["suspect_score"])
    elif check_id == "geogate":
        result["list"] = _choice(raw.get("list"), ("block", "allow"), base["list"])
        countries = raw.get("countries") if isinstance(raw.get("countries"), list) else []
        result["countries"] = sorted({c.upper() for c in countries if isinstance(c, str) and re.fullmatch(r"[A-Za-z]{2}", c)})
        overrides = raw.get("overrides") if isinstance(raw.get("overrides"), dict) else {}
        result["overrides"] = {key: value for key, value in list(overrides.items())[:320] if key in _geogate_keys() and value in ACTIONS}
    return result


def _normalize_message(name: str, raw: Any) -> dict:
    base = DEFAULT_MESSAGES[name]
    raw = raw if isinstance(raw, dict) else {}
    result = {
        "content": _text(raw.get("content"), 2000, base["content"]),
        "title": _text(raw.get("title"), 256, base["title"]),
        "description": _text(raw.get("description"), 4000, base["description"]).strip() or base["description"],
        "color": _int(raw.get("color"), 0, 0xFFFFFF, base["color"]),
        "thumbnail": _https_url(raw.get("thumbnail")),
        "image": _https_url(raw.get("image")),
        "footer": _text(raw.get("footer"), 2048),
        "author": _snowflake(raw.get("author")),
    }
    if name == "verification":
        for prefix in ("verify", "help"):
            result[f"{prefix}_label"] = _text(raw.get(f"{prefix}_label"), 80, base[f"{prefix}_label"]).strip() or base[f"{prefix}_label"]
            result[f"{prefix}_emoji"] = _emoji(raw.get(f"{prefix}_emoji"))
            result[f"{prefix}_style"] = _choice(raw.get(f"{prefix}_style"), BUTTON_STYLES, base[f"{prefix}_style"])
    return result


def _normalize_rule(raw: Any, default_required: list[str]) -> dict:
    """One access rule: required permissions plus overrides for roles, members or everyone."""
    raw = raw if isinstance(raw, dict) else {}
    required = raw.get("required")
    if isinstance(required, list):
        required = [name for name in required if name in PERMISSION_NAMES]
    else:
        required = list(default_required)
    overrides = []
    entries = raw.get("overrides") if isinstance(raw.get("overrides"), list) else []
    for entry in entries[:100]:
        if not isinstance(entry, dict):
            continue
        kind = _choice(entry.get("type"), ("role", "user", "everyone", "channel"), None)
        target = _snowflake(entry.get("id"))
        if kind is None or (kind != "everyone" and target is None):
            continue
        # Only a plain true grants anything, so a damaged override can't open a page.
        overrides.append({"type": kind, "id": target, "allow": _bool(entry.get("allow"), False)})
    return {"required": required, "overrides": overrides}


def page_rule(settings: dict, page: str, level: str) -> dict:
    stored = settings["permissions"]["pages"].get(page, {}).get(level)
    default = PAGE_DEFAULTS.get(page, {}).get(level, ["manage_guild"])
    return _normalize_rule(stored, default)


def command_rule(settings: dict, name: str) -> dict:
    return _normalize_rule(settings["permissions"]["commands"].get(name), COMMAND_DEFAULTS.get(name, ["manage_guild"]))


def command_rule_untouched(settings: dict, name: str) -> bool:
    """Whether a command's rule still says what it says out of the box. The order of its permissions means nothing."""
    rule = command_rule(settings, name)
    default = _normalize_rule(None, COMMAND_DEFAULTS.get(name, ["manage_guild"]))
    return set(rule["required"]) == set(default["required"]) and rule["overrides"] == default["overrides"]


def normalize(raw: Any) -> dict:
    """Turn any JSON value into a complete, safe settings document."""
    raw = raw if isinstance(raw, dict) else {}
    base = defaults()
    core_in = raw.get("core") if isinstance(raw.get("core"), dict) else {}
    core = base["core"]
    result = copy.deepcopy(base)
    out = result["core"]
    out["verified_role"] = _snowflake(core_in.get("verified_role"))
    out["channel"] = _snowflake(core_in.get("channel"))
    out["mode"] = _choice(core_in.get("mode"), MODES, core["mode"])
    out["unverified_role"] = _snowflake(core_in.get("unverified_role"))
    for key in ("unverified_enabled", "auto_dm", "remember_rejoin", "fail_open", "show_reason", "external_vpn_lookup", "direct_signin"):
        out[key] = _bool(core_in.get(key), core[key])

    notify = core_in.get("notify_closed_dms") if isinstance(core_in.get("notify_closed_dms"), dict) else {}
    out["notify_closed_dms"] = {"enabled": _bool(notify.get("enabled"), True), "seconds": _int(notify.get("seconds"), 30, 300, 30)}
    kick = core_in.get("auto_kick") if isinstance(core_in.get("auto_kick"), dict) else {}
    out["auto_kick"] = {"enabled": _bool(kick.get("enabled"), False), "minutes": _int(kick.get("minutes"), 5, 10080, 10)}
    cooldown = core_in.get("cooldown") if isinstance(core_in.get("cooldown"), dict) else {}
    out["cooldown"] = {"enabled": _bool(cooldown.get("enabled"), False), "seconds": _int(cooldown.get("seconds"), 1, 86400, 60)}

    logs = core_in.get("logs") if isinstance(core_in.get("logs"), dict) else {}
    modules = logs.get("modules") if isinstance(logs.get("modules"), dict) else {}
    out["logs"] = {"enabled": _bool(logs.get("enabled"), False),
                   "modules": {name: channel for name in LOG_MODULES if (channel := _snowflake(modules.get(name)))}}
    alerts = core_in.get("alerts") if isinstance(core_in.get("alerts"), dict) else {}
    roles = alerts.get("roles") if isinstance(alerts.get("roles"), dict) else {}
    roles = {name: role for name in LOG_MODULES if (role := _snowflake(roles.get(name)))}
    main = _snowflake(alerts.get("role"))
    off = alerts.get("off") if isinstance(alerts.get("off"), list) else []
    if "role" not in alerts and roles:
        # Saved before there was one role for everything. The role most modules use becomes it, and what pinged nobody still pings nobody.
        main = Counter(roles.values()).most_common(1)[0][0]
        off = [name for name in IMPORTANT_ALERTS if name not in roles]
        roles = {name: role for name, role in roles.items() if role != main or name not in IMPORTANT_ALERTS}
    out["alerts"] = {"enabled": _bool(alerts.get("enabled"), True), "role": main, "off": [name for name in IMPORTANT_ALERTS if name in off], "roles": roles}
    desk = core_in.get("help_desk") if isinstance(core_in.get("help_desk"), dict) else {}
    out["help_desk"] = {
        "enabled": _bool(desk.get("enabled"), False),
        "support_role": _snowflake(desk.get("support_role")),
        "require_attempt": _bool(desk.get("require_attempt"), True),
        "redirect": _bool(desk.get("redirect"), False),
        "auto_close": _bool(desk.get("auto_close"), False),
        "member_close": _bool(desk.get("member_close"), False),
    }

    checks_in = raw.get("checks") if isinstance(raw.get("checks"), dict) else {}
    for check_id in CHECK_IDS:
        entry = checks_in.get(check_id)
        if isinstance(entry, dict):
            result["checks"][check_id] = _normalize_check(check_id, entry, base["checks"][check_id])

    pot = raw.get("honeypot") if isinstance(raw.get("honeypot"), dict) else {}
    result["honeypot"] = {
        "enabled": _bool(pot.get("enabled"), False),
        "channel": _snowflake(pot.get("channel")),
        "action": _choice(pot.get("action"), HONEYPOT_ACTIONS, base["honeypot"]["action"]),
        "timeout_minutes": _int(pot.get("timeout_minutes"), 1, 40320, 60),
        "whitelist_roles": _snowflake_list(pot.get("whitelist_roles")),
    }
    raid = raw.get("raid") if isinstance(raw.get("raid"), dict) else {}
    result["raid"] = {
        "enabled": _bool(raid.get("enabled"), True),
        "joins": _int(raid.get("joins"), 3, 1000, 15),
        "seconds": _int(raid.get("seconds"), 5, 3600, 60),
        "duration_minutes": _int(raid.get("duration_minutes"), 1, 1440, 15),
        "min_account_days": _int(raid.get("min_account_days"), 0, 365, 7),
        "alert_role": _snowflake(raid.get("alert_role")),
    }
    appeals = raw.get("appeals") if isinstance(raw.get("appeals"), dict) else {}
    result["appeals"] = {"enabled": _bool(appeals.get("enabled"), True), "channel": _snowflake(appeals.get("channel")),
                         "role": _snowflake(appeals.get("role"))}
    privacy = raw.get("privacy") if isinstance(raw.get("privacy"), dict) else {}
    result["privacy"] = {
        "identifier_days": _int(privacy.get("identifier_days"), 30, 730, 365),
        "ip_days": _int(privacy.get("ip_days"), 1, 365, 30),
        "attempt_days": _int(privacy.get("attempt_days"), 30, 730, 365),
        "banned_days": _int(privacy.get("banned_days"), 0, 1825, 730),
    }
    messages = raw.get("messages") if isinstance(raw.get("messages"), dict) else {}
    result["messages"] = {name: _normalize_message(name, messages.get(name)) for name in DEFAULT_MESSAGES}
    look = raw.get("appearance") if isinstance(raw.get("appearance"), dict) else {}
    nickname = _text(look.get("nickname"), 32).strip()
    result["appearance"] = {"nickname": nickname if len(nickname) != 1 else "", "bio": _text(look.get("bio"), 190),
                            "avatar": _choice(look.get("avatar"), AVATAR_COLORS, ""), **_name_style(look)}

    perms = raw.get("permissions") if isinstance(raw.get("permissions"), dict) else {}
    pages_in = perms.get("pages") if isinstance(perms.get("pages"), dict) else {}
    pages: dict[str, dict] = {}
    for page, levels in PAGE_DEFAULTS.items():
        stored = pages_in.get(page) if isinstance(pages_in.get(page), dict) else {}
        # A rule at its default isn't stored, so one saved change doesn't pin every other rule to today's default.
        kept = {level: rule for level, default in levels.items()
                if level in stored and (rule := _normalize_rule(stored[level], default)) != _normalize_rule(None, default)}
        if kept:
            pages[page] = kept
    commands_in = perms.get("commands") if isinstance(perms.get("commands"), dict) else {}
    commands = {name: rule for name, default in COMMAND_DEFAULTS.items()
                if name in commands_in and (rule := _normalize_rule(commands_in[name], default)) != _normalize_rule(None, default)}
    result["permissions"] = {"pages": pages, "commands": commands}

    result["preset"] = detect_preset(result)
    return result


class Conflict(Exception):
    """Someone saved this part of the settings after the person saving now loaded it."""


def revision(document: dict, section: str) -> str:
    """A fingerprint of one part of a document, so a save can tell whether it still has the latest.

    The pages edit separate parts: `rules` is everything except permissions, messages and appearance,
    `access` is permissions, and `look` is messages and appearance. A save on one page doesn't conflict
    with a save on another.
    """
    if section not in REVISION_SECTIONS:
        raise ValueError(f"Unknown settings section {section!r}")
    names = REVISION_SECTIONS[section]
    part = {key: value for key, value in document.items() if (key not in OTHER_SECTIONS if names is None else key in names)}
    return hashlib.sha256(json.dumps(part, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def problem_items(settings: dict) -> list[dict]:
    """What the save bar must refuse, and which setting on the page to point at."""
    found = []

    def add(text: str, item: str) -> None:
        found.append({"text": text, "item": item})

    core = settings["core"]
    if not core["verified_role"]:
        add("Pick a verified role.", "core")
    if not core["channel"]:
        add("Pick a verification channel.", "core")
    if core["unverified_enabled"] and not core["unverified_role"]:
        add("Pick an unverified role, or turn that option off.", "unverified")
    if core["help_desk"]["enabled"] and not core["help_desk"]["support_role"]:
        add("Pick a support role for the help desk.", "helpdesk")
    if settings["honeypot"]["enabled"] and not settings["honeypot"]["channel"]:
        add("Pick a honeypot channel.", "honeypot")
    if core["unverified_enabled"] and core["unverified_role"] == core["verified_role"]:
        add("The verified and unverified roles must be different.", "unverified")
    # A member at the attempt limit would get the role the limit is keeping from them.
    if settings["checks"]["max_attempts"]["role"] and settings["checks"]["max_attempts"]["role"] == core["verified_role"]:
        add("The attempt limit role can't be the verified role.", "max_attempts")
    # A trap in the channel members verify in would catch their help threads and their questions.
    if settings["honeypot"]["enabled"] and settings["honeypot"]["channel"] and settings["honeypot"]["channel"] == core["channel"]:
        add("The honeypot channel can't be the verification channel.", "honeypot")
    return found


def problems(settings: dict) -> list[str]:
    return [entry["text"] for entry in problem_items(settings)]


def given_roles(settings: dict) -> list[tuple[str, str | None, str]]:
    """Roles AltWarden hands to members, with a label and the setting that holds each one."""
    core = settings["core"]
    return [("Verified role", core["verified_role"], "core"),
            ("Unverified role", core["unverified_role"] if core["unverified_enabled"] else None, "unverified"),
            ("Attempt limit role", settings["checks"]["max_attempts"]["role"], "max_attempts")]


def message_problems(messages: dict) -> list[str]:
    found = []
    for name, message in messages.items():
        used = len(message["title"]) + len(message["description"]) + len(message["footer"])
        if used > MESSAGE_ROOM:
            found.append(f"{MESSAGE_NAMES[name]} is {used:,} characters long. Keep its title, description and footer under {MESSAGE_ROOM:,} in all.")
    return found


def paused_checks(settings: dict) -> list[str]:
    """Checks that are on but can't run in the current mode. They stay saved and sit idle."""
    mode = settings["core"]["mode"]
    return [check_id for check_id in CHECK_IDS
            if settings["checks"][check_id]["enabled"] and mode not in BY_ID[check_id].modes]


def _strip_server_specific(settings: dict) -> dict:
    """Roles, channels and messages belong to one server, so an export leaves them out."""
    export = copy.deepcopy(settings)
    core = export["core"]
    for key in ("verified_role", "channel", "unverified_role"):
        core[key] = None
    core["logs"]["modules"] = {}
    core["alerts"].update(role=None, roles={})
    core["help_desk"]["support_role"] = None
    export["checks"]["max_attempts"]["role"] = None
    export["honeypot"]["channel"] = None
    export["honeypot"]["whitelist_roles"] = []
    export["raid"]["alert_role"] = None
    export["appeals"].update({"channel": None, "role": None})
    export.pop("messages", None)
    export.pop("appearance", None)
    export.pop("permissions", None)
    return export


def export_code(settings: dict) -> str:
    """A compact text form of a server's rules, safe to paste anywhere."""
    payload = json.dumps(_strip_server_specific(settings), separators=(",", ":")).encode()
    return "AW1." + base64.urlsafe_b64encode(zlib.compress(payload, 9)).decode()


def import_code(current: dict, code: str) -> dict:
    """Apply an export to this server, keeping this server's roles, channels and messages."""
    code = code.strip()
    if len(code) > MAX_EXPORT_BYTES or not code.startswith("AW1."):
        raise ValueError("That is not an AltWarden settings code.")
    try:
        decompressor = zlib.decompressobj()
        payload = decompressor.decompress(base64.urlsafe_b64decode(code[4:]), MAX_EXPORT_BYTES)
        if decompressor.unconsumed_tail:
            raise ValueError("too large")
        incoming = json.loads(payload)
        if not isinstance(incoming, dict):
            raise ValueError("not a settings document")
    except Exception as exc:
        raise ValueError("That settings code is damaged or too large.") from exc
    sections = {key: incoming[key] for key in ("checks", "honeypot", "raid", "privacy", "appeals") if isinstance(incoming.get(key), dict)}
    merged = normalize({**current, **sections})
    if isinstance(incoming.get("core"), dict):
        kept = {key: value for key, value in incoming["core"].items()
                if key not in ("verified_role", "channel", "unverified_role", "logs", "alerts", "help_desk")}
        # These three carry switches worth sharing beside channels and roles that aren't.
        for name, options in IMPORTED_SWITCHES.items():
            given = incoming["core"].get(name)
            if isinstance(given, dict):
                kept[name] = {**merged["core"][name], **{key: given[key] for key in options if key in given}}
        merged = normalize({**merged, "core": {**merged["core"], **kept}})
    for key, value in (("channel", current["honeypot"]["channel"]), ("whitelist_roles", current["honeypot"]["whitelist_roles"])):
        merged["honeypot"][key] = value
    merged["checks"]["max_attempts"]["role"] = current["checks"]["max_attempts"]["role"]
    merged["raid"]["alert_role"] = current["raid"]["alert_role"]
    merged["appeals"].update({"channel": current["appeals"]["channel"], "role": current["appeals"]["role"]})
    return merged


def diff(before: dict, after: dict, prefix: str = "") -> list[dict]:
    """A flat list of what changed, for the audit log."""
    changes = []
    keys = sorted(set(before) | set(after)) if isinstance(before, dict) and isinstance(after, dict) else []
    for key in keys:
        path = f"{prefix}.{key}" if prefix else str(key)
        old, new = before.get(key), after.get(key)
        if isinstance(old, dict) and isinstance(new, dict):
            changes.extend(diff(old, new, path))
        elif old != new:
            changes.append({"path": path, "before": old, "after": new})
    return changes


__all__ = ["ACTIONS", "BAN", "Conflict", "DENY", "KICK", "WATCH", "apply_preset", "command_rule", "defaults", "detect_preset",
           "diff", "export_code", "given_roles", "import_code", "message_problems", "normalize", "page_rule", "paused_checks",
           "problem_items", "problems", "revision"]
