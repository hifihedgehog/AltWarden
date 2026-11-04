"""Finds what would stop verification in a server, and says how to fix it.

The report also works out the smallest permission set the current settings need, so a server
never has to hand the bot Administrator.
"""
from __future__ import annotations

from .catalog import BAN, BY_ID, CHECK_IDS, KICK, PERMISSION_LABELS
from .settings import given_roles

# Discord permission bits, from the permissions topic.
BITS = {
    "kick_members": 1 << 1, "ban_members": 1 << 2, "administrator": 1 << 3, "manage_channels": 1 << 4, "manage_guild": 1 << 5,
    "view_channel": 1 << 10, "send_messages": 1 << 11, "manage_messages": 1 << 13, "embed_links": 1 << 14,
    "read_message_history": 1 << 16, "mention_everyone": 1 << 17, "change_nickname": 1 << 26, "manage_roles": 1 << 28,
    "manage_threads": 1 << 34, "create_private_threads": 1 << 36, "send_messages_in_threads": 1 << 38, "moderate_members": 1 << 40,
    "pin_messages": 1 << 51,
}
BASE_PERMISSIONS = ("view_channel", "send_messages", "embed_links", "read_message_history", "manage_roles", "kick_members",
                    "ban_members", "moderate_members", "manage_messages", "manage_threads", "create_private_threads",
                    "send_messages_in_threads", "change_nickname", "pin_messages")


def invite_permissions() -> int:
    return sum(BITS[name] for name in BASE_PERMISSIONS)


def invite_url(client_id: str) -> str:
    return (f"https://discord.com/oauth2/authorize?client_id={client_id}&scope=bot%20applications.commands"
            f"&permissions={invite_permissions()}")


def needed_permissions(settings: dict) -> dict[str, list[str]]:
    """Each server-wide permission the settings use, and which features use it."""
    core = settings["core"]
    needs: dict[str, list[str]] = {"manage_roles": ["Verified role"]}
    if core["unverified_enabled"]:
        needs["manage_roles"].append("Unverified role")
    kicks: list[str] = []
    bans: list[str] = []
    if core["auto_kick"]["enabled"]:
        kicks.append("Auto kick")
    for check_id in CHECK_IDS:
        check = settings["checks"][check_id]
        if not check["enabled"] or core["mode"] not in BY_ID[check_id].modes:
            continue
        actions = {check["action"]}
        if check_id == "alt_account":
            actions |= {check["alt_action"], check["main_action"], check["banned_alt_action"]}
        if KICK in actions:
            kicks.append(BY_ID[check_id].name)
        if BAN in actions:
            bans.append(BY_ID[check_id].name)
    pot = settings["honeypot"]
    if pot["enabled"]:
        if pot["action"] == "kick":
            kicks.append("Honeypot")
        elif pot["action"] in ("ban", "softban"):
            bans.append("Honeypot")
        elif pot["action"] == "timeout":
            needs["moderate_members"] = ["Honeypot"]
    if kicks:
        needs["kick_members"] = kicks
    if bans:
        needs["ban_members"] = bans
    look = settings["appearance"]
    profile = (["Custom name"] if look["nickname"] else []) + (["Name style"] if look["font"] else [])
    if profile:
        needs["change_nickname"] = profile
    return needs


def _role(guild, role_id):
    return next((role for role in guild.roles if role["id"] == role_id), None)


def _channel(guild, channel_id):
    return next((channel for channel in guild.channels if channel["id"] == channel_id), None)


def _check_role(guild, label: str, role_id, issues: list, ok: list, *, must_mention: bool = False, feature: str | None = None) -> None:
    role = _role(guild, role_id)
    if role is None:
        issues.append({"area": "roles", "feature": feature, "title": f"{label} is missing", "fix": f"Pick a {label.lower()} on the Settings page."})
        return
    if role["managed"] or role["id"] == guild.id:
        issues.append({"area": "roles", "feature": feature, "title": f"{label} can't be used", "fix": "Pick a regular role. @everyone and roles owned by other apps can't be given out."})
        return
    if not must_mention and role["position"] >= guild.bot_top_role:
        issues.append({"area": "roles", "feature": feature, "title": f"AltWarden's role is below {role['name']}",
                       "fix": "In Server Settings, Roles, drag the AltWarden role above it. Discord only lets an app give roles below its own."})
        return
    if must_mention and not role["mentionable"] and "mention_everyone" not in guild.bot_permissions and "administrator" not in guild.bot_permissions:
        issues.append({"area": "roles", "feature": feature, "title": f"{role['name']} can't be pinged", "fix": "Make the role mentionable, or allow AltWarden to mention all roles."})
        return
    ok.append({"area": "roles", "label": label, "value": role["name"]})


def _check_channel(guild, label: str, channel_id, issues: list, ok: list, extra: tuple = (), feature: str | None = None) -> None:
    channel = _channel(guild, channel_id)
    if channel is None:
        issues.append({"area": "channels", "feature": feature, "title": f"{label} is missing", "fix": f"Pick a {label.lower()} on the Settings page."})
        return
    held = guild.channel_permissions.get(channel_id, frozenset())
    missing = [name for name in ("view_channel", "send_messages", "embed_links") + extra if name not in held and "administrator" not in held]
    if missing:
        issues.append({"area": "channels", "feature": feature, "title": f"AltWarden can't work in #{channel['name']}",
                       "fix": "Allow " + ", ".join(PERMISSION_LABELS[name] for name in missing) + " in that channel."})
        return
    ok.append({"area": "channels", "label": label, "value": channel["name"]})


def report(guild, settings: dict) -> dict:
    issues: list[dict] = []
    ok: list[dict] = []
    core = settings["core"]
    needs = needed_permissions(settings)
    for name, features in needs.items():
        if name in guild.bot_permissions or "administrator" in guild.bot_permissions:
            ok.append({"area": "permissions", "label": PERMISSION_LABELS[name], "value": ", ".join(features)})
        else:
            issues.append({"area": "permissions", "title": f"Missing {PERMISSION_LABELS[name]}",
                           "fix": f"Give AltWarden's role this permission. It is needed for: {', '.join(features)}."})
    _check_role(guild, "Verified role", core["verified_role"], issues, ok)
    if core["unverified_enabled"]:
        _check_role(guild, "Unverified role", core["unverified_role"], issues, ok)
    if settings["checks"]["max_attempts"]["role"]:
        _check_role(guild, "Attempt limit role", settings["checks"]["max_attempts"]["role"], issues, ok)
    if core["alerts"]["enabled"]:
        for role_id in dict.fromkeys(core["alerts"]["roles"].values()):
            _check_role(guild, "Alert role", role_id, issues, ok, must_mention=True)
    _check_channel(guild, "Verification channel", core["channel"], issues, ok)
    if core["logs"]["enabled"]:
        for channel_id in dict.fromkeys(core["logs"]["modules"].values()):
            _check_channel(guild, "Logs channel", channel_id, issues, ok)
    pot = settings["honeypot"]
    if pot["enabled"]:
        _check_channel(guild, "Honeypot channel", pot["channel"], issues, ok, ("manage_messages", "pin_messages"), feature="honeypot")
    desk = core["help_desk"]
    if desk["enabled"]:
        _check_role(guild, "Support role", desk["support_role"], issues, ok, must_mention=True, feature="help_desk")
        channel = _channel(guild, core["channel"])
        if channel is not None and channel["type"] != "text":
            issues.append({"area": "help_desk", "feature": "help_desk", "title": "The help desk needs a text channel", "fix": "Pick a regular text channel for verification."})
        held = guild.channel_permissions.get(core["channel"], frozenset())
        for name in ("create_private_threads", "send_messages_in_threads", "manage_threads", "pin_messages"):
            if name not in held and "administrator" not in held:
                issues.append({"area": "help_desk", "feature": "help_desk", "title": f"Help desk needs {PERMISSION_LABELS[name]}", "fix": "Allow it for AltWarden in the verification channel."})
    surplus = "administrator" in guild.bot_permissions
    return {"healthy": not issues, "issues": issues, "ok": ok, "needs": needs, "has_administrator": surplus,
            "advice": ("AltWarden has Administrator, which it doesn't need. If its token were ever stolen, the attacker "
                       "would control the whole server. Remove Administrator and keep only the permissions listed here.") if surplus else None}


def feature_warnings(guild, settings: dict) -> dict[str, list[str]]:
    """What the help desk and honeypot are missing, grouped by the log module that should hear about it."""
    found: dict[str, list[str]] = {}
    for issue in report(guild, settings)["issues"]:
        if issue.get("feature"):
            found.setdefault(issue["feature"], []).append(f"**{issue['title']}**\n{issue['fix']}")
    return found


def role_refusals(guild, before: dict | None, after: dict, viewer) -> list[dict]:
    """Newly chosen roles a save must refuse.

    A member with Manage Server must not be able to hand out a role above their own, or they could
    give themselves that role by verifying. Roles that were already set are left alone.
    """
    old = {role_id for _, role_id, _ in given_roles(before)} if before else set()
    own_top = max((role["position"] for role in guild.roles if role["id"] in viewer.role_ids), default=0)
    refused = []
    for label, role_id, item in given_roles(after):
        if not role_id or role_id in old:
            continue
        role = _role(guild, role_id)
        if role is None:
            text = f"{label}: that role no longer exists."
        elif role["managed"] or role["id"] == guild.id:
            text = f"{label}: pick a regular role. @everyone and roles owned by other apps can't be given out."
        elif role["position"] >= guild.bot_top_role:
            text = f"{label}: drag AltWarden's role above {role['name']} in Server Settings first."
        elif not viewer.is_admin and role["position"] >= own_top:
            text = f"{label}: pick a role below your own highest role."
        else:
            continue
        refused.append({"text": text, "item": item})
    return refused
