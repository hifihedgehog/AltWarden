"""Who may open a dashboard page or run a command.

The order is Discord's own, from the permissions topic: a member override decides first, then the
member's roles, then an override for @everyone, then the required permissions. The server owner
and Administrators always pass, so a bad rule can't lock a server out of its own settings.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Viewer:
    user_id: str
    role_ids: frozenset
    permissions: frozenset
    is_owner: bool = False

    @property
    def is_admin(self) -> bool:
        return self.is_owner or "administrator" in self.permissions


def channel_allowed(rule: dict, channel_id: str | None) -> bool:
    """Commands can be limited to, or kept out of, specific channels."""
    entries = [entry for entry in rule.get("overrides", []) if entry["type"] == "channel"]
    if channel_id is None or not entries:
        return True
    for entry in entries:
        if entry["id"] == channel_id:
            return bool(entry["allow"])
    return not any(entry["allow"] for entry in entries)


def allowed(rule: dict, viewer: Viewer, channel_id: str | None = None) -> bool:
    if viewer.is_admin:
        return True
    if not channel_allowed(rule, channel_id):
        return False
    overrides = rule.get("overrides", [])
    for entry in overrides:
        if entry["type"] == "user" and entry["id"] == viewer.user_id:
            return bool(entry["allow"])
    role_entries = [entry for entry in overrides if entry["type"] == "role" and entry["id"] in viewer.role_ids]
    if any(entry["allow"] for entry in role_entries):
        return True
    if role_entries:
        return False
    for entry in overrides:
        if entry["type"] == "everyone":
            return bool(entry["allow"])
    required = rule.get("required", [])
    return bool(required) and all(name in viewer.permissions for name in required)
