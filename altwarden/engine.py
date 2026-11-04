"""Runs a server's checks against one attempt and decides what happens.

Two differences from a simple first-failure gate:

  * Every enabled check runs, so the log shows everything an attempt tripped, not only the first.
  * The strongest action among the failures wins. A VPN set to Deny can't hide an alt of a banned
    account set to Ban, which a first-failure gate would never reach.

A check set to Watch is recorded and never stops anyone.
"""
from __future__ import annotations

import copy
import time
from dataclasses import dataclass, field

from . import altmatch
from .catalog import BAN, BUTTON, BY_ID, CHECK_IDS, DENY, FAILURE_TEXT, INSTANT, KICK, SEVERITY, WATCH, WEB
from .netintel import NetInfo
from .signals import BrowserVerdict

DISCORD_EPOCH_MS = 1420070400000


def account_created_at(user_id: str | int) -> float:
    """Seconds since 1970 when a Discord ID was created. The ID's top bits are its timestamp."""
    return ((int(user_id) >> 22) + DISCORD_EPOCH_MS) / 1000


@dataclass
class Account:
    """The Discord account in one attempt. Only flags and a domain survive from the sign-in."""

    id: str
    username: str = ""
    avatar: str | None = None
    mfa: bool | None = None
    email_verified: bool | None = None
    email_disposable: bool | None = None

    @property
    def age_days(self) -> float:
        return (time.time() - account_created_at(self.id)) / 86400


@dataclass
class Finding:
    check_id: str
    action: str
    reason: str
    detail: dict = field(default_factory=dict)
    text_args: dict = field(default_factory=dict)

    @property
    def message(self) -> str:
        return FAILURE_TEXT[self.reason].format(**self.text_args)

    @property
    def enforced(self) -> bool:
        return self.action != WATCH

    @property
    def retry_at(self) -> float | None:
        """When a member can come back: once the account is old enough, or attempts return."""
        return self.detail.get("old_enough_at") or self.detail.get("attempts_back_at")


@dataclass
class Decision:
    findings: list[Finding] = field(default_factory=list)
    alt_link: altmatch.Link | None = None
    main_action: str = WATCH
    cooldown_left: float = 0.0

    @property
    def enforced(self) -> list[Finding]:
        return [finding for finding in self.findings if finding.enforced]

    @property
    def passed(self) -> bool:
        return not self.enforced and self.cooldown_left <= 0

    @property
    def primary(self) -> Finding | None:
        """The failure that decides the outcome: the strongest action, then the check order."""
        enforced = self.enforced
        if not enforced:
            return None
        return max(enforced, key=lambda finding: SEVERITY[finding.action])

    @property
    def action(self) -> str:
        primary = self.primary
        return primary.action if primary else WATCH


@dataclass
class Attempt:
    settings: dict
    mode: str
    account: Account
    member: dict | None = None
    net: NetInfo | None = None
    browser: BrowserVerdict | None = None
    links: list = field(default_factory=list)
    suspect: int = 0
    suspect_hits: list = field(default_factory=list)
    cellular: bool = False
    bypass: frozenset = frozenset()
    now: float = field(default_factory=time.time)


def effective_settings(settings: dict, raid_active: bool) -> dict:
    """During a raid, every account-level rule tightens for as long as the raid lasts."""
    if not raid_active:
        return settings
    tightened = copy.deepcopy(settings)
    raid = tightened["raid"]
    age = tightened["checks"]["account_age"]
    age["enabled"] = True
    age["days"] = max(age["days"], raid["min_account_days"])
    age["action"] = _at_least(age["action"], KICK)
    for check_id in ("vpn", "automation", "antidetect"):
        check = tightened["checks"][check_id]
        check["enabled"] = True
        check["action"] = _at_least(check["action"], DENY)
    alt = tightened["checks"]["alt_account"]
    alt["enabled"] = True
    alt["alt_action"] = _at_least(alt["alt_action"], KICK)
    alt["banned_alt_action"] = _at_least(alt["banned_alt_action"], KICK)
    return tightened


def _at_least(action: str, floor: str) -> str:
    """A raid only ever tightens a rule, so a server's Ban stays a Ban."""
    return action if SEVERITY[action] >= SEVERITY[floor] else floor


def _active(attempt: Attempt, check_id: str) -> dict | None:
    """A check's options, if it should run on this attempt."""
    check = attempt.settings["checks"][check_id]
    if not check["enabled"] or attempt.mode not in BY_ID[check_id].modes or check_id in attempt.bypass:
        return None
    return check


def _simple(attempt: Attempt, decision: Decision, check_id: str, failed: bool, *, reason: str | None = None,
            detail: dict | None = None, text_args: dict | None = None) -> None:
    check = _active(attempt, check_id)
    if check is not None and failed:
        decision.findings.append(Finding(check_id, check["action"], reason or check_id, detail or {}, text_args or {}))


def geogate_action(check: dict, country: str, regions: dict) -> str | None:
    """The action for a country, or None if it may pass. The most specific rule wins."""
    listed = country in check["countries"]
    if (check["list"] == "block" and not listed) or (check["list"] == "allow" and listed):
        return None
    overrides = check["overrides"]
    entry = regions.get(country, {})
    for key in (country, f"region:{entry.get('region')}", f"continent:{entry.get('continent')}"):
        if key in overrides:
            return overrides[key]
    return check["action"]


def run_checks(attempt: Attempt, regions: dict | None = None) -> Decision:
    decision = Decision()
    settings = attempt.settings
    member = attempt.member or {}
    account = attempt.account

    cooldown = settings["core"]["cooldown"]
    if cooldown["enabled"] and "cooldown" not in attempt.bypass and member.get("last_fail_at"):
        left = member["last_fail_at"] + cooldown["seconds"] - attempt.now
        if left > 0:
            decision.cooldown_left = left
            return decision  # A wait isn't a failure, so nothing else runs and nothing is logged.

    limit = _active(attempt, "max_attempts")
    if limit is not None and member.get("fails", 0) >= limit["attempts"]:
        detail = {"attempts": limit["attempts"]}
        if limit["reset_minutes"] and member.get("limit_reached_at"):
            detail["attempts_back_at"] = member["limit_reached_at"] + limit["reset_minutes"] * 60
        decision.findings.append(Finding("max_attempts", limit["action"], "max_attempts", detail))

    age = settings["checks"]["account_age"]
    _simple(attempt, decision, "account_age", account.age_days < age["days"],
            detail={"account_days": int(account.age_days), "minimum": age["days"],
                    "old_enough_at": account_created_at(account.id) + age["days"] * 86400},
            text_args={"days": age["days"]})
    _simple(attempt, decision, "avatar", not account.avatar)
    _simple(attempt, decision, "mfa", account.mfa is False)

    if account.email_verified is False:
        _simple(attempt, decision, "disposable_email", True, reason="no_email")
    else:
        _simple(attempt, decision, "disposable_email", account.email_disposable is True)

    _check_alt(attempt, decision)

    net = attempt.net
    if net is not None:
        _simple(attempt, decision, "vpn", net.anonymized, detail={"network": net.labels()})
        _simple(attempt, decision, "mobile_data", net.mobile or attempt.cellular)
        _check_geogate(attempt, decision, net, regions or {})

    browser = attempt.browser
    if browser is not None:
        checks = settings["checks"]
        reasons = browser.reasons
        _simple(attempt, decision, "automation", browser.automated, detail={"signs": reasons.get("automated", [])})
        _simple(attempt, decision, "antidetect", browser.antidetect, detail={"signs": reasons.get("antidetect", [])})
        _simple(attempt, decision, "tampering", browser.tamper_score >= checks["tampering"]["anomaly_score"],
                detail={"score": browser.tamper_score, "signs": reasons.get("tamper", [])})
        _simple(attempt, decision, "fake_ua", browser.fake_ua, detail={"signs": reasons.get("fake_ua", [])})
        _simple(attempt, decision, "devtools", browser.devtools, detail={"signs": reasons.get("devtools", [])})
        _simple(attempt, decision, "incognito", browser.private)
        _simple(attempt, decision, "privacy", browser.privacy, detail={"signs": reasons.get("privacy", [])})
        threat = checks["threat"]
        _simple(attempt, decision, "threat",
                browser.bot_score >= threat["bot_score"] or attempt.suspect >= threat["suspect_score"],
                detail={"bot_score": browser.bot_score, "suspect_score": attempt.suspect, "signs": attempt.suspect_hits})
        _simple(attempt, decision, "vm", browser.vm, detail={"signs": reasons.get("vm", [])})
        _simple(attempt, decision, "rooted", browser.emulated, detail={"signs": reasons.get("emulated", [])})
    return decision


def _check_alt(attempt: Attempt, decision: Decision) -> None:
    check = _active(attempt, "alt_account")
    if check is None:
        return
    link = altmatch.strongest(attempt.links, check["min_confidence"])
    if link is None:
        return
    decision.alt_link = link
    if link.banned:
        action, other = check["banned_alt_action"], WATCH
    elif link.other_is_main:
        action, other = check["alt_action"], check["main_action"]
    else:
        # This account verified first, so it's the main one and the other is the alt.
        action, other = check["main_action"], WATCH
    decision.main_action = other
    decision.findings.append(Finding("alt_account", action, "alt_account", link.as_dict()))


def _check_geogate(attempt: Attempt, decision: Decision, net: NetInfo, regions: dict) -> None:
    check = _active(attempt, "geogate")
    if check is None or not net.country:
        return
    action = geogate_action(check, net.country, regions)
    if action is not None:
        # Staff learn the rule applied, never the member's country.
        decision.findings.append(Finding("geogate", action, "geogate", {"list": check["list"]}))


def available_checks(settings: dict, mode: str) -> list[str]:
    """What a bypass link can skip: checks that are on and run in this mode."""
    return [check_id for check_id in CHECK_IDS if settings["checks"][check_id]["enabled"] and mode in BY_ID[check_id].modes]


def bypass_options(settings: dict) -> list[str]:
    """Bypass links always open the web page, so staff can skip anything that runs there, cooldown included."""
    options = available_checks(settings, WEB)
    if settings["core"]["cooldown"]["enabled"]:
        options.append("cooldown")
    return options


__all__ = ["Account", "Attempt", "BAN", "BUTTON", "Decision", "Finding", "INSTANT", "KICK", "WEB", "account_created_at",
           "available_checks", "bypass_options", "effective_settings", "geogate_action", "run_checks"]
