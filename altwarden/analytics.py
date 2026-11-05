"""Numbers for the dashboard, computed from the attempts table in the viewer's time zone."""
from __future__ import annotations

import asyncio
import json
import statistics
import time
import weakref
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Iterable
from zoneinfo import ZoneInfo

from . import altmatch
from .altmatch import RANK
from .catalog import SEVERITY, WATCH

BUCKETS = ((30, "<30s"), (60, "30s-1m"), (120, "1-2m"), (300, "2-5m"), (900, "5-15m"), (3600, "15m-1h"), (float("inf"), "1h+"))
MAX_RANGE_DAYS = 400
VERIFYING_SECONDS = 300
_jobs: weakref.WeakValueDictionary = weakref.WeakValueDictionary()


def _job(guild_id: str) -> asyncio.Lock:
    """One slow read per server at a time, so repeated requests queue instead of filling every worker thread."""
    lock = _jobs.get(guild_id)
    if lock is None:
        lock = _jobs[guild_id] = asyncio.Lock()
    return lock


def _zone(name: str | None):
    try:
        return ZoneInfo(name) if name else timezone.utc
    except Exception:
        return timezone.utc


async def report(db, guild_id: str, start: float, end: float, zone_name: str | None = None) -> dict:
    """Everything the Analytics page shows for one period.

    A busy server can have hundreds of thousands of attempts, so this runs on its own thread and its
    own connection, where members verifying don't wait for it.
    """
    async with _job(guild_id):
        return await asyncio.to_thread(_report, db, guild_id, start, end, zone_name)


def _report(db, guild_id: str, start: float, end: float, zone_name: str | None) -> dict:
    asked = start
    start = max(start, end - MAX_RANGE_DAYS * 86400)
    zone = _zone(zone_name)
    connection = db.reader()
    try:
        data = _summarize(connection.execute("SELECT user_id, at, outcome, check_id, action, mode, seconds, bypassed FROM attempts "
                                             "WHERE guild_id = ? AND at >= ? AND at < ? ORDER BY at", (guild_id, start, end)), start, end, zone)
        data["range"] = {"start": start, "end": end, "clamped": start != asked}  # a longer period than this is cut, so the page can say so
        return data
    finally:
        connection.close()


def _summarize(rows, start: float, end: float, zone) -> dict:
    daily: dict[str, Counter] = defaultdict(Counter)
    day = datetime.fromtimestamp(start, zone).date()
    last = datetime.fromtimestamp(end - 1, zone).date()
    while day <= last:
        daily[day.isoformat()]
        day += timedelta(days=1)

    verified = blocked = 0
    reasons: Counter = Counter()
    modes: Counter = Counter()
    actions: Counter = Counter()
    heat = [[0] * 24 for _ in range(7)]
    durations: list[float] = []
    people: set = set()
    started: set = set()
    finished: set = set()
    passed: set = set()
    tries: Counter = Counter()
    bypassed = 0

    for row in rows:
        when = datetime.fromtimestamp(row["at"], zone)
        key = when.date().isoformat()
        outcome = row["outcome"]
        user = row["user_id"]
        if outcome == "started":
            started.add(user)
            continue
        if outcome in ("passed", "failed", "manual"):
            people.add(user)
            heat[when.weekday()][when.hour] += 1
        if outcome == "passed":
            verified += 1
            passed.add(user)
            finished.add(user)
            tries[user] += 1
            daily[key]["verified"] += 1
            modes[row["mode"] or "web"] += 1
            if row["seconds"]:
                durations.append(row["seconds"])
            bypassed += row["bypassed"]
        elif outcome == "manual":
            verified += 1
            passed.add(user)
            finished.add(user)  # staff finished it for them, and a funnel can't grow from one step to the next
            daily[key]["verified"] += 1
            modes["staff"] += 1
        elif outcome == "failed":
            blocked += 1
            finished.add(user)
            tries[user] += 1
            daily[key]["blocked"] += 1
            daily[key][f"check:{row['check_id']}"] += 1
            reasons[row["check_id"] or "unknown"] += 1
            actions[row["action"] or "deny"] += 1
        elif outcome == "auto_kick":
            actions["auto_kick"] += 1

    histogram = Counter()
    for seconds in durations:
        histogram[next(label for limit, label in BUCKETS if seconds < limit)] += 1

    decided = verified + blocked
    return {
        "cards": {
            "verified": verified,
            "blocked": blocked,
            "pass_rate": round(verified / decided * 100, 1) if decided else None,
            "members": len(people),
            "median_seconds": round(statistics.median(durations), 1) if durations else None,
        },
        "daily": [{"day": key, "verified": counts["verified"], "blocked": counts["blocked"],
                   "checks": {name[6:]: value for name, value in counts.items() if name.startswith("check:")}}
                  for key, counts in sorted(daily.items())],
        "reasons": reasons.most_common(),
        "funnel": {"started": len(started | finished | passed), "finished": len(finished), "verified": len(passed),
                   "unfinished": len(started - finished - passed), "retried": sum(1 for count in tries.values() if count > 1)},
        "heatmap": heat,
        "durations": [{"label": label, "count": histogram[label]} for _, label in BUCKETS],
        "outcomes": {"modes": dict(modes), "bypassed": bypassed, "actions": dict(actions)},
    }


async def verifying_now(db, guild_id: str) -> int:
    """People in the middle of a check, or signed in within the last few minutes with no result yet.

    Someone turned away keeps their link for a retry, and someone who walked away keeps it until it ends, and neither is verifying now.
    """
    now = time.time()
    return await db.scalar("SELECT COUNT(*) FROM sessions WHERE guild_id = ? AND (state = 'checking' OR (state = 'signed_in' AND finished_at IS NULL AND signed_in_at > ?)) "
                           "AND expires_at > ?", (guild_id, now - VERIFYING_SECONDS, now)) or 0


async def preview(db, guild_id: str, rules: dict, days: int = 30) -> dict:
    """Replay recent attempts against proposed rules: who would have been let in or stopped.

    Attempts store what each enabled check found, so this can only replay checks that were on,
    in Watch or stronger, when the attempt happened. The page says so. Country rules can't be replayed
    at all, because a finding never records the country, so `not_replayed` counts those attempts and
    the blocked and passed numbers leave them out. A busy server can hold hundreds of thousands of
    attempts, so this reads them one at a time, on its own thread and its own connection.
    """
    since = time.time() - days * 86400
    async with _job(guild_id):
        return await asyncio.to_thread(_preview, db, guild_id, since, rules, days)


def _preview(db, guild_id: str, since: float, rules: dict, days: int) -> dict:
    connection = db.reader()
    try:
        return _replay(connection.execute("SELECT user_id, outcome, detail FROM attempts WHERE guild_id = ? AND at >= ? AND outcome IN ('passed', 'failed')",
                                          (guild_id, since)), rules, days)
    finally:
        connection.close()


def _replay(rows: Iterable, rules: dict, days: int) -> dict:
    attempts = now_blocked = would_block = newly_blocked = newly_passed = not_replayed = 0
    by_check: Counter = Counter()
    for row in rows:
        attempts += 1
        findings = json.loads(row["detail"]).get("findings", [])
        strongest = WATCH
        counted = []
        unknown = False
        for finding in findings:
            check = rules["checks"].get(finding["check"], {})
            if not check.get("enabled"):
                continue
            if finding["check"] == "geogate" and (check["list"] == "allow" or check["countries"]):
                unknown = True
                continue
            if not _still_fires(finding, check):
                continue
            action = _action_for(finding, check)
            if SEVERITY[action] > SEVERITY[strongest]:
                strongest = action
            if action != WATCH:
                counted.append(finding["check"])
        if unknown:
            not_replayed += 1
            continue
        by_check.update(counted)
        was_blocked = row["outcome"] == "failed"
        blocked = strongest != WATCH
        now_blocked += was_blocked
        would_block += blocked
        newly_blocked += blocked and not was_blocked
        newly_passed += was_blocked and not blocked
    return {"days": days, "attempts": attempts, "blocked_then": now_blocked, "blocked_now": would_block,
            "newly_blocked": newly_blocked, "newly_passed": newly_passed, "by_check": by_check.most_common(), "not_replayed": not_replayed}


def _still_fires(finding: dict, check: dict) -> bool:
    """Whether a recorded finding would fire under the proposed limits. Findings keep the numbers they fired on."""
    detail = finding.get("detail", {})
    name = finding["check"]
    if name == "threat":
        return detail.get("bot_score", 0) >= check["bot_score"] or detail.get("suspect_score", 0) >= check["suspect_score"]
    if name == "tampering":
        return detail.get("score", 0) >= check["anomaly_score"]
    if name == "account_age":
        return detail.get("account_days", 0) < check["days"]
    if name == "alt_account":
        return RANK[_alt_confidence(detail, check)] >= RANK.get(check["min_confidence"], RANK["likely"])
    if name == "max_attempts":
        return detail.get("attempts", 0) >= check["attempts"]  # it fired at that limit, so a higher one hasn't been reached for certain
    if name == "geogate":
        return False  # with no countries on a block list, nothing can match. Everything else is counted as not replayed.
    return True


def _alt_confidence(detail: dict, check: dict) -> str:
    """How strong a recorded link would be with the evidence switched on now. Rows that kept no evidence list keep their confidence."""
    methods = detail.get("methods")
    if not methods:
        return detail.get("confidence") if detail.get("confidence") in RANK else "none"
    kept = [kind for kind in methods if check.get("methods", {}).get(altmatch.METHOD_FOR_KIND.get(kind), False)]
    if not kept:
        return "none"
    # Rows from before the weak kinds were recorded can have counted for less than the full weights, so the recorded score is a ceiling.
    score = altmatch.score_for(kept, detail.get("weak", []))
    return altmatch.confidence_for(min(score, detail["score"]) if "score" in detail else score)


def _action_for(finding: dict, check: dict) -> str:
    if finding["check"] == "alt_account":
        detail = finding.get("detail", {})
        # The account that verified first gets the main action, whichever of the two was verifying.
        other_is_main = not (detail.get("earlier_account") or detail.get("other_is_main") is False)
        return altmatch.judge(check, _alt_confidence(detail, check), bool(detail.get("banned")), other_is_main)[0]
    return check.get("action", WATCH)
