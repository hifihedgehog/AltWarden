"""Numbers for the dashboard, computed from the attempts table in the viewer's time zone."""
from __future__ import annotations

import json
import statistics
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from .catalog import SEVERITY, WATCH

BUCKETS = ((30, "<30s"), (60, "30s-1m"), (120, "1-2m"), (300, "2-5m"), (900, "5-15m"), (3600, "15m-1h"), (float("inf"), "1h+"))
MAX_RANGE_DAYS = 400


def _zone(name: str | None):
    try:
        return ZoneInfo(name) if name else timezone.utc
    except Exception:
        return timezone.utc


async def report(db, guild_id: str, start: float, end: float, zone_name: str | None = None) -> dict:
    """Everything the Analytics page shows for one period."""
    start = max(start, end - MAX_RANGE_DAYS * 86400)
    zone = _zone(zone_name)
    rows = await db.all("SELECT user_id, at, outcome, check_id, action, mode, seconds, bypassed FROM attempts "
                        "WHERE guild_id = ? AND at >= ? AND at < ? ORDER BY at", (guild_id, start, end))
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
    return await db.scalar("SELECT COUNT(*) FROM sessions WHERE guild_id = ? AND state IN ('signed_in', 'checking') AND expires_at > ?",
                           (guild_id, time.time())) or 0


async def preview(db, guild_id: str, rules: dict, days: int = 30) -> dict:
    """Replay recent attempts against proposed rules: who would have been let in or stopped.

    Attempts store what each enabled check found, so this can only replay checks that were on,
    in Watch or stronger, when the attempt happened. The page says so.
    """
    since = time.time() - days * 86400
    rows = await db.all("SELECT user_id, outcome, detail FROM attempts WHERE guild_id = ? AND at >= ? AND outcome IN ('passed', 'failed')",
                        (guild_id, since))
    now_blocked = would_block = newly_blocked = newly_passed = 0
    by_check: Counter = Counter()
    for row in rows:
        findings = json.loads(row["detail"]).get("findings", [])
        strongest = WATCH
        for finding in findings:
            check = rules["checks"].get(finding["check"], {})
            if not check.get("enabled"):
                continue
            action = _action_for(finding, check)
            if SEVERITY[action] > SEVERITY[strongest]:
                strongest = action
            if action != WATCH:
                by_check[finding["check"]] += 1
        was_blocked = row["outcome"] == "failed"
        blocked = strongest != WATCH
        now_blocked += was_blocked
        would_block += blocked
        newly_blocked += blocked and not was_blocked
        newly_passed += was_blocked and not blocked
    return {"days": days, "attempts": len(rows), "blocked_then": now_blocked, "blocked_now": would_block,
            "newly_blocked": newly_blocked, "newly_passed": newly_passed, "by_check": by_check.most_common()}


def _action_for(finding: dict, check: dict) -> str:
    if finding["check"] == "alt_account":
        banned = finding.get("detail", {}).get("banned")
        return check.get("banned_alt_action" if banned else "alt_action", WATCH)
    return check.get("action", WATCH)
