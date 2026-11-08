"""Every message AltWarden posts. Plain, with no advertising in any of them."""
from __future__ import annotations

import re

from .catalog import ACTION_LABEL, BY_ID, FAILURE_TEXT, HELP_SLUG
from .ports import Button, Notice

GREEN = 0x2FBF71
RED = 0xE5484D
AMBER = 0xF5A524
TEAL = 0x1FB8A6
GRAY = 0x7A8596
DESCRIPTION_LIMIT = 4096
EMBED_LIMIT = 6000
# Discord's markdown, after the set discord.py escapes in utils.escape_markdown, plus what makes a mention or a masked
# link. A bare address stays as it is, because a backslash would break it.
_URL = r"(?P<url><[^: >]+:\/[^ >]+>|(?:https?|steam):\/\/[^\s<]+[^<.,:;\"\'\]\s])"
_MARKDOWN = re.compile(rf"{_URL}|(?P<mark>[_\\~|*`<@\[]|^>(?:>>)?\s|^#{{1,3}}|^\s*-)", re.MULTILINE)


def escape_text(text: str) -> str:
    """Show text a member wrote as they typed it, so it can't pass for links, mentions or staff formatting beside a button."""
    return _MARKDOWN.sub(lambda found: found["url"] or "\\" + found["mark"], text)


def check_name(check_id: str | None) -> str:
    if check_id in BY_ID:
        return BY_ID[check_id].name
    return {"cooldown": "Cooldown", "no_email": "No verified email", "role_problem": "Role problem", "honeypot": "Honeypot"}.get(check_id, check_id or "Unknown")


def link_notice(guild_name: str, url: str, *, minutes: int, kick_minutes: int | None, bypass: bool = False) -> Notice:
    lines = [f"**{guild_name}** checks new members before letting them in."]
    lines.append("Press the button to verify. The link is yours alone" +
                 (f" and works for the next {_duration(minutes)}." if minutes else "."))
    if bypass:
        lines.append("Staff set this link up for you, so it skips the checks they chose.")
    if kick_minutes:
        lines.append(_deadline(kick_minutes))
    return Notice(embeds=[{"title": f"Verify to enter {guild_name}", "description": "\n\n".join(lines), "color": TEAL}],
                  buttons=[Button("Verify", url=url, style="link")])


def _deadline(kick_minutes: int | None) -> str:
    return f"Members who don't verify within {_duration(kick_minutes)} are removed." if kick_minutes else ""


def _press_verify(channel_id: str | None) -> str:
    return f"Go to <#{channel_id}> and press **Verify**." if channel_id else "Go to the server's verification channel and press **Verify**."


def go_to_channel_notice(guild_name: str, channel_id: str | None, kick_minutes: int | None = None) -> Notice:
    return Notice(embeds=[{"title": f"Verify to enter {guild_name}",
                           "description": f"{_press_verify(channel_id)} {_deadline(kick_minutes)}".strip(), "color": TEAL}])


def closed_dms_notice(user_id: str, seconds: int, kick_minutes: int | None = None) -> Notice:
    return Notice(content=f"<@{user_id}> your DMs are closed, so AltWarden couldn't message you. "
                          f"Press **Verify** on the message in this channel to verify. {_deadline(kick_minutes)}".strip(),
                  mention_users=[user_id], delete_after=seconds)


def verified_notice(guild_name: str) -> Notice:
    return Notice(embeds=[{"title": "You're verified", "description": f"Welcome to **{guild_name}**.", "color": GREEN}])


def wait_notice(guild_name: str, until: float) -> Notice:
    return Notice(embeds=[{"title": f"Please wait before verifying in {guild_name}",
                           "description": f"You're on cooldown after a failed attempt. You can leave the server and rejoin to try again <t:{int(until)}:R>.", "color": AMBER}])


def problem_notice(guild_name: str, title: str, text: str) -> Notice:
    return Notice(embeds=[{"title": f"{title} ({guild_name})", "description": text, "color": AMBER}])


def tries_left(count: int) -> str:
    return f"{count} {'try' if count == 1 else 'tries'} left."


def fixes_text(fixes: list[dict], room: int = DESCRIPTION_LIMIT) -> str:
    """Each fix as Discord text, in as many as fit in the room left. Steps done in Discord carry every device, because the
    member may read this on another device than the one Discord's settings are on."""
    text = ""
    for fix in fixes:
        ways = [way for way in fix["ways"] if way["in_dm"]] if fix["every_way"] else fix["ways"][:1]
        lines = [f"**{fix['title']}**"]
        for way in ways:
            if len(ways) > 1:
                lines.append(f"*{way['heading']}*")
            lines += [f"{number}. {step}" for number, step in enumerate(way["steps"], 1)]
        part = "\n\n" + "\n".join(lines)
        if len(text) + len(part) > room:
            break
        text += part
    return text


STEPS_TITLE = "Try these first"
STEPS_LEAD = "These are the steps for what stopped your last attempt. If you've done them and it still fails, say what happened when you tried."


def steps_embed(fixes: list[dict], room: int) -> dict | None:
    """The steps for a help thread, in the room left in its first message, so the obvious answers are there before anyone asks."""
    text = fixes_text(fixes, room=min(DESCRIPTION_LIMIT, room - len(STEPS_TITLE)) - len(STEPS_LEAD))
    return {"title": STEPS_TITLE, "color": TEAL, "description": STEPS_LEAD + text} if text else None


def _checklist(fixes: list[dict]) -> str:
    return "\n".join(f"- {fix['title']}" for fix in fixes)


def help_thread_lead(fixes: list[dict], channel_id: str | None) -> str:
    """The first lines of a help thread, short and plain, so a member who skips the boxes still sees what to fix."""
    return (f"Your last attempt didn't pass. To get in, you need to:\n{_checklist(fixes)}\n"
            f"The steps are in the box below. {_when_done(channel_id)}")


def help_reminder(user_id: str, fixes: list[dict], channel_id: str | None) -> Notice:
    """Posted once when a member writes in their help thread after a failure, because many write before they read."""
    content = (f"<@{user_id}> Staff will see your message. While you wait, your last attempt needs this fixed:\n{_checklist(fixes)}\n"
               f"The steps are below. {_when_done(channel_id)}")
    embed = steps_embed(fixes, EMBED_LIMIT)
    return Notice(content=content[:2000], embeds=[embed] if embed else [], mention_users=[user_id])


def _when_done(channel_id: str | None) -> str:
    where = f"<#{channel_id}>" if channel_id else "the server's verification channel"
    return f"When you're done, go to {where} and press **Verify** to try again."


def failed_notice(guild_name: str, reason: str, text: str, action: str, public_url: str,
                  appeal_url: str | None, show_reason: bool, retry_on: float | None = None, *, attempts_left: int | None = None, instant: bool = False,
                  fixes: list[dict] | None = None, retry: bool = False, channel_id: str | None = None) -> Notice:
    what = {"kick": "You were removed from the server.", "ban": "You were banned from the server."}.get(action, "")
    body = (text if show_reason else "You didn't pass this server's checks.") + (f"\n\n{what}" if what else "")
    if show_reason and retry_on:
        body += f"\n\nYou can try again after <t:{int(retry_on)}:f>."
    if attempts_left:
        body += f"\n\n{tries_left(attempts_left)}"
    ending = ""
    if instant and action == "deny" and (reason != "max_attempts" or not show_reason):  # Instant mode only checks on a join, so there's no button to press. Rejoining doesn't bring attempts back.
        ending = "\n\nLeave the server and rejoin to try again."
    elif show_reason and fixes and retry and any(fix["after"] for fix in fixes):
        ending = f"\n\n{_when_done(channel_id)}"
    if show_reason and fixes:
        body += fixes_text(fixes, room=DESCRIPTION_LIMIT - len(body) - len(ending))
    body += ending
    # With reasons hidden, a page named after the check would give the reason away.
    slug = HELP_SLUG.get(reason, "verification") if show_reason else "verification"
    buttons = [Button("What to do", url=f"{public_url}/help/{slug}", style="link")]
    if appeal_url:
        buttons.append(Button("Appeal", url=appeal_url, style="link"))
    return Notice(embeds=[{"title": f"You weren't verified in {guild_name}", "description": body, "color": RED}], buttons=buttons)


def timed_out_notice(guild_name: str) -> Notice:
    return Notice(embeds=[{"title": f"Your time to verify in {guild_name} ran out",
                           "description": "You were removed, and you can rejoin and try again.", "color": AMBER}])


def honeypot_notice(guild_name: str, action: str, timeout_minutes: int, appeal_url: str | None) -> Notice:
    what = {"timeout": f"You were timed out for {_duration(timeout_minutes)}.", "kick": "You were removed from the server.",
            "softban": "You were removed from the server, and your recent messages were deleted. You can rejoin.", "ban": "You were banned from the server."}[action]
    return Notice(embeds=[{"title": f"You posted in a trap channel in {guild_name}",
                           "description": f"This server uses a honeypot channel to catch spam accounts, and your account posted in it. {what}", "color": RED}],
                  buttons=[Button("Appeal", url=appeal_url, style="link")] if appeal_url else [])


def timeout_failed_notice(guild_name: str) -> Notice:
    return Notice(embeds=[{"title": f"You weren't timed out in {guild_name}",
                           "description": "AltWarden tried to time you out and it didn't go through. The last message is out of date.", "color": AMBER}])


def kick_retry_notice(guild_name: str) -> Notice:
    """Sent when an Auto Kick AltWarden announced didn't go through. It tries again, so this can't promise they're staying."""
    return Notice(embeds=[{"title": f"You weren't removed from {guild_name} this time",
                           "description": "AltWarden tried to remove you and it didn't go through this time, so you're still in the server. It may be tried again, so verify if you want to stay.",
                           "color": AMBER}])


def not_removed_notice(guild_name: str) -> Notice:
    """Sent when a removal AltWarden announced didn't go through, because the announcement can't wait for the result."""
    return Notice(embeds=[{"title": f"You weren't removed from {guild_name}",
                           "description": "AltWarden tried to remove you and it didn't go through, so you're still in the server. The last message is out of date.",
                           "color": AMBER}])


def kick_reminder_notice(guild_name: str, kick_at: float, mode: str, channel_id: str | None) -> Notice:
    if mode == "instant":
        how = "Leave the server and rejoin to be checked again."
    elif mode == "web":
        how = "Use the link AltWarden sent you" + (f", or press **Verify** in <#{channel_id}>." if channel_id else ".")
    else:
        how = _press_verify(channel_id)
    return Notice(embeds=[{"title": f"Your time to verify in {guild_name} runs out soon",
                           "description": f"You'll be removed <t:{int(kick_at)}:R> if you haven't verified. {how}", "color": AMBER}])


def reset_notice(guild_name: str, url: str | None, channel_id: str | None = None, instant: bool = False, kick_minutes: int | None = None) -> Notice:
    buttons = [Button("Verify", url=url, style="link")] if url else []
    if url:
        where = "Press the button to start."
    elif instant:
        where = "Leave the server and rejoin to be checked again."
    else:
        where = _press_verify(channel_id)
    return Notice(embeds=[{"title": f"Your verification in {guild_name} was reset",
                           "description": f"Staff reset your verification, so you need to verify again. {where} {_deadline(kick_minutes)}".strip(), "color": AMBER}],
                  buttons=buttons)


def appeal_result_notice(guild_name: str, approved: bool, note: str | None) -> Notice:
    title = "Your appeal was approved" if approved else "Your appeal was turned down"
    text = f"Staff in **{guild_name}** reviewed your appeal."
    if note:
        text += f"\n\n{note}"
    return Notice(embeds=[{"title": title, "description": text, "color": GREEN if approved else RED}])


def verification_message(message: dict, *, guild_name: str, help_desk: bool, icon_url: str | None, public_url: str = "") -> Notice:
    embed = _embed(message, guild_name, public_url)
    if not message["thumbnail"] and icon_url:
        embed["thumbnail"] = {"url": icon_url}
    buttons = [Button(message["verify_label"], custom_id="aw:verify", style=message["verify_style"],
                      emoji=message["verify_emoji"] or None)]
    if help_desk:
        buttons.append(Button(message["help_label"], custom_id="aw:help", style=message["help_style"],
                              emoji=message["help_emoji"] or None))
    return Notice(content=message["content"], embeds=[embed], buttons=buttons)


def plain_message(message: dict, guild_name: str = "", public_url: str = "") -> Notice:
    return Notice(content=message["content"], embeds=[_embed(message, guild_name, public_url)])


def _embed(message: dict, guild_name: str, public_url: str = "") -> dict:
    description = message["description"].replace("{server}", guild_name)
    author = message.get("author")
    line = ""
    if author:
        # A customized message names who wrote it, so nobody can pass off a scam as AltWarden's own words.
        report = f" [Report it]({public_url}/security#abuse)" if public_url else ""
        line = f"\n\n*Written by <@{author}> on this server's staff.*{report}"
    # Discord's limits are 4096 here and 6000 across the embed. A long server name in {server} mustn't cost the
    # writer's line, or the whole post.
    room = min(DESCRIPTION_LIMIT, EMBED_LIMIT - len(message["title"]) - len(message["footer"])) - len(line)
    embed = {"title": message["title"], "description": description[:room] + line, "color": message["color"]}
    if message["thumbnail"]:
        embed["thumbnail"] = {"url": message["thumbnail"]}
    if message["image"]:
        embed["image"] = {"url": message["image"]}
    if message["footer"]:
        embed["footer"] = {"text": message["footer"]}
    return embed


# --- staff logs ---------------------------------------------------------------------------------

METHOD_NAMES = {"cookie": "Browser cookie", "fingerprint": "Browser fingerprint", "ip": "IP address", "device": "Device"}


def _safe_name(user_id: str, username: str) -> str:
    # A display name can hold anything. Inside a code span only a backtick or a line break can get out.
    return re.sub(r"[`\r\n]", "", username or "") or user_id


def _account_field(user_id: str, username: str) -> dict:
    return {"name": "Account", "value": f"<@{user_id}>\n`{_safe_name(user_id, username)}`", "inline": True}


def _alt_fields(user_id: str, detail: dict) -> list[dict]:
    """Which account is which, what matched, and what the two devices have in common."""
    other = f"<@{detail['account']}>" + (" (banned)" if detail.get("banned") else "")
    me = f"<@{user_id}>"
    alt, main = (me, other) if detail.get("other_is_main", True) else (other, me)
    fields = [{"name": "Alt account", "value": alt, "inline": True}, {"name": "Main account", "value": main, "inline": True},
              {"name": "Detection", "value": ", ".join(METHOD_NAMES.get(method, method) for method in detail.get("methods", [])) or "Unknown", "inline": False}]
    device = [f"{name}: {'same' if detail[key] else 'different'}" for key, name in (("same_os", "Operating system"), ("same_browser", "Browser")) if detail.get(key) is not None]
    if device:
        fields.append({"name": "Matching device", "value": "\n".join(device), "inline": False})
    return fields


def _attempt_sentence(name: str, decision) -> str:
    if decision.passed:
        return f"`{name}` passed verification." if not decision.findings else f"`{name}` passed verification, with checks on Watch."
    primary = decision.primary
    if primary.check_id == "alt_account":
        return f"`{name}` matched an earlier account."
    if primary.check_id == "max_attempts":
        return f"`{name}` reached the attempt limit."
    return f"`{name}` was stopped by {check_name(primary.check_id)}."


def _detail_text(finding) -> str:
    detail = finding.detail
    parts = []
    if "minimum" in detail:
        parts.append(f"{detail.get('account_days', '?')} days old, minimum {detail['minimum']}")
    if detail.get("network"):
        parts.append(", ".join(detail["network"]))
    if detail.get("signs"):
        parts.append(", ".join(str(item) for item in detail["signs"][:6]))
    if "score" in detail and "account" not in detail:
        parts.append(f"score {detail['score']}")
    if "bot_score" in detail:
        parts.append(f"bot {detail['bot_score']}, suspect {detail['suspect_score']}")
    if "account" in detail:
        parts.append(f"{detail['confidence'].capitalize()} match, score {detail['score']}")
    if "list" in detail:
        parts.append(f"{detail['list']}list rule")
    return "; ".join(parts)


def attempt_log(user_id: str, username: str, avatar_url: str | None, decision, *, took: str, bypassed: list, mode: str, role_given: str | None = None, guild_name: str | None = None) -> dict:
    """One embed for one attempt, listing everything it tripped. Holds no raw identifiers."""
    if decision.passed and not decision.findings:
        title, color = "Member verified", GREEN
    elif decision.passed:
        title, color = "Member verified, checks watched", AMBER
    else:
        title, color = "Verification stopped", RED
    fields = [_account_field(user_id, username), {"name": "Outcome", "value": took, "inline": True}]
    if role_given:
        fields.append({"name": "Role given", "value": f"<@&{role_given}>", "inline": True})
    for finding in decision.findings[:10]:
        label = f"{check_name(finding.check_id)}: {ACTION_LABEL[finding.action]}"
        fields.append({"name": label, "value": _detail_text(finding) or FAILURE_TEXT[finding.reason].format(**(finding.text_args or _no_args(finding))), "inline": False})
        if finding.check_id == "alt_account" and "account" in finding.detail:
            fields += _alt_fields(user_id, finding.detail)
    if bypassed:
        fields.append({"name": "Skipped by bypass link", "value": ", ".join(check_name(item) for item in bypassed), "inline": False})
    embed = {"title": title, "description": _attempt_sentence(_safe_name(user_id, username), decision), "color": color, "fields": fields}
    if avatar_url:
        embed["thumbnail"] = {"url": avatar_url}
    if guild_name:
        embed["footer"] = {"text": guild_name}
    return embed


def _no_args(finding) -> dict:
    return {"days": finding.detail.get("minimum", "?")}


def staff_log(title: str, text: str, color: int = TEAL, **extra) -> dict:
    embed = {"title": title, "description": text, "color": color}
    embed.update(extra)
    return embed


def embed_size(embed: dict) -> int:
    """How much of Discord's limit across a message's embeds this one uses: every title, description, field, footer and author."""
    fields = sum(len(field["name"]) + len(field["value"]) for field in embed.get("fields", []))
    return (len(embed.get("title", "")) + len(embed.get("description", "")) + fields
            + len(embed.get("footer", {}).get("text", "")) + len(embed.get("author", {}).get("name", "")))


def records_embed(rows: list, show_reason: bool, room: int) -> dict | None:
    """A member's recent attempts for their help thread, newest first, in the room left. With reasons hidden it lists only when, not why."""
    title = "Verification records"
    used = len(title)
    lines = []
    for row in rows:
        line = f"<t:{int(row['at'])}:R>" + (f" {check_name(row['check_id'])}" if show_reason else "")
        used += len(line) + (1 if lines else 0)
        if used > room:
            break
        lines.append(line)
    return {"title": title, "color": GRAY, "description": "\n".join(lines)} if lines else None


def help_thread_buttons(user_id: str) -> list[Button]:
    """The rule for each staff button is checked when it's pressed, because the member can see them too."""
    return [Button("Verify", custom_id=f"aw:staff:verify:{user_id}", style="success"),
            Button("Create bypass link", custom_id=f"aw:staff:bypass:{user_id}", style="secondary"),
            Button("Close thread", custom_id="aw:help:close", style="secondary")]


ALT_APPEAL_BUTTONS = "Approve lets them in now, and the link still stands if they rejoin. Approve and trust link is for two different people."


def appeal_card(appeal_id: int, user_id: str, username: str, check_id: str | None, text: str, *, linked: bool = False) -> Notice:
    embed = {"title": "New appeal", "color": AMBER, "description": escape_text(text[:1500]),
             "fields": [_account_field(user_id, username),
                        {"name": "Stopped by", "value": check_name(check_id), "inline": True}]}
    if check_id == "alt_account" or linked:  # a limit reached on an alt link appeals as the limit, and the choice of button still matters
        embed["fields"].append({"name": "Which button", "value": ALT_APPEAL_BUTTONS, "inline": False})
    return Notice(embeds=[embed], buttons=[
        Button("Approve", custom_id=f"aw:appeal:approve:{appeal_id}", style="success"),
        Button("Approve and trust link", custom_id=f"aw:appeal:trust:{appeal_id}", style="primary"),
        Button("Turn down", custom_id=f"aw:appeal:deny:{appeal_id}", style="danger"),
    ])


def _duration(minutes: int) -> str:
    if minutes % 1440 == 0:
        days = minutes // 1440
        return f"{days} day{'s' if days != 1 else ''}"
    if minutes % 60 == 0:
        hours = minutes // 60
        return f"{hours} hour{'s' if hours != 1 else ''}"
    return f"{minutes} minute{'s' if minutes != 1 else ''}"
