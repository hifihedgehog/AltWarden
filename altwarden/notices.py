"""Every message AltWarden posts. Plain, with no advertising in any of them."""
from __future__ import annotations

from .catalog import ACTION_LABEL, BY_ID, FAILURE_TEXT, HELP_SLUG
from .ports import Button, Notice

GREEN = 0x2FBF71
RED = 0xE5484D
AMBER = 0xF5A524
TEAL = 0x1FB8A6
GRAY = 0x7A8596
DESCRIPTION_LIMIT = 4096


def check_name(check_id: str | None) -> str:
    if check_id in BY_ID:
        return BY_ID[check_id].name
    return {"cooldown": "Cooldown", "no_email": "No verified email"}.get(check_id, check_id or "Unknown")


def link_notice(guild_name: str, url: str, *, minutes: int, kick_minutes: int | None, bypass: bool = False) -> Notice:
    lines = [f"**{guild_name}** checks new members before letting them in."]
    lines.append("Press the button to verify. The link is yours alone" +
                 (f" and works for the next {_duration(minutes)}." if minutes else "."))
    if bypass:
        lines.append("Staff set this link up for you, so it skips the checks they chose.")
    if kick_minutes:
        lines.append(f"Members who don't verify within {_duration(kick_minutes)} are removed.")
    return Notice(embeds=[{"title": f"Verify to enter {guild_name}", "description": "\n\n".join(lines), "color": TEAL}],
                  buttons=[Button("Verify", url=url, style="link")])


def go_to_channel_notice(guild_name: str, channel_id: str) -> Notice:
    return Notice(embeds=[{"title": f"Verify to enter {guild_name}",
                           "description": f"Go to <#{channel_id}> and press **Verify**.", "color": TEAL}])


def closed_dms_notice(user_id: str, seconds: int) -> Notice:
    return Notice(content=f"<@{user_id}> your DMs are closed, so AltWarden couldn't message you. "
                          "Press **Verify** on the message in this channel to verify.",
                  mention_users=[user_id], delete_after=seconds)


def verified_notice(guild_name: str) -> Notice:
    return Notice(embeds=[{"title": "You're verified", "description": f"Welcome to **{guild_name}**.", "color": GREEN}])


def wait_notice(guild_name: str, until: float) -> Notice:
    return Notice(embeds=[{"title": f"Please wait before verifying in {guild_name}",
                           "description": f"You're on cooldown after a failed attempt. You can try again <t:{int(until)}:R>.", "color": AMBER}])


def problem_notice(guild_name: str, title: str, text: str) -> Notice:
    return Notice(embeds=[{"title": f"{title} ({guild_name})", "description": text, "color": AMBER}])


def failed_notice(guild_name: str, reason: str, text: str, action: str, public_url: str, retry_url: str | None,
                  appeal_url: str | None, show_reason: bool, retry_on: float | None = None) -> Notice:
    what = {"kick": "You were removed from the server.", "ban": "You were banned from the server."}.get(action, "")
    body = (text if show_reason else "You didn't pass this server's checks.") + (f"\n\n{what}" if what else "")
    if show_reason and retry_on:
        body += f"\n\nYou can try again after <t:{int(retry_on)}:f>."
    buttons = [Button("What to do", url=f"{public_url}/help/{HELP_SLUG.get(reason, 'verification')}", style="link")]
    if retry_url and action == "deny":
        buttons.insert(0, Button("Try again", url=retry_url, style="link"))
    if appeal_url:
        buttons.append(Button("Appeal", url=appeal_url, style="link"))
    return Notice(embeds=[{"title": f"You weren't verified in {guild_name}", "description": body, "color": RED}], buttons=buttons)


def timed_out_notice(guild_name: str) -> Notice:
    return Notice(embeds=[{"title": f"Your time to verify in {guild_name} ran out",
                           "description": "You were removed, and you can rejoin and try again.", "color": AMBER}])


def reset_notice(guild_name: str, url: str | None, channel_id: str | None = None, instant: bool = False) -> Notice:
    buttons = [Button("Verify", url=url, style="link")] if url else []
    if url:
        where = "Press the button to start."
    elif instant:
        where = "Leave the server and rejoin to be checked again."
    else:
        where = f"Go to <#{channel_id}> and press **Verify**."
    return Notice(embeds=[{"title": f"Your verification in {guild_name} was reset",
                           "description": f"Staff reset your verification, so you need to verify again. {where}", "color": AMBER}],
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
    # Discord's limit is 4096. A long server name in {server} mustn't cost the writer's line, or the whole post.
    embed = {"title": message["title"], "description": description[:DESCRIPTION_LIMIT - len(line)] + line, "color": message["color"]}
    if message["thumbnail"]:
        embed["thumbnail"] = {"url": message["thumbnail"]}
    if message["image"]:
        embed["image"] = {"url": message["image"]}
    if message["footer"]:
        embed["footer"] = {"text": message["footer"]}
    return embed


# --- staff logs ---------------------------------------------------------------------------------

def _account_field(user_id: str, username: str) -> dict:
    return {"name": "Account", "value": f"<@{user_id}>\n`{username or user_id}`", "inline": True}


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
        banned = ", banned account" if detail.get("banned") else ""
        parts.append(f"<@{detail['account']}>, {detail['confidence']} ({', '.join(detail['methods'])}){banned}")
        for key, name in (("same_os", "system"), ("same_browser", "browser")):
            if detail.get(key) is not None:
                parts.append(f"{'same' if detail[key] else 'different'} {name}")
    if "list" in detail:
        parts.append(f"{detail['list']}list rule")
    return "; ".join(parts)


def attempt_log(user_id: str, username: str, avatar_url: str | None, decision, *, took: str, bypassed: list, mode: str) -> dict:
    """One embed for one attempt, listing everything it tripped. Holds no raw identifiers."""
    if decision.passed and not decision.findings:
        title, color = "Member verified", GREEN
    elif decision.passed:
        title, color = "Member verified, checks watched", AMBER
    else:
        title, color = "Verification stopped", RED
    fields = [_account_field(user_id, username), {"name": "Outcome", "value": took, "inline": True}]
    for finding in decision.findings[:10]:
        label = f"{check_name(finding.check_id)}: {ACTION_LABEL[finding.action]}"
        fields.append({"name": label, "value": _detail_text(finding) or FAILURE_TEXT[finding.reason].format(**(finding.text_args or _no_args(finding))), "inline": False})
    if bypassed:
        fields.append({"name": "Skipped by bypass link", "value": ", ".join(check_name(item) for item in bypassed), "inline": False})
    embed = {"title": title, "color": color, "fields": fields}
    if avatar_url:
        embed["thumbnail"] = {"url": avatar_url}
    return embed


def _no_args(finding) -> dict:
    return {"days": finding.detail.get("minimum", "?")}


def staff_log(title: str, text: str, color: int = TEAL, **extra) -> dict:
    embed = {"title": title, "description": text, "color": color}
    embed.update(extra)
    return embed


def appeal_card(appeal_id: int, user_id: str, username: str, check_id: str | None, text: str) -> Notice:
    embed = {"title": "New appeal", "color": AMBER, "description": text[:1500],
             "fields": [_account_field(user_id, username),
                        {"name": "Stopped by", "value": check_name(check_id), "inline": True}]}
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
    return f"{minutes} minutes"
