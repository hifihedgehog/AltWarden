"""Decides whether a member is a second account of someone already in this server.

Any one match on a connection, a browser cookie or a browser fingerprint makes the new account an alt
of the earlier one, and the server's chosen action applies. Each kind of evidence carries a weight, so
staff see how strong the link is:

    cookie       100  the same browser, using a cookie only this site can have set
    fingerprint   45  the same browser setup (10 on phones, tablets and Chromebooks, which look alike)
    ip            70  the same connection (10 on VPN and carrier-shared addresses)
    device        20  the same kind of machine, seen across browsers

    confirmed   100 or more
    likely       70 or more
    possible     30 or more

Only the cookie is signed by this server, so without it a score stops at 99 and the link can't be
"confirmed". The same kind of machine on the same connection adds 15, as long as neither is one of the
weak kinds above.

The kind of machine alone, and evidence weak on this attempt, never make a match, because every phone of
one model and every customer behind one carrier address look like that. A server can raise its floor
above "possible" to act on less. A link to a banned account counts from 60 even then.

Everything happens inside one server. Digests are keyed per server, so there is no way to compare
across servers, and this module has no query that could.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from .catalog import DENY, SEVERITY, WATCH

WEIGHTS = {"cookie": 100, "fingerprint": 45, "ip": 70, "device": 20}
WEAK_WEIGHTS = {"fingerprint": 10, "ip": 10}
PAIR_BONUS = 15
SCORE_WITHOUT_COOKIE = 99
LEVELS = (("confirmed", 100), ("likely", 70), ("possible", 30))
BANNED_LINK_SCORE = 60  # a link to a banned account counts from here, whatever a server's floor is
RANK = {"none": 0, "possible": 1, "likely": 2, "confirmed": 3}
# A server's switches cover these kinds of evidence. "device" rides on the fingerprint switch.
METHOD_FOR_KIND = {"cookie": "cookie", "fingerprint": "fingerprint", "device": "fingerprint", "ip": "ip"}


def confidence_for(score: int) -> str:
    for name, floor in LEVELS:
        if score >= floor:
            return name
    return "none"


def score_for(kinds: Iterable[str], weak: Iterable[str] = ()) -> int:
    """The score for a set of matching evidence. `weak` names what counts for less on this attempt."""
    kinds, weak = set(kinds), set(weak)
    score = sum(WEAK_WEIGHTS[kind] if kind in weak else WEIGHTS[kind] for kind in kinds)
    if {"ip", "device"} <= kinds and not weak:
        score += PAIR_BONUS
    return score if "cookie" in kinds else min(score, SCORE_WITHOUT_COOKIE)


def judge(check: dict, banned: bool, other_is_main: bool) -> tuple[str, str]:
    """What a link does: the action on this member, and the action on the other account."""
    if banned:
        return check["banned_alt_action"], WATCH
    if other_is_main:
        return check["alt_action"], check["main_action"]
    return check["main_action"], WATCH  # this account verified first, so it's the main one


@dataclass
class Link:
    """A match between the member verifying now and one earlier account."""

    other_id: str
    score: int
    confidence: str
    methods: list[str] = field(default_factory=list)
    banned: bool = False
    other_is_main: bool = True
    same_os: bool | None = None
    same_browser: bool | None = None
    verified: bool = False
    weak: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        found = {"account": self.other_id, "confidence": self.confidence, "score": self.score, "methods": self.methods, "banned": self.banned,
                 "other_is_main": self.other_is_main, "same_os": self.same_os, "same_browser": self.same_browser}
        return {**found, "weak": self.weak} if self.weak else found


def lock_keys(digests: dict[str, str], alt: dict, *, weak_fingerprint: bool, weak_ip: bool) -> dict[str, str]:
    """The evidence two attempts at once have to queue on, or each could read the other as not yet verified and both would pass.

    These are enough because of how scores add up. A device value scores 20 alone, below possible, so any link that counts also
    matches on a cookie, a fingerprint or an address, and those lock. Above possible a weak value adds too little to matter: the
    least that counts is 60, and a weak fingerprint plus a device and a full-weight address reach it only through that address.
    Every machine of one model shares a device value, and every phone of one model a weak fingerprint, so locking on those would
    make strangers verify single file.
    """
    if not alt["enabled"]:
        return {}
    above_possible = RANK.get(alt["min_confidence"], RANK["likely"]) > RANK["possible"]
    weak = {kind for kind, is_weak in (("fingerprint", weak_fingerprint), ("ip", weak_ip)) if is_weak and above_possible}
    return {kind: digest for kind, digest in digests.items() if kind != "device" and kind not in weak and alt["methods"].get(METHOD_FOR_KIND[kind], False)}


async def find_links(db, guild_id: str, user_id: str, digests: dict[str, str], *, methods: dict, weak_fingerprint: bool,
                     weak_ip: bool) -> list[Link]:
    """Every account sharing evidence with this one, strongest first. `counting` decides which of them count."""
    weak = [kind for kind, is_weak in (("fingerprint", weak_fingerprint), ("ip", weak_ip)) if is_weak]
    evidence: dict[str, set[str]] = {}
    for kind, digest in digests.items():
        if not digest or not methods.get(METHOD_FOR_KIND[kind], False):
            continue
        for other_id in await db.matches(guild_id, user_id, kind, digest):
            evidence.setdefault(other_id, set()).add(kind)

    scores = {other_id: score_for(kinds, weak) for other_id, kinds in evidence.items()}
    # A shared address can hold thousands of accounts, so everything about them is read in one go.
    facts = await db.link_facts(guild_id, user_id, [other_id for other_id, score in scores.items() if confidence_for(score) != "none"])
    links = [Link(other_id, scores[other_id], confidence_for(scores[other_id]), sorted(evidence[other_id], key=WEIGHTS.get, reverse=True),
                  banned=fact["banned"], verified=fact["verified"], weak=weak)
             for other_id, fact in facts.items() if not fact["trusted"]]
    # Accounts that count go first, or a pile of failed attempts could push the one real match out of the list.
    links.sort(key=lambda link: (link.banned, link.verified, link.score), reverse=True)
    return links


async def compare_profiles(db, guild_id: str, links: list[Link], profile: dict[str, str]) -> None:
    """Note whether each linked account used the same system and browser. Staff read this; it adds no score."""
    for link in links:
        for kind, attribute in (("os", "same_os"), ("browser", "same_browser")):
            stored = await db.digests(guild_id, link.other_id, kind)
            if profile.get(kind) and stored:
                setattr(link, attribute, profile[kind] in stored)


def strong_enough(link: Link, minimum: str) -> bool:
    """Whether a link scores enough to count if the other account is banned. Below a server's floor, only a ban can make it count."""
    if RANK[link.confidence] >= RANK.get(minimum, RANK["possible"]):
        return True
    # A phone's fingerprint is weak, so two people with one model at one address reach this score without being one person.
    return link.score >= BANNED_LINK_SCORE and "fingerprint" not in link.weak


def counting(links: list[Link], minimum: str) -> list[Link]:
    """The links at or above a confidence that can make this member a second account, and links to banned accounts from BANNED_LINK_SCORE.

    Someone who tried and never got in, and wasn't banned, isn't an account this one can be a second
    account of. Anyone who ever got in still counts, even after failing a later check or leaving.
    """
    floor = RANK.get(minimum, RANK["possible"])
    return [link for link in links if not looks_alike_only(link) and ((link.verified and RANK[link.confidence] >= floor) or (link.banned and strong_enough(link, minimum)))]


def looks_alike_only(link: Link) -> bool:
    """Whether nothing but the kind of machine, or evidence weak on this attempt, ties a link together. Strangers with one phone model look like this."""
    return set(link.methods) - set(link.weak) <= {"device"}


async def assign_roles(db, guild_id: str, user_id: str, link: Link) -> None:
    """The account that verified first is the main one. Anything else is the alt."""
    mine = await db.member(guild_id, user_id)
    theirs = await db.member(guild_id, link.other_id)
    my_time = (mine or {}).get("first_verified_at")
    their_time = (theirs or {}).get("first_verified_at")
    link.other_is_main = not (my_time and (not their_time or my_time < their_time))
