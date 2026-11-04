"""Decides whether a member is a second account of someone already in this server.

One matching value doesn't prove much: a family shares an address, and every iPhone of one model
looks alike. So each kind of evidence carries a weight, and staff see how strong the link is.

    cookie       100  the same browser, using a cookie only this site can have set
    fingerprint   70  the same browser setup (35 on iPhones and iPads, which look alike)
    ip            35  the same connection (10 on mobile, VPN and carrier-shared addresses)
    device        20  the same kind of machine, seen across browsers

    confirmed   100 or more
    likely       70 or more
    possible     30 or more

A shared home connection alone scores 35, which is "possible", so by default it never blocks a
sibling. A cookie alone, or a fingerprint plus a connection, is enough to act on.

Everything happens inside one server. Digests are keyed per server, so there is no way to compare
across servers, and this module has no query that could.
"""
from __future__ import annotations

from dataclasses import dataclass, field

WEIGHTS = {"cookie": 100, "fingerprint": 70, "ip": 35, "device": 20}
WEAK_WEIGHTS = {"fingerprint": 35, "ip": 10}
LEVELS = (("confirmed", 100), ("likely", 70), ("possible", 30))
RANK = {"none": 0, "possible": 1, "likely": 2, "confirmed": 3}
# A server's switches cover these kinds of evidence. "device" rides on the fingerprint switch.
METHOD_FOR_KIND = {"cookie": "cookie", "fingerprint": "fingerprint", "device": "fingerprint", "ip": "ip"}


def confidence_for(score: int) -> str:
    for name, floor in LEVELS:
        if score >= floor:
            return name
    return "none"


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

    def as_dict(self) -> dict:
        return {"account": self.other_id, "confidence": self.confidence, "score": self.score,
                "methods": self.methods, "banned": self.banned, "same_os": self.same_os, "same_browser": self.same_browser}


async def find_links(db, guild_id: str, user_id: str, digests: dict[str, str], *, methods: dict, weak_fingerprint: bool,
                     weak_ip: bool) -> list[Link]:
    """Every earlier account sharing evidence with this one, strongest first."""
    evidence: dict[str, dict[str, int]] = {}
    for kind, digest in digests.items():
        if not digest or not methods.get(METHOD_FOR_KIND[kind], False):
            continue
        weight = WEIGHTS[kind]
        if (kind == "fingerprint" and weak_fingerprint) or (kind == "ip" and weak_ip):
            weight = WEAK_WEIGHTS[kind]
        for other_id in await db.matches(guild_id, user_id, kind, digest):
            evidence.setdefault(other_id, {})[kind] = weight

    links = []
    for other_id, kinds in evidence.items():
        if await db.is_trusted_pair(guild_id, user_id, other_id):
            continue
        score = sum(kinds.values())
        confidence = confidence_for(score)
        if confidence == "none":
            continue
        links.append(Link(other_id, score, confidence, sorted(kinds, key=WEIGHTS.get, reverse=True),
                          banned=await db.is_banned(guild_id, other_id)))
    links.sort(key=lambda link: (link.banned, link.score), reverse=True)
    return links


async def compare_profiles(db, guild_id: str, links: list[Link], profile: dict[str, str]) -> None:
    """Note whether each linked account used the same system and browser. Staff read this; it adds no score."""
    for link in links:
        for kind, attribute in (("os", "same_os"), ("browser", "same_browser")):
            stored = await db.digests(guild_id, link.other_id, kind)
            if profile.get(kind) and stored:
                setattr(link, attribute, profile[kind] in stored)


def strongest(links: list[Link], minimum: str) -> Link | None:
    """The link to act on, if any reaches the server's chosen confidence."""
    floor = RANK.get(minimum, RANK["likely"])
    for link in links:
        if RANK[link.confidence] >= floor:
            return link
    return None


async def assign_roles(db, guild_id: str, user_id: str, link: Link) -> None:
    """The account that verified first is the main one. Anything else is the alt."""
    mine = await db.member(guild_id, user_id)
    theirs = await db.member(guild_id, link.other_id)
    my_time = (mine or {}).get("verified_at")
    their_time = (theirs or {}).get("verified_at")
    link.other_is_main = not (my_time and (not their_time or my_time < their_time))
