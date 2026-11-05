"""What an IP address says about a connection, answered locally from open lists.

Members' addresses go to no outside service unless a server turns on the optional lookup. The
lists are downloaded here and searched in memory, then the address is dropped. Nothing in this
module writes an address anywhere.

  VPN providers   X4BNet lists_vpn, plus first-party lists in open-source-vpn-ip-lists
  Data centers    X4BNet lists_vpn
  Tor exits       the Tor Project's bulk exit list
  Private Relay   Apple's published egress ranges
  Country, ASN    ip-location-db (user-country, origin-asn), public domain under the PDDL
  Throwaway mail  disposable-email-domains
"""
from __future__ import annotations

import asyncio
import contextvars
import csv
import ipaddress
import logging
import os
import re
import time
from array import array
from bisect import bisect_right
from dataclasses import dataclass, field
from pathlib import Path

import aiohttp

log = logging.getLogger("altwarden.netintel")

LOCATION_DB = "https://github.com/sapics/ip-location-db/releases/download/latest"
X4B = "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output"
OPEN_VPN = "https://raw.githubusercontent.com/Joe12387/open-source-vpn-ip-lists/master"
OPEN_VPN_FILES = ("airvpn", "ivpn", "mullvad", "nordvpn", "ovpn", "pia", "protonvpn", "riseupvpn", "surfshark",
                  "windscribe")
SOURCES = {
    "country-ipv4.csv": f"{LOCATION_DB}/user-country-ipv4-num.csv",
    "country-ipv6.csv": f"{LOCATION_DB}/user-country-ipv6-num.csv",
    "asn-ipv4.csv": f"{LOCATION_DB}/origin-asn-ipv4-num.csv",
    "asn-ipv6.csv": f"{LOCATION_DB}/origin-asn-ipv6-num.csv",
    "vpn-x4b-ipv4.txt": f"{X4B}/vpn/ipv4.txt",
    "vpn-x4b-ipv6.txt": f"{X4B}/vpn/ipv6.txt",
    "hosting-x4b-ipv4.txt": f"{X4B}/datacenter/ipv4.txt",
    "hosting-x4b-ipv6.txt": f"{X4B}/datacenter/ipv6.txt",
    "tor.txt": "https://check.torproject.org/torbulkexitlist",
    "relay.csv": "https://mask-api.icloud.com/egress-ip-ranges.csv",
    "disposable.txt": "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf",
    **{f"vpn-open-{name}.txt": f"{OPEN_VPN}/{name}.txt" for name in OPEN_VPN_FILES},
}
REFRESH_SECONDS = 7 * 86400
# A download with fewer good rows than this is an error page or a broken export, so it can't replace the list on
# disk. Each is well under half of what the source published on 2026-11-04, so an ordinary shrink still gets through.
MIN_ROWS = {
    "country-ipv4.csv": 50_000, "country-ipv6.csv": 50_000, "asn-ipv4.csv": 50_000, "asn-ipv6.csv": 50_000,
    "vpn-x4b-ipv4.txt": 1_000, "vpn-x4b-ipv6.txt": 100, "hosting-x4b-ipv4.txt": 5_000, "hosting-x4b-ipv6.txt": 1_000,
    "tor.txt": 200, "relay.csv": 50_000, "disposable.txt": 2_000,
    **{f"vpn-open-{name}.txt": 5 for name in OPEN_VPN_FILES},
}

# A carrier's network name is the only free signal for mobile data, so this reads the ASN's registered name
# for a word that says mobile. A bare brand isn't enough, because Vodafone, Claro, Airtel and Jio also sell home
# lines, and a home line called mobile loses its IP evidence. It misses carriers with plain names, which the
# page's connection type backs up for the Mobile data check.
MOBILE_ORG = re.compile(r"\b(wireless|mobility|mobile|tmobile|cellular|celular|cellco|m[oó]vil|m[oó]viles|lte|gsm|umts|5g|4g|3g)\b", re.IGNORECASE)
# Carriers whose registered names don't say so.
KNOWN_MOBILE_ASNS = frozenset({6167, 22394, 20057, 21928})  # Verizon Wireless, AT&T Mobility, T-Mobile US
NOT_MOBILE_ORG = re.compile(r"\b(county|school|university|college|bank|hosting|cloud|server|datacenter|data center)\b", re.IGNORECASE)

# Large mail providers stay allowed even if a list ever names them by mistake.
TRUSTED_MAIL = frozenset({"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
                          "yahoo.com", "icloud.com", "me.com", "mac.com", "proton.me", "protonmail.com", "pm.me",
                          "aol.com", "gmx.com", "gmx.de", "web.de", "yandex.com", "yandex.ru", "mail.ru", "qq.com",
                          "163.com", "126.com", "naver.com"})

DOMAIN = re.compile(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+")

# Providers known to send many unrelated people through one address. Sharing one of these proves nothing.
SHARED_ADDRESS_NETS = tuple(ipaddress.ip_network(net) for net in ("100.64.0.0/10",))  # RFC 6598 carrier-grade NAT


def to_key(address: ipaddress._BaseAddress) -> tuple[int, int]:
    """(family, sort key). IPv6 uses the top 64 bits, the unit every allocation is made in."""
    if address.version == 4:
        return 4, int(address)
    return 6, int(address) >> 64


MAX_RANGE_VALUE = 2 ** 64 - 1  # what array("Q") holds


class RangeTable:
    """Sorted, non-overlapping ranges searched with bisect, packed so a million rows stay small."""

    def __init__(self) -> None:
        self.starts = array("Q")
        self.ends = array("Q")
        self.values: list = []

    def add(self, start: int, end: int, value) -> None:
        # Checked before anything goes in, or one bad row would leave the three lists out of step and every later lookup wrong.
        if not (0 <= start <= MAX_RANGE_VALUE and 0 <= end <= MAX_RANGE_VALUE):
            raise OverflowError(f"A range value doesn't fit in 64 bits: {start}, {end}")
        self.starts.append(start)
        self.ends.append(end)
        self.values.append(value)

    def finish(self) -> "RangeTable":
        if any(self.starts[i] > self.starts[i + 1] for i in range(len(self.starts) - 1)):
            order = sorted(range(len(self.starts)), key=self.starts.__getitem__)
            self.starts = array("Q", (self.starts[i] for i in order))
            self.ends = array("Q", (self.ends[i] for i in order))
            self.values = [self.values[i] for i in order]
        return self

    def find(self, key: int):
        index = bisect_right(self.starts, key) - 1
        if index >= 0 and key <= self.ends[index]:
            return self.values[index]
        return None

    def __len__(self) -> int:
        return len(self.starts)


class RangeSet:
    """Merged ranges for a yes-or-no question."""

    def __init__(self) -> None:
        self._pending: list[tuple[int, int]] = []
        self.starts = array("Q")
        self.ends = array("Q")

    def add(self, start: int, end: int) -> None:
        self._pending.append((start, end))

    def merge(self, other: "RangeSet") -> None:
        self._pending.extend(other._pending)

    def add_text(self, entry: str) -> int:
        """Add one CIDR or address and return its family, or 0 if the text isn't one."""
        entry = entry.strip()
        if not entry or entry.startswith("#"):
            return 0
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            return 0
        if network.version == 4:
            self.add(int(network.network_address), int(network.broadcast_address))
        else:
            self.add(int(network.network_address) >> 64, int(network.broadcast_address) >> 64)
        return network.version

    def finish(self) -> "RangeSet":
        merged_start, merged_end = array("Q"), array("Q")
        for start, end in sorted(self._pending):
            if merged_end and start <= merged_end[-1] + 1:
                merged_end[-1] = max(merged_end[-1], end)
            else:
                merged_start.append(start)
                merged_end.append(end)
        self.starts, self.ends, self._pending = merged_start, merged_end, []
        return self

    def __contains__(self, key: int) -> bool:
        index = bisect_right(self.starts, key) - 1
        return index >= 0 and key <= self.ends[index]

    def __len__(self) -> int:
        return len(self.starts)


@dataclass
class NetInfo:
    """Everything a check may ask about one connection. Held in memory for one request only."""

    country: str | None = None
    asn: int | None = None
    org: str | None = None
    vpn: bool = False
    tor: bool = False
    relay: bool = False
    hosting: bool = False
    mobile: bool = False
    shared: bool = False
    reserved: bool = False
    known: bool = True

    @property
    def anonymized(self) -> bool:
        return self.vpn or self.tor or self.relay or self.hosting

    def labels(self) -> list[str]:
        """Which kinds of network matched, for the staff log. Names a category, never the address."""
        names = (("vpn", self.vpn), ("tor", self.tor), ("private relay", self.relay), ("data center", self.hosting))
        return [label for label, hit in names if hit]


@dataclass
class ListSet:
    country: dict = field(default_factory=lambda: {4: RangeTable(), 6: RangeTable()})
    asn: dict = field(default_factory=lambda: {4: RangeTable(), 6: RangeTable()})
    vpn: dict = field(default_factory=lambda: {4: RangeSet(), 6: RangeSet()})
    hosting: dict = field(default_factory=lambda: {4: RangeSet(), 6: RangeSet()})
    relay: dict = field(default_factory=lambda: {4: RangeSet(), 6: RangeSet()})
    tor: dict = field(default_factory=lambda: {4: RangeSet(), 6: RangeSet()})
    orgs: dict = field(default_factory=dict)
    mobile_asns: set = field(default_factory=set)
    disposable: set = field(default_factory=set)
    loaded_at: float = 0.0
    entries: int = 0
    rows: dict = field(default_factory=dict)  # file name to the rows the last load read from it


def _read_table(path: Path, family: int, parse) -> RangeTable:
    table = RangeTable()
    shift = 0 if family == 4 else 64
    with path.open(encoding="utf-8", errors="replace", newline="") as handle:
        for row in csv.reader(handle):
            if len(row) < 3:
                continue
            try:
                start, end = int(row[0]) >> shift, int(row[1]) >> shift
                value = parse(row)
                if value is not None:
                    table.add(start, end, value)
            except (ValueError, OverflowError):  # a value that isn't a number, or won't fit in 64 bits
                continue
    return table.finish()


def _read_ranges(path: Path, entry_of) -> tuple[dict, int]:
    """Read addresses and networks into new sets, one entry a line. Returns them and how many lines held one."""
    ranges = {4: RangeSet(), 6: RangeSet()}
    rows = 0
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            entry = entry_of(line).strip()
            family = 6 if ":" in entry else 4
            if ranges[family].add_text(entry) == family:
                rows += 1
    return ranges, rows


def _read_list(name: str, path: Path, data: ListSet) -> int:
    """Read one file into `data` and return its rows. Nothing reaches `data` until the whole file has parsed,
    so a file that fails halfway can't leave half a table to search."""
    if name.startswith(("country-ipv", "asn-ipv")):
        family = 6 if "ipv6" in name else 4
        if name.startswith("country-"):
            data.country[family] = _read_table(path, family, lambda row: row[2][:2].upper())
            return len(data.country[family])
        orgs: dict[int, str] = {}

        def parse_asn(row: list[str]) -> int | None:
            number = int(row[2])
            if len(row) > 3:
                orgs.setdefault(number, row[3][:80])
            return number

        data.asn[family] = _read_table(path, family, parse_asn)
        for number, org in orgs.items():
            data.orgs.setdefault(number, org)
        return len(data.asn[family])
    if name == "disposable.txt":
        with path.open(encoding="utf-8", errors="replace") as handle:
            domains = {line.strip().lower() for line in handle}
        domains = {domain for domain in domains if DOMAIN.fullmatch(domain)}
        data.disposable |= domains
        return len(domains)
    if name == "relay.csv":
        target, entry_of = data.relay, lambda line: line.split(",", 1)[0]
    else:
        target = data.tor if name == "tor.txt" else data.hosting if name.startswith("hosting-") else data.vpn
        entry_of = str
    ranges, rows = _read_ranges(path, entry_of)
    for family in (4, 6):
        target[family].merge(ranges[family])
    return rows


def load_lists(folder: Path) -> ListSet:
    """Read every list from disk. This blocks for a few seconds, so call it in a thread. A file that
    can't be read is logged and skipped, because one bad file mustn't stop the bot from starting."""
    started = time.monotonic()
    data = ListSet()
    for name in SOURCES:
        path = folder / name
        try:
            if path.exists():
                data.rows[name] = _read_list(name, path, data)
        except Exception as exc:
            log.warning("Could not read %s: %s: %s", name, type(exc).__name__, str(exc)[:200])
    for group in (data.vpn, data.hosting, data.relay, data.tor):
        group[4].finish()
        group[6].finish()
    data.mobile_asns = KNOWN_MOBILE_ASNS | {number for number, org in data.orgs.items()
                                            if MOBILE_ORG.search(org) and not NOT_MOBILE_ORG.search(org)}
    data.disposable -= TRUSTED_MAIL
    data.entries = sum(len(table) for group in (data.country, data.asn, data.vpn, data.hosting, data.relay, data.tor)
                       for table in group.values())
    data.loaded_at = time.time()
    log.info("Loaded %d network list entries in %.1f seconds", data.entries, time.monotonic() - started)
    return data


class NetIntel:
    """Local lookups, plus the weekly refresh."""

    def __init__(self, folder: str | Path):
        self._refreshing = asyncio.Lock()
        self.folder = Path(folder)
        self.lists = ListSet()

    @property
    def ready(self) -> bool:
        return self.lists.entries > 0

    async def load(self) -> None:
        self.folder.mkdir(parents=True, exist_ok=True)
        self.lists = await asyncio.to_thread(load_lists, self.folder)

    def lookup(self, ip: str) -> NetInfo:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return NetInfo(known=False)
        if address.version == 6 and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        if not address.is_global:
            shared = any(address in net for net in SHARED_ADDRESS_NETS)
            return NetInfo(reserved=True, shared=shared, known=False)
        family, key = to_key(address)
        data = self.lists
        asn = data.asn[family].find(key)
        return NetInfo(
            country=data.country[family].find(key),
            asn=asn,
            org=data.orgs.get(asn),
            vpn=key in data.vpn[family],
            tor=key in data.tor[family],
            relay=key in data.relay[family],
            hosting=key in data.hosting[family],
            mobile=asn in data.mobile_asns,
            shared=asn in data.mobile_asns,
            # Other lists tell nothing about where an address is, so an allow list can't hold an unplaced address against anyone without this table.
            known=len(data.country[family]) > 0,
        )

    def is_disposable(self, domain: str) -> bool:
        domain = domain.strip().lower().rstrip(".")
        if not domain or domain in TRUSTED_MAIL:
            return False
        try:  # the list holds internationalized domains in their xn-- form
            domain = domain.encode("idna").decode("ascii")
        except UnicodeError:
            pass
        parts = domain.split(".")
        return any(".".join(parts[index:]) in self.lists.disposable for index in range(len(parts) - 1))

    def _fresh(self, name: str) -> bool:
        path = self.folder / name
        return path.exists() and time.time() - path.stat().st_mtime <= REFRESH_SECONDS

    async def refresh(self, session: aiohttp.ClientSession | None = None) -> int:
        """Download each list that's missing or old, replacing a file only after a good download. Returns how many changed."""
        async with self._refreshing:  # startup and the hourly timer can both want this on a first run
            owned = session is None
            session = session or aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=180))
            changed = 0
            try:
                for name, url in SOURCES.items():
                    if self._fresh(name):
                        continue
                    try:
                        changed += await self._fetch(session, name, url)
                    except Exception as exc:
                        log.warning("Could not refresh %s: %s", name, exc)
            finally:
                if owned:
                    await session.close()
            if changed:
                await self.load()
            return changed

    async def _fetch(self, session: aiohttp.ClientSession, name: str, url: str) -> int:
        target = self.folder / name
        partial = target.with_suffix(target.suffix + ".part")
        try:
            async with session.get(url, headers={"User-Agent": "AltWarden list refresh"}) as response:
                response.raise_for_status()
                with partial.open("wb") as handle:
                    async for chunk in response.content.iter_chunked(1 << 16):
                        handle.write(chunk)
            # A 200 can still be an error page, so it's parsed the way the next load will parse it before it counts.
            rows = await asyncio.to_thread(_read_list, name, partial, ListSet())
            if rows < MIN_ROWS[name]:
                raise ValueError(f"only {rows} rows")
            os.replace(partial, target)
        finally:
            partial.unlink(missing_ok=True)
        return 1

    def missing(self) -> list[str]:
        """Lists that have never downloaded. The Health page shows these, so one can't fail quietly."""
        return [name for name in SOURCES if not (self.folder / name).exists()]

    def stale(self) -> bool:
        return not all(self._fresh(name) for name in SOURCES)

    def list_status(self) -> list[dict]:
        """Each list's name, its age in days (None if it never downloaded) and the rows the last load read, for the Health page."""
        rows = []
        for name in SOURCES:
            try:
                age = round((time.time() - (self.folder / name).stat().st_mtime) / 86400, 1)
            except OSError:
                age = None
            rows.append({"name": name, "age_days": age, "rows": self.lists.rows.get(name, 0)})
        return rows


# What proxycheck.io said on its last refusal, for the caller in the same task. Empty when it just couldn't be reached.
last_refusal: contextvars.ContextVar[str | None] = contextvars.ContextVar("last_refusal", default=None)


async def external_lookup(session: aiohttp.ClientSession, ip: str, key: str | None = None) -> dict | None:
    """Ask proxycheck.io about an address. Returns what it detected, `proxy`, `vpn`, `tor` and `hosting`, or None on any failure.

    Runs only for servers that chose this. "anonymous" doesn't count, because it's true for public addresses such as
    Google's DNS. The key is optional: proxycheck.io allows 100 lookups a day without one and 1,000 with a free one.
    """
    last_refusal.set(None)
    try:
        async with session.get(f"https://proxycheck.io/v3/{ip}", params={"key": key} if key else None,
                               timeout=aiohttp.ClientTimeout(total=3)) as response:
            body = await response.json(content_type=None)
    except Exception as exc:
        log.warning("Outside VPN lookup failed: %s", type(exc).__name__)
        return None
    if not isinstance(body, dict):
        return None
    if body.get("status") not in ("ok", "warning"):
        message = body.get("message") if isinstance(body.get("message"), str) else str(body.get("status"))
        if key:
            message = message.replace(key, "[key]")
        last_refusal.set(message[:200])
        log.warning("Outside VPN lookup was refused: %s", last_refusal.get())
        return None
    entry = next((value for value in body.values() if isinstance(value, dict) and isinstance(value.get("detections"), dict)), None)
    return None if entry is None else {name: entry["detections"].get(name) is True for name in ("proxy", "vpn", "tor", "hosting")}


async def check_lookup_key(session: aiohttp.ClientSession, key: str) -> bool | None:
    """Whether proxycheck.io recognizes a key: True, False, or None if it couldn't be asked."""
    try:
        async with session.get("https://proxycheck.io/dashboard/export/usage/", params={"key": key},
                               timeout=aiohttp.ClientTimeout(total=5)) as response:
            body = await response.json(content_type=None)
    except Exception as exc:
        log.warning("Couldn't check a lookup key: %s", type(exc).__name__)
        return None
    if not isinstance(body, dict):
        return None
    return "error" not in body
