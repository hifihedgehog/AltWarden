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
MIN_REFRESH_BYTES = 200  # a shorter body is an error page, not a list

# A carrier's network name is the only free signal for mobile data, so this reads the ASN's
# registered name. It misses carriers with plain names, which the page's connection type backs up.
MOBILE_ORG = re.compile(
    r"\b(wireless|mobility|mobile|cellular|cellco|lte|gsm|umts|5g|4g|t-mobile|tmobile|vodafone|verizon business wireless"
    r"|telefonica moviles|movistar|claro|tim celular|orange mobile|ee limited|hutchison|three uk|airtel|jio|globe telecom"
    r"|smart communications|telstra mobile|optus mobile|rogers wireless|bell mobility|telus mobility)\b", re.IGNORECASE)
# Carriers whose registered names don't say so.
KNOWN_MOBILE_ASNS = frozenset({6167, 22394, 20057, 21928})  # Verizon Wireless, AT&T Mobility, T-Mobile US
NOT_MOBILE_ORG = re.compile(r"\b(county|school|university|college|bank|hosting|cloud|server|datacenter|data center)\b", re.IGNORECASE)

# Large mail providers stay allowed even if a list ever names them by mistake.
TRUSTED_MAIL = frozenset({"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
                          "yahoo.com", "icloud.com", "me.com", "mac.com", "proton.me", "protonmail.com", "pm.me",
                          "aol.com", "gmx.com", "gmx.de", "web.de", "yandex.com", "yandex.ru", "mail.ru", "qq.com",
                          "163.com", "126.com", "naver.com"})

# Providers known to send many unrelated people through one address. Sharing one of these proves nothing.
SHARED_ADDRESS_NETS = tuple(ipaddress.ip_network(net) for net in ("100.64.0.0/10",))  # RFC 6598 carrier-grade NAT


def to_key(address: ipaddress._BaseAddress) -> tuple[int, int]:
    """(family, sort key). IPv6 uses the top 64 bits, the unit every allocation is made in."""
    if address.version == 4:
        return 4, int(address)
    return 6, int(address) >> 64


class RangeTable:
    """Sorted, non-overlapping ranges searched with bisect, packed so a million rows stay small."""

    def __init__(self) -> None:
        self.starts = array("Q")
        self.ends = array("Q")
        self.values: list = []

    def add(self, start: int, end: int, value) -> None:
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


def _load_table(path: Path, table: RangeTable, family: int, parse) -> None:
    if not path.exists():
        return
    shift = 0 if family == 4 else 64
    with path.open(encoding="utf-8", errors="replace", newline="") as handle:
        for row in csv.reader(handle):
            if len(row) < 3:
                continue
            try:
                start, end = int(row[0]) >> shift, int(row[1]) >> shift
            except ValueError:
                continue
            value = parse(row)
            if value is not None:
                table.add(start, end, value)
    table.finish()


def _load_lines(path: Path, target: dict) -> None:
    if not path.exists():
        return
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            entry = line.strip()
            if not entry or entry.startswith("#"):
                continue
            network = ipaddress.ip_network(entry, strict=False) if _is_network(entry) else None
            if network is None:
                continue
            target[network.version].add_text(entry)


def _is_network(entry: str) -> bool:
    try:
        ipaddress.ip_network(entry, strict=False)
        return True
    except ValueError:
        return False


def load_lists(folder: Path) -> ListSet:
    """Read every list from disk. This blocks for a few seconds, so call it in a thread."""
    started = time.monotonic()
    data = ListSet()
    for family in (4, 6):
        _load_table(folder / f"country-ipv{family}.csv", data.country[family], family, lambda row: row[2][:2].upper())

        def parse_asn(row: list[str]) -> int | None:
            try:
                number = int(row[2])
            except ValueError:
                return None
            if len(row) > 3 and number not in data.orgs:
                data.orgs[number] = row[3][:80]
            return number

        _load_table(folder / f"asn-ipv{family}.csv", data.asn[family], family, parse_asn)
        _load_lines(folder / f"vpn-x4b-ipv{family}.txt", data.vpn)
        _load_lines(folder / f"hosting-x4b-ipv{family}.txt", data.hosting)
    for name in OPEN_VPN_FILES:
        _load_lines(folder / f"vpn-open-{name}.txt", data.vpn)
    _load_lines(folder / "tor.txt", data.tor)
    relay = folder / "relay.csv"
    if relay.exists():
        with relay.open(encoding="utf-8", errors="replace") as handle:
            for line in handle:
                entry = line.split(",", 1)[0].strip()
                if entry:
                    data.relay[4 if ":" not in entry else 6].add_text(entry)
    for group in (data.vpn, data.hosting, data.relay, data.tor):
        group[4].finish()
        group[6].finish()
    data.mobile_asns = KNOWN_MOBILE_ASNS | {number for number, org in data.orgs.items()
                                            if MOBILE_ORG.search(org) and not NOT_MOBILE_ORG.search(org)}
    path = folder / "disposable.txt"
    if path.exists():
        with path.open(encoding="utf-8", errors="replace") as handle:
            data.disposable.update(line.strip().lower() for line in handle if line.strip() and not line.startswith("#"))
    data.disposable -= TRUSTED_MAIL
    data.entries = sum(len(table) for group in (data.country, data.asn, data.vpn, data.hosting, data.relay, data.tor)
                       for table in group.values())
    data.loaded_at = time.time()
    log.info("Loaded %d network list entries in %.1f seconds", data.entries, time.monotonic() - started)
    return data


class NetIntel:
    """Local lookups, plus the weekly refresh."""

    def __init__(self, folder: str | Path):
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
            known=self.ready,
        )

    def is_disposable(self, domain: str) -> bool:
        domain = domain.strip().lower().rstrip(".")
        if not domain or domain in TRUSTED_MAIL:
            return False
        parts = domain.split(".")
        return any(".".join(parts[index:]) in self.lists.disposable for index in range(len(parts) - 1))

    def _fresh(self, name: str) -> bool:
        path = self.folder / name
        return path.exists() and time.time() - path.stat().st_mtime <= REFRESH_SECONDS

    async def refresh(self, session: aiohttp.ClientSession | None = None) -> int:
        """Download each list that's missing or old, replacing a file only after a good download. Returns how many changed."""
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
        async with session.get(url, headers={"User-Agent": "AltWarden list refresh"}) as response:
            response.raise_for_status()
            size = 0
            with partial.open("wb") as handle:
                async for chunk in response.content.iter_chunked(1 << 16):
                    handle.write(chunk)
                    size += len(chunk)
        if size < MIN_REFRESH_BYTES:
            partial.unlink(missing_ok=True)
            raise ValueError(f"only {size} bytes")
        os.replace(partial, target)
        return 1

    def missing(self) -> list[str]:
        """Lists that have never downloaded. The Health page shows these, so one can't fail quietly."""
        return [name for name in SOURCES if not (self.folder / name).exists()]

    def stale(self) -> bool:
        return not all(self._fresh(name) for name in SOURCES)


async def external_lookup(session: aiohttp.ClientSession, ip: str, key: str) -> dict | None:
    """Ask proxycheck.io about one address. Runs only for servers that chose this, and fails quietly."""
    try:
        async with session.get(f"https://proxycheck.io/v2/{ip}", params={"key": key, "vpn": 1, "risk": 1},
                               timeout=aiohttp.ClientTimeout(total=3)) as response:
            body = await response.json(content_type=None)
    except Exception as exc:
        log.warning("Outside VPN lookup failed: %s", type(exc).__name__)
        return None
    entry = body.get(ip) if isinstance(body, dict) else None
    return entry if isinstance(entry, dict) else None
