"""Keys, keyed hashes, tokens and the proof-of-work puzzle.

No raw IP address, cookie value or browser fingerprint reaches the database. Each one is
replaced by an HMAC under a key derived for one server and one kind of identifier, so:

  * a stolen database holds no readable IP address, cookie or fingerprint,
  * the same person has unrelated digests in two servers, so nobody can link them,
  * the master key stays out of the database, so the digests can't be reversed from it alone.

Derivation is HKDF-SHA256 from RFC 5869. Token storage keeps only a SHA-256 of the token.

A few values have to be read back to be used: a server's proxycheck.io key, and its webhook addresses
and secrets. Those are sealed with AES-GCM under a key for one purpose and one server, so a stolen
database or backup holds nothing usable without the master key.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import secrets
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MASTER_KEY_BYTES = 32
DIGEST_BYTES = 16  # 128 bits: far past any chance of a collision inside one server
SEALED_PREFIX = "v1."
NONCE_BYTES = 12


def hkdf_sha256(ikm: bytes, *, salt: bytes = b"", info: bytes = b"", length: int = 32) -> bytes:
    """HKDF-Extract then HKDF-Expand, as defined in RFC 5869 sections 2.2 and 2.3."""
    if length > 255 * 32:
        raise ValueError("HKDF output is limited to 255 hash blocks")
    prk = hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()
    output, block = b"", b""
    counter = 1
    while len(output) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        output += block
        counter += 1
    return output[:length]


def decode_master_key(value: str) -> bytes:
    """Read the base64 master key from .env and refuse anything too short to be safe."""
    try:
        key = base64.b64decode(value.strip(), validate=True)
    except Exception as exc:
        raise ValueError("MASTER_KEY is not valid base64") from exc
    if len(key) < MASTER_KEY_BYTES:
        raise ValueError(f"MASTER_KEY must hold at least {MASTER_KEY_BYTES} bytes")
    return key


def is_sealed(value: str) -> bool:
    """Whether a stored value is already sealed. Rows from before sealing hold the plain value."""
    return value.startswith(SEALED_PREFIX)


def new_master_key() -> str:
    return base64.b64encode(secrets.token_bytes(MASTER_KEY_BYTES)).decode()


def new_token(nbytes: int = 32) -> str:
    """An unguessable URL-safe token."""
    return secrets.token_urlsafe(nbytes)


def token_hash(token: str) -> str:
    """What the database keeps instead of a token, so a stolen copy can't be replayed."""
    return hashlib.sha256(token.encode("utf-8", "surrogatepass")).hexdigest()  # a cookie can hold any bytes


def network_of(ip: str) -> str:
    """The value alt matching compares: one IPv4 address, or one IPv6 /64.

    A home connection gets a whole /64 and rotates addresses inside it, so comparing full
    IPv6 addresses would miss the same household.
    """
    address = ipaddress.ip_address(ip)
    if address.version == 6:
        mapped = address.ipv4_mapped
        if mapped is not None:
            return str(mapped)
        return str(ipaddress.ip_network(f"{address}/64", strict=False).network_address)
    return str(address)


def wide_network_of(ip: str) -> str:
    """The block one party is likely to hold many addresses in: an IPv6 /48 or an IPv4 /24."""
    address = ipaddress.ip_address(network_of(ip))
    return str(ipaddress.ip_network(f"{address}/{48 if address.version == 6 else 24}", strict=False).network_address)


@dataclass(frozen=True)
class Keyring:
    """Every key AltWarden uses comes from the one master key, one purpose at a time."""

    master: bytes = field(repr=False)  # a stray log line or error report must never carry it

    def derive(self, purpose: str, scope: str = "") -> bytes:
        return hkdf_sha256(self.master, info=f"altwarden/{purpose}/{scope}".encode())

    def database_key(self) -> str:
        """The key for the database file, as the 64 hex digits SQLCipher takes for a raw key. Nothing else uses this purpose, and it's never stored."""
        return self.derive("database").hex()

    def digest(self, guild_id: int, kind: str, value: str) -> str:
        """The stored stand-in for one identifier in one server."""
        key = self.derive("identifier", f"{guild_id}/{kind}")
        return hmac.new(key, value.encode(), hashlib.sha256).digest()[:DIGEST_BYTES].hex()

    def sign(self, purpose: str, message: str) -> str:
        mac = hmac.new(self.derive("sign", purpose), message.encode("utf-8", "surrogatepass"), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(mac).rstrip(b"=").decode()

    def verify(self, purpose: str, message: str, signature: str) -> bool:
        return hmac.compare_digest(self.sign(purpose, message).encode(), signature.encode("utf-8", "surrogatepass"))  # a cookie can hold any bytes, and compare_digest refuses non-ASCII text

    def seal(self, purpose: str, scope: str | int, text: str) -> str:
        """Encrypt a value that has to be read back later. A fresh nonce per call, so equal values look unrelated."""
        nonce = secrets.token_bytes(NONCE_BYTES)
        sealed = AESGCM(self.derive(f"seal/{purpose}", str(scope))).encrypt(nonce, text.encode("utf-8", "surrogatepass"), None)
        return SEALED_PREFIX + base64.b64encode(nonce + sealed).decode()

    def unseal(self, purpose: str, scope: str | int, value: str) -> str:
        """The value `seal` was given. A changed value, or one sealed for another purpose or server, raises ValueError."""
        if not is_sealed(value):
            raise ValueError("That value isn't sealed")
        try:
            raw = base64.b64decode(value[len(SEALED_PREFIX):], validate=True)
            text = AESGCM(self.derive(f"seal/{purpose}", str(scope))).decrypt(raw[:NONCE_BYTES], raw[NONCE_BYTES:], None)
        except (InvalidTag, ValueError) as exc:  # binascii.Error is a ValueError, and so is a short nonce
            raise ValueError("That sealed value can't be opened") from exc
        return text.decode("utf-8", "surrogatepass")

    def new_device_cookie(self) -> str:
        """A random browser identifier, signed so a forged value is never treated as evidence."""
        value = secrets.token_urlsafe(24)
        return f"{value}.{self.sign('device-cookie', value)}"

    def read_device_cookie(self, cookie: str | None) -> str | None:
        """Return the identifier inside a cookie this server issued, or None."""
        if not cookie or cookie.count(".") != 1:
            return None
        value, signature = cookie.split(".")
        return value if self.verify("device-cookie", value, signature) else None


# Proof of work: find a counter so SHA-256(salt + counter) starts with `bits` zero bits. The
# browser pays a fraction of a second, a bulk script pays that for every attempt. This is the
# scheme behind ALTCHA and hashcash. A solved puzzle proves effort, never identity.

def leading_zero_bits(digest: bytes) -> int:
    count = 0
    for byte in digest:
        if byte == 0:
            count += 8
            continue
        return count + 8 - byte.bit_length()
    return count


def pow_solved(salt: str, counter: int, bits: int) -> bool:
    if counter < 0 or counter > 0xFFFFFFFF:
        return False
    digest = hashlib.sha256(f"{salt}{counter}".encode()).digest()
    return leading_zero_bits(digest) >= bits
