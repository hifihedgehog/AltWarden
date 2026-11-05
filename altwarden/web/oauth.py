"""Discord sign-in, used for one read and then thrown away.

Follows the authorization code grant in Discord's OAuth2 topic: a `state` value tied to this
browser, an exchange of the code for a token, one read of /users/@me, and then the token is revoked
under RFC 7009. Discord's docs state that revoking a token ends the whole authorization. No access
or refresh token is ever stored. If Discord refuses or doesn't answer all three revoke tries, the
token stays valid at Discord until its own expiry, and the log says so.
"""
from __future__ import annotations

import asyncio
import logging
from urllib.parse import urlencode

import aiohttp

log = logging.getLogger("altwarden.oauth")

API = "https://discord.com/api/v10"
AUTHORIZE = "https://discord.com/oauth2/authorize"
COMMAND_PERMISSION_TYPES = {"role": 1, "user": 2, "channel": 3}
REVOKE_TRIES = 3
REVOKE_SECONDS = 5


class OAuthError(Exception):
    pass


# What a talk with Discord can end in. A total timeout raises plain TimeoutError, which isn't a ClientError,
# and a 200 with a body that isn't JSON raises ValueError.
FAILURES = (OAuthError, aiohttp.ClientError, TimeoutError, ValueError)


class DiscordOAuth:
    def __init__(self, session: aiohttp.ClientSession, client_id: str, client_secret: str, *, api: str = API):
        self.session = session
        self.client_id = client_id
        self.client_secret = client_secret
        self.api = api

    def authorize_url(self, *, redirect_uri: str, state: str, scopes: list[str], prompt: str = "none") -> str:
        query = {"response_type": "code", "client_id": self.client_id, "scope": " ".join(scopes), "state": state,
                 "redirect_uri": redirect_uri, "prompt": prompt}
        return f"{AUTHORIZE}?{urlencode(query)}"

    def _auth(self) -> aiohttp.BasicAuth:
        return aiohttp.BasicAuth(self.client_id, self.client_secret)

    async def exchange(self, code: str, redirect_uri: str) -> str:
        """Trade the one-time code for an access token. The refresh token is ignored and never stored."""
        data = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri}
        async with self.session.post(f"{self.api}/oauth2/token", data=data, auth=self._auth()) as response:
            if response.status != 200:
                raise OAuthError(f"token exchange returned {response.status}")
            body = await response.json()
        token = body.get("access_token") if isinstance(body, dict) else None
        if not token:
            raise OAuthError("token exchange returned no token")
        return token

    async def read(self, token: str, path: str):
        headers = {"Authorization": f"Bearer {token}"}
        async with self.session.get(f"{self.api}{path}", headers=headers) as response:
            if response.status != 200:
                raise OAuthError(f"{path} returned {response.status}")
            return await response.json()

    async def read_me(self, token: str) -> dict:
        """The signed-in account. An answer with no ID is a failure, because everything after it keys on the ID."""
        me = await self.read(token, "/users/@me")
        if not isinstance(me, dict) or not me.get("id"):
            raise OAuthError("/users/@me returned no account")
        return me

    async def revoke(self, token: str) -> None:
        """End the authorization. This runs after the account has been read, so a failure here is logged and never costs the sign-in."""
        data = {"token": token, "token_type_hint": "access_token"}
        problem = "no answer"
        for _ in range(REVOKE_TRIES):
            try:
                async with self.session.post(f"{self.api}/oauth2/token/revoke", data=data, auth=self._auth(),
                                             timeout=aiohttp.ClientTimeout(total=REVOKE_SECONDS)) as response:
                    if response.status == 200:
                        return
                    problem = f"status {response.status}"
            except Exception as exc:
                problem = type(exc).__name__
        log.warning("Token revocation failed after %s tries: %s. The token lasts until Discord expires it.", REVOKE_TRIES, problem)

    async def edit_command_permissions(self, token: str, guild_id: str, command_id: str, overrides: list[dict]) -> int:
        """Replace one command's overrides with the signed-in person's own token. Returns the HTTP status."""
        url = f"{self.api}/applications/{self.client_id}/guilds/{guild_id}/commands/{command_id}/permissions"
        body = {"permissions": [{"id": entry["id"], "type": COMMAND_PERMISSION_TYPES[entry["type"]], "permission": entry["allow"]}
                                for entry in overrides]}
        headers = {"Authorization": f"Bearer {token}"}
        status = 0
        for _ in range(3):
            async with self.session.put(url, json=body, headers=headers) as response:
                status = response.status
                if status != 429:
                    return status
                try:
                    wait = float((await response.json(content_type=None)).get("retry_after", 1))
                except (ValueError, TypeError, AttributeError):
                    wait = 1.0
            await asyncio.sleep(min(wait, 10))
        return status

    async def identify(self, code: str, redirect_uri: str, *, guilds: bool = False) -> tuple[dict, list]:
        """Sign someone in, read who they are, and end the authorization, all in one step."""
        token = await self.exchange(code, redirect_uri)
        try:
            me = await self.read_me(token)
            joined = await self.read(token, "/users/@me/guilds") if guilds else []
        finally:
            await self.revoke(token)
        if not isinstance(joined, list) or not all(isinstance(guild, dict) and guild.get("id") for guild in joined):
            raise OAuthError("/users/@me/guilds returned no list of servers")
        return me, joined


def account_from(me: dict, is_disposable, *, wants_email: bool) -> dict:
    """Keep only what the checks need. The email address itself stops here."""
    account = {"id": str(me["id"]), "username": str(me.get("username", ""))[:40], "avatar": me.get("avatar"),
               "mfa": me.get("mfa_enabled")}
    if wants_email:
        email = me.get("email")
        account["email_verified"] = bool(email) and me.get("verified") is True
        domain = email.rsplit("@", 1)[-1] if isinstance(email, str) and "@" in email else ""
        account["email_disposable"] = bool(domain) and is_disposable(domain)
    return account
