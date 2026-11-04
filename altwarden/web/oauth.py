"""Discord sign-in, used for one read and then thrown away.

Follows the authorization code grant in Discord's OAuth2 topic: a `state` value tied to this
browser, an exchange of the code for a token, one read of /users/@me, and then the token is revoked
under RFC 7009. Discord's docs state that revoking a token ends the whole authorization, so no
access or refresh token outlives the request.
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


class OAuthError(Exception):
    pass


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
        token = body.get("access_token")
        if not token:
            raise OAuthError("token exchange returned no token")
        return token

    async def read(self, token: str, path: str):
        headers = {"Authorization": f"Bearer {token}"}
        async with self.session.get(f"{self.api}{path}", headers=headers) as response:
            if response.status != 200:
                raise OAuthError(f"{path} returned {response.status}")
            return await response.json()

    async def revoke(self, token: str) -> None:
        data = {"token": token, "token_type_hint": "access_token"}
        try:
            async with self.session.post(f"{self.api}/oauth2/token/revoke", data=data, auth=self._auth()) as response:
                if response.status != 200:
                    log.warning("Token revocation returned %s", response.status)
        except aiohttp.ClientError as exc:
            log.warning("Token revocation failed: %s", type(exc).__name__)

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
                wait = (await response.json(content_type=None)).get("retry_after", 1)
            await asyncio.sleep(min(float(wait), 10))
        return status

    async def identify(self, code: str, redirect_uri: str, *, guilds: bool = False) -> tuple[dict, list]:
        """Sign someone in, read who they are, and end the authorization, all in one step."""
        token = await self.exchange(code, redirect_uri)
        try:
            me = await self.read(token, "/users/@me")
            joined = await self.read(token, "/users/@me/guilds") if guilds else []
        finally:
            await self.revoke(token)
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
