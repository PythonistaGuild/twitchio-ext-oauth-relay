"""MIT License

Copyright (c) 2025 - Present PythonistaGuild

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any, ClassVar, Literal, Self, TypedDict

import aiohttp

import twitchio
import twitchio.backoff


if TYPE_CHECKING:
    from twitchio.authentication.payloads import UserTokenPayload, ValidateTokenPayload


LOGGER: logging.Logger = logging.getLogger(__name__)


class OAuthPayload(TypedDict):
    code: str
    grant_type: Literal["authorization_code"]
    redirect_uri: str


class OAuthRelay:
    RELAY_URL: ClassVar[str] = "https://twitchio.id/oauth/connect"

    def __init__(self, client: twitchio.Client, *, application_id: str, token: str) -> None:
        self.client = client
        self._application_id = application_id
        self._token = token

        self._socket: aiohttp.ClientWebSocketResponse | None = None
        self._connected: asyncio.Event = asyncio.Event()
        self._backoff = twitchio.backoff.Backoff()

        self._listen_task: asyncio.Task[None] | None = asyncio.create_task(self._listen())
        self._reconnecting: asyncio.Task[None] | None = None

    @property
    def connected(self) -> bool:
        return self._connected.is_set() and self._socket is not None

    @property
    def application_id(self) -> str:
        return self._application_id

    @property
    def headers(self) -> dict[str, str]:
        return {"Application-ID": self.application_id, "Authorization": self._token}

    async def fetch_token(self, code: str, *, redirect: str) -> None:
        try:
            resp: UserTokenPayload = await self.client._http.user_access_token(code, redirect_uri=redirect)
        except twitchio.HTTPException as e:
            LOGGER.error("Unable to authorize user via OAuth-Relay: %s", e)
            return

        try:
            validated: ValidateTokenPayload = await self.client._http.validate_token(resp.access_token)
        except Exception as e:
            LOGGER.error("An error occurred trying to validate token in OAuth-Relay: %s", e)
            return

        resp._user_id = validated.user_id
        resp._user_login = validated.login

        LOGGER.info("Dispatched 'event_oauth_authorized' from OAuth-Relay for user: %s | %s", resp.user_login, resp.user_id)
        self.client.dispatch(event="oauth_authorized", payload=resp)

    async def connect(self) -> None:
        async with aiohttp.ClientSession(headers=self.headers) as session:
            socket = await session.ws_connect(self.RELAY_URL, heartbeat=10)
            session.detach()

            self._socket = socket
            self._connected.set()

        LOGGER.info("Successfully connected to OAuth-Relay.")

    async def reconnect(self) -> None:
        self._connected.clear()

        if self._socket:
            try:
                await self._socket.close()
            except Exception:
                pass

        self._socket = None
        while True:
            try:
                await self.connect()
            except Exception:
                wait = self._backoff.calculate()

                LOGGER.warning("OAuth-Relay trying to reconnect in %d seconds.", wait)
                await asyncio.sleep(wait)
            else:
                break

        LOGGER.info("Successfully reconnected to OAuth-Relay websocket.")

    async def _listen(self) -> None:
        while True:
            await self._connected.wait()

            if not self._socket:
                self._reconnecting = asyncio.create_task(self.reconnect())
                continue

            try:
                data: OAuthPayload = await self._socket.receive_json()
            except Exception:
                self._reconnecting = asyncio.create_task(self.reconnect())
                continue

            try:
                code: str = data["code"]
                grant: Literal["authorization_code"] = data["grant_type"]
                redirect: str = data["redirect_uri"]
            except KeyError:
                LOGGER.warning("Unrecognized payload received in OAuth-Relay.")
                continue

            if grant != "authorization_code":
                LOGGER.warning("Unrecognized payload received in OAuth-Relay.")
                continue

            await self.fetch_token(code, redirect=redirect)

    async def close(self) -> None:
        self._connected.clear()

        if self._listen_task:
            try:
                self._listen_task.cancel()
            except Exception:
                pass

        if self._reconnecting:
            try:
                self._reconnecting.cancel()
            except Exception:
                pass

        if self._socket:
            try:
                await self._socket.close()
            except Exception:
                pass

        self._listen_task = None
        self._socket = None
        self._reconnecting = None

    async def __aenter__(self) -> Self:
        await self.connect()
        return self

    async def __aexit__(self, *args: Any, **kwargs: Any) -> None:
        await self.close()
