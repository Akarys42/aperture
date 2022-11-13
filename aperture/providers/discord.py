import hashlib
import logging
import os
import urllib.parse
from typing import Optional

import requests
from starlette.requests import Request
from starlette.responses import Response

from aperture.providers.base import (
    BaseProvider,
    ChallengeResponse,
    FailedChallenge,
    VerifiedChallenge,
)

DISCORD_BASE = "https://discord.com/api/v10"
OAUTH_ENDPOINT = DISCORD_BASE + "/oauth2/authorize"
EXCHANGE_ENDPOINT = DISCORD_BASE + "/oauth2/token"
ME_ENDPOINT = DISCORD_BASE + "/users/@me"


logger = logging.getLogger(__name__)


class DiscordProvider(BaseProvider):
    """
    Class implementing Discord OAuth.

    The user ID is the returned identity
    """

    identifier = "discord"
    brand_filename = "discord-logo-white.svg"

    def __init__(self, client_id: str, client_secret: str, base_url: str) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.verify_url = f"{base_url.strip('/')}/verify/discord/"

    def start_challenge(self, challenge: str, request: Request) -> Response:
        """Redirects the user to the Discord OAuth page with only the identify scope."""
        query = urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": self.client_id,
                "scope": "identify",
                "state": self._calculate_state(challenge),
                "redirect_uri": self.verify_url,
                "prompt": "consent",
            }
        )

        set_cookie = f"challenge={challenge}; Path=/; Max-Age=300; HttpOnly; SameSite=Lax"

        return Response(
            status_code=307,
            headers={"Location": f"{OAUTH_ENDPOINT}?{query}", "Set-Cookie": set_cookie},
        )

    def verify_challenge(self, request: Request) -> ChallengeResponse:
        """Verifies the challenge by exchanging the code and querying the UID."""
        challenge = request.cookies.get("challenge", None)

        if challenge is None:
            return FailedChallenge("No challenge cookie found. Are cookies disabled?")

        if request.query_params.get("state", None) != self._calculate_state(challenge):
            return FailedChallenge("Invalid state.")

        code = request.query_params.get("code", None)

        if code is None:
            return FailedChallenge("No code found.")

        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.verify_url,
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        r = requests.post(EXCHANGE_ENDPOINT, data=data, headers=headers)
        if r.status_code != 200 or "access_token" not in r.json():
            return FailedChallenge(f"Failed to verify code with Discord ({r.status_code}).")

        access_token = r.json()["access_token"]

        headers = {"Authorization": f"Bearer {access_token}"}
        r = requests.get(ME_ENDPOINT, headers=headers)

        if r.status_code != 200 or "id" not in r.json():
            logger.warning(f"Failed to get user info from Discord ({r.status_code}): {r.text}")
            return FailedChallenge(f"Failed to get user info from Discord ({r.status_code}).")

        return VerifiedChallenge(r.json()["id"], challenge)

    @staticmethod
    def _calculate_state(challenge: str) -> str:
        return hashlib.sha256(challenge.encode("utf-8")).hexdigest()[:8]

    @classmethod
    def new(cls) -> Optional["BaseProvider"]:
        """Creates a new instance of the provider if the environment variables are set."""
        required_env = ["DISCORD_ID", "DISCORD_SECRET"]

        if not all(env in os.environ for env in required_env):
            return None

        return cls(os.getenv("DISCORD_ID"), os.getenv("DISCORD_SECRET"), os.getenv("BASE_URL"))
