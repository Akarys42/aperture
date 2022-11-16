import base64
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

REDDIT_BASE = "https://www.reddit.com/api/v1"
OAUTH_ENDPOINT = REDDIT_BASE + "/authorize"
EXCHANGE_ENDPOINT = REDDIT_BASE + "/access_token"
USER_ENDPOINT = "https://oauth.reddit.com/api/v1/me.json"


logger = logging.getLogger(__name__)


class RedditProvider(BaseProvider):
    """
    Class implementing Reddit OAuth.

    The user real name and email is the returned identity
    """

    identifier = "reddit"
    brand_filename = "Reddit_Lockup_OnWhite.svg"
    data_requested = ["Account ID", "Username"]

    def __init__(self, client_id: str, client_secret: str, base_url: str) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = f"{base_url.strip('/')}/verify/reddit/"
        self.user_agent = (
            f"web:aperture.starchild.systems:{os.getenv('GIT_SHA')[:8]} (by /u/Akarys42)"
        )

    def start_challenge(self, challenge: str, request: Request) -> Response:
        """Redirects the user to the Reddit OAuth page with only the identify scope."""
        query = urllib.parse.urlencode(
            {
                "client_id": self.client_id,
                "response_type": "code",
                "scope": "identity",
                "state": self._calculate_state(challenge),
                "redirect_uri": self.redirect_uri,
                "duration": "temporary",
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

        error = request.query_params.get("error", None)
        if error:
            return FailedChallenge(f"Error from Reddit: {error}")

        if request.query_params.get("state", None) != self._calculate_state(challenge):
            return FailedChallenge("Invalid state.")

        code = request.query_params.get("code", None)

        if code is None:
            return FailedChallenge("No code found.")

        data = {
            "code": code,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "User-Agent": self.user_agent,
            "Authorization": f"Basic {self._format_basic_auth()}",
        }

        r = requests.post(EXCHANGE_ENDPOINT, data=data, headers=headers)
        if r.status_code != 200 or "access_token" not in r.json():
            return FailedChallenge(f"Failed to verify code with Reddit ({r.status_code})")

        access_token = r.json()["access_token"]

        headers = {
            "Authorization": f"bearer {access_token}",
            "Accept": "application/json",
            "User-Agent": self.user_agent,
        }
        r = requests.get(USER_ENDPOINT, headers=headers)

        if r.status_code != 200 or "id" not in r.json():
            logger.warning(f"Failed to get user info from Reddit ({r.status_code}): {r.text}")
            return FailedChallenge(f"Failed to get user info from Reddit ({r.status_code}).")

        data = r.json()
        identity = f"/u/{data['name']} ({data['id']})"

        return VerifiedChallenge(identity, challenge)

    def _format_basic_auth(self) -> str:
        """Formats the client ID and secret for basic auth."""
        return base64.urlsafe_b64encode(
            f"{self.client_id}:{self.client_secret}".encode("utf-8")
        ).decode("utf-8")

    @staticmethod
    def _calculate_state(challenge: str) -> str:
        return hashlib.sha256(challenge.encode("utf-8")).hexdigest()[:8]

    @classmethod
    def new(cls) -> Optional["BaseProvider"]:
        """Creates a new instance of the provider if the environment variables are set."""
        required_env = ["REDDIT_ID", "REDDIT_SECRET"]

        if not all(env in os.environ for env in required_env):
            return None

        return cls(os.getenv("REDDIT_ID"), os.getenv("REDDIT_SECRET"), os.getenv("BASE_URL"))
