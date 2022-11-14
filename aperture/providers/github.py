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

OAUTH_ENDPOINT = "https://github.com/login/oauth/authorize"
EXCHANGE_ENDPOINT = "https://github.com/login/oauth/access_token"
USER_ENDPOINT = "https://api.github.com/user"


logger = logging.getLogger(__name__)


class GithubProvider(BaseProvider):
    """
    Class implementing Github OAuth.

    The user name and ID is the returned identity
    """

    identifier = "github"
    human_identifier = "GitHub"
    brand_filename = "GitHub_Logo_White.png"

    def __init__(self, client_id: str, client_secret: str, base_url: str) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.verify_url = f"{base_url.strip('/')}/verify/github/"

    def start_challenge(self, challenge: str, request: Request) -> Response:
        """Redirects the user to the Discord OAuth page with only the identify scope."""
        query = urllib.parse.urlencode(
            {
                "client_id": self.client_id,
                "scope": "",
                "state": self._calculate_state(challenge),
                "redirect_uri": self.verify_url,
                "allow_signup": "false",
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
            "code": code,
            "redirect_uri": self.verify_url,
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }

        r = requests.post(EXCHANGE_ENDPOINT, data=data, headers=headers)
        if r.status_code != 200 or "access_token" not in r.json():
            return FailedChallenge(f"Failed to verify code with GitHub ({r.status_code}): {r.text}")

        access_token = r.json()["access_token"]

        headers = {"Authorization": f"Bearer {access_token}"}
        r = requests.get(USER_ENDPOINT, headers=headers)

        if r.status_code != 200 or "id" not in r.json():
            logger.warning(f"Failed to get user info from GitHub ({r.status_code}): {r.text}")
            return FailedChallenge(f"Failed to get user info from GitHub ({r.status_code}).")

        data = r.json()
        identity = f"{data['login']} ({data['id']})"

        return VerifiedChallenge(identity, challenge)

    @staticmethod
    def _calculate_state(challenge: str) -> str:
        return hashlib.sha256(challenge.encode("utf-8")).hexdigest()[:8]

    @classmethod
    def new(cls) -> Optional["BaseProvider"]:
        """Creates a new instance of the provider if the environment variables are set."""
        required_env = ["GITHUB_ID", "GITHUB_SECRET"]

        if not all(env in os.environ for env in required_env):
            return None

        return cls(os.getenv("GITHUB_ID"), os.getenv("GITHUB_SECRET"), os.getenv("BASE_URL"))
