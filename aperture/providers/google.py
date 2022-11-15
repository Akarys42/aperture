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

OAUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
EXCHANGE_ENDPOINT = "https://oauth2.googleapis.com/token"
USER_ENDPOINT = "https://www.googleapis.com/oauth2/v1/userinfo?alt=json"


logger = logging.getLogger(__name__)


class GoogleProvider(BaseProvider):
    """
    Class implementing Google OAuth.

    The user real name and email is the returned identity
    """

    identifier = "google"
    brand_filename = "google.png"

    def __init__(self, client_id: str, client_secret: str, base_url: str) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = f"{base_url.strip('/')}/verify/google/"

    def start_challenge(self, challenge: str, request: Request) -> Response:
        """Redirects the user to the Discord OAuth page with only the identify scope."""
        query = urllib.parse.urlencode(
            {
                "client_id": self.client_id,
                "response_type": "code",
                "scope": "email profile",
                "state": self._calculate_state(challenge),
                "redirect_uri": self.redirect_uri,
                "prompt": "select_account",
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
            return FailedChallenge(f"Error from Google: {error}")

        if request.query_params.get("state", None) != self._calculate_state(challenge):
            return FailedChallenge("Invalid state.")

        code = request.query_params.get("code", None)

        if code is None:
            return FailedChallenge("No code found.")

        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }

        r = requests.post(EXCHANGE_ENDPOINT, data=data, headers=headers)
        if r.status_code != 200 or "access_token" not in r.json():
            return FailedChallenge(f"Failed to verify code with Google ({r.status_code})")

        access_token = r.json()["access_token"]

        headers = {"Authorization": f"Bearer {access_token}"}
        r = requests.get(USER_ENDPOINT, headers=headers)

        if r.status_code != 200 or "email" not in r.json():
            logger.warning(f"Failed to get user info from Google ({r.status_code}): {r.text}")
            return FailedChallenge(f"Failed to get user info from Google ({r.status_code}).")

        data = r.json()
        identity = f"{data['name']} ({data['email']})"

        return VerifiedChallenge(identity, challenge)

    @staticmethod
    def _calculate_state(challenge: str) -> str:
        return hashlib.sha256(challenge.encode("utf-8")).hexdigest()[:8]

    @classmethod
    def new(cls) -> Optional["BaseProvider"]:
        """Creates a new instance of the provider if the environment variables are set."""
        required_env = ["GOOGLE_ID", "GOOGLE_SECRET"]

        if not all(env in os.environ for env in required_env):
            return None

        return cls(os.getenv("GOOGLE_ID"), os.getenv("GOOGLE_SECRET"), os.getenv("BASE_URL"))
