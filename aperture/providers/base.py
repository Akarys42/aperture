import abc
from collections import namedtuple
from typing import Optional

from starlette.requests import Request
from starlette.responses import Response

VerifiedChallenge = namedtuple("VerifiedChallenge", ["identity", "challenge"])
FailedChallenge = namedtuple("FailedChallenge", ["reason"])

ChallengeResponse = FailedChallenge | VerifiedChallenge


class BaseProvider(abc.ABC):
    """This is the base class implemented by all identity providers."""

    @property
    @abc.abstractmethod
    def identifier(self) -> str:
        """The unique identifier of this provider."""
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def brand_filename(self) -> str:
        """The filename of the brand logo of this provider."""
        raise NotImplementedError

    @abc.abstractmethod
    def start_challenge(self, challenge: str, request: Request) -> Response:
        """
        Starts a challenge with the provider.

        The challenge is a unique identifier that should be verified at the end of the session.
        It can be stored in the `challenge` cookie.

        The provider shall respond to the request with a redirect to the provider's login page,
        or a html page explaining the verification process.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def verify_challenge(self, request: Request) -> ChallengeResponse:
        """
        Verifies a challenge with the provider.

        The provider shall verify the challenge and return a `VerifiedChallenge`
        if the challenge was successful, else a `FailedChallenge` with an appropriate reason.
        """
        raise NotImplementedError

    @classmethod
    @abc.abstractmethod
    def new(cls) -> Optional["BaseProvider"]:
        """
        Creates a new instance of the provider.

        This method can return `None` if the provider is not configured.
        """
        raise NotImplementedError
