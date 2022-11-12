import logging

from fastapi import FastAPI
from starlette.requests import Request

from aperture.providers.base import BaseProvider, VerifiedChallenge
from aperture.utils import filter_none

app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)

available_providers = filter_none(provider.new() for provider in BaseProvider.__subclasses__())
providers = {provider.identifier: provider for provider in available_providers}

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s - %(message)s")

logger.info(f"Available providers: {', '.join(providers.keys())}")


@app.get("/")
async def root():
    return {"message": "Hello World"}


@app.get("/start/{provider:str}/{challenge:str}")
async def start(provider: str, challenge: str, request: Request):
    if provider not in providers:
        return {"message": "Unknown provider"}

    logger.info(f"Starting challenge {challenge!r} for provider {provider!r}")

    return providers[provider].start_challenge(challenge, request)


@app.get("/verify/{provider:str}")
async def verify(provider: str, request: Request):
    if provider not in providers:
        return {"message": "Unknown provider"}

    logger.info(f"Verifying challenge for provider {provider!r}")

    status = providers[provider].verify_challenge(request)

    if isinstance(status, VerifiedChallenge):
        logger.info(f"Challenge verified for provider {provider!r}")
        return {
            "message": f"Challenge verified",
            "provider": provider,
            "identity": status.identity,
            "challenge": status.challenge,
        }
    else:
        logger.info(f"Challenge failed for provider {provider!r}: {status.reason}")
        return {"message": f"Challenge failed", "provider": provider, "reason": status.reason}
