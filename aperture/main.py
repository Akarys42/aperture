import logging
import os
from datetime import timedelta, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI
from starlette.requests import Request
import jwt
from starlette.responses import Response

from aperture.providers.base import BaseProvider, VerifiedChallenge
from aperture.utils import filter_none, calculate_key_fingerprint

TOKEN_DURATION = timedelta(days=10)
BASE_URL = os.environ.get("BASE_URL")

app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)

available_providers = filter_none(provider.new() for provider in BaseProvider.__subclasses__())
providers = {provider.identifier: provider for provider in available_providers}

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s - %(message)s")

logger.info(f"Available providers: {', '.join(providers.keys())}")

key_directory = Path("./dev-keys" if os.getenv("USE_DEV_KEYS", None) else "/var/aperture/keys")
with open(key_directory / "rsa.private", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

public_key = private_key.public_key()
fingerprint = calculate_key_fingerprint(public_key)

logger.info(f"Using key {fingerprint}")


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
            "token": create_token(status.identity, status.challenge, provider),
        }
    else:
        logger.info(f"Challenge failed for provider {provider!r}: {status.reason}")
        return {"message": f"Challenge failed", "provider": provider, "reason": status.reason}


@app.get("/rsa.pub")
async def get_public_key():
    return Response(
        public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.PKCS1
        ).decode("utf-8")
    )


def create_token(identity: str, challenge: str, provider: str) -> str:
    data = {
        "exp": datetime.utcnow() + TOKEN_DURATION,
        "nbf": datetime.utcnow(),
        "iat": datetime.utcnow(),
        "iss": BASE_URL,
        "identity": identity,
        "challenge": challenge,
        "provider": provider,
    }
    headers = {"kid": fingerprint}
    token = jwt.encode(data, private_key, algorithm="RS256", headers=headers)
    return token
