import logging
import os
from datetime import timedelta, datetime
from pathlib import Path
import string
import random

from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI
from starlette.requests import Request
import jwt
from starlette.responses import Response
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

from aperture.providers.base import BaseProvider, VerifiedChallenge
from aperture.utils import filter_none, calculate_key_fingerprint

TOKEN_DURATION = timedelta(days=10)
BASE_URL = os.environ.get("BASE_URL")
CHALLENGE_LENGTH = 12

app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

_available_providers = filter_none(provider.new() for provider in BaseProvider.__subclasses__())
providers = {provider.identifier: provider for provider in _available_providers}

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
async def root(request: Request) -> Response:
    return templates.TemplateResponse("index.jinja2", {"request": request, "providers": providers})


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
        token = create_token(status.identity, status.challenge, provider)
        return Response(status_code=307, headers={"Location": f"/success?token={token}"})
    else:
        logger.info(f"Challenge failed for provider {provider!r}: {status.reason}")
        return {"message": f"Challenge failed", "provider": provider, "reason": status.reason}


@app.get("/generate/{provider:str}")
async def generate(provider: str, request: Request):
    character_set = string.ascii_letters + string.digits
    random_challenge = "".join(random.choices(character_set, k=CHALLENGE_LENGTH))

    return Response(
        status_code=307, headers={"Location": f"/challenge/{provider}/{random_challenge}"}
    )


@app.get("/challenge/{provider:str}/{challenge:str}")
async def challenge(provider: str, challenge: str, request: Request):
    if provider not in providers:
        return {"message": "Unknown provider"}

    return templates.TemplateResponse(
        "challenge.jinja2",
        {
            "request": request,
            "provider": providers[provider],
            "challenge": challenge,
            "challenge_url": f"{BASE_URL.strip('/')}/start/{provider}/{challenge}",
        },
    )


@app.get("/success")
async def success(request: Request):
    token = request.query_params.get("token", None)

    if token is None:
        return {"message": "Missing token"}

    try:
        decoded = jwt.decode(token, public_key, algorithms=["RS256"])
        kid = jwt.get_unverified_header(token)["kid"]
    except jwt.exceptions.PyJWTError:
        return {"message": "Invalid token"}

    return templates.TemplateResponse(
        "success.jinja2",
        {"request": request, "token": token, "decoded": decoded, "datetime": datetime, "kid": kid},
    )


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
