import logging
import os
import random
import string
from datetime import datetime, timedelta

import jwt
from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.requests import Request
from starlette.responses import Response

from aperture.providers.base import BaseProvider, VerifiedChallenge
from aperture.utils import calculate_key_fingerprint, filter_none

TOKEN_DURATION = timedelta(days=10)
BASE_URL = os.environ.get("BASE_URL")
CHALLENGE_LENGTH = 12
CHALLENGE_LENGTH_LIMIT = 256

app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

_available_providers = filter_none(provider.new() for provider in BaseProvider.__subclasses__())
providers = {provider.identifier: provider for provider in _available_providers}

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s - %(message)s")

logger.info(f"Available providers: {', '.join(providers.keys())}")

if os.getenv("USE_DEV_KEYS", None):
    with open("./dev-keys/rsa.private", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
        logger.warning("Development key loaded. Do *not* use this in prod.")
else:
    private_key = serialization.load_pem_private_key(
        os.getenv("RSA_KEY").encode("utf-8"), password=None
    )

BASE_URL = os.getenv("BASE_URL", None)
if not BASE_URL:
    logging.error("BASE_URL environment variable isn't set.")
    exit(1)

public_key = private_key.public_key()
fingerprint = calculate_key_fingerprint(public_key)

logger.info(f"Using key {fingerprint}")


@app.get("/")
async def root(request: Request) -> Response:
    """Return the service index."""
    return templates.TemplateResponse("index.jinja2", {"request": request, "providers": providers})


@app.get("/start/{provider:str}/{challenge:str}")
async def start(provider: str, challenge: str, request: Request) -> Response:
    """Start the authentication process."""
    if provider not in providers:
        raise HTTPException(status_code=404, detail="Provider not found")

    if len(challenge) > CHALLENGE_LENGTH_LIMIT:
        raise HTTPException(status_code=400, detail="Challenge too long")

    logger.info(f"Starting challenge {challenge!r} for provider {provider!r}")

    return providers[provider].start_challenge(challenge, request)


@app.get("/verify/{provider:str}")
async def verify(provider: str, request: Request) -> Response:
    """Verify the authentication process and emit a token if it succeeded."""
    if provider not in providers:
        raise HTTPException(status_code=404, detail="Provider not found")

    logger.info(f"Verifying challenge for provider {provider!r}")

    status = providers[provider].verify_challenge(request)

    if isinstance(status, VerifiedChallenge):
        logger.info(f"Challenge verified for provider {provider!r}")
        token = create_token(status.identity, status.challenge, provider)
        return Response(status_code=307, headers={"Location": f"/success?token={token}"})
    else:
        logger.info(f"Challenge failed for provider {provider!r}: {status.reason}")
        return templates.TemplateResponse(
            "failure.jinja2", {"request": request, "reason": status.reason, "is_user_error": False}
        )


@app.get("/generate/{provider:str}")
async def generate(provider: str) -> Response:
    """Redirect to a challenge page with a random challenge string."""
    character_set = string.ascii_letters + string.digits
    random_challenge = "".join(random.choices(character_set, k=CHALLENGE_LENGTH))

    return Response(
        status_code=307, headers={"Location": f"/challenge/{provider}/{random_challenge}"}
    )


@app.get("/challenge/{provider:str}/{challenge:str}")
async def challenge(provider: str, challenge: str, request: Request) -> Response:
    """Returns an HTML page explaining the challenge."""
    if provider not in providers:
        raise HTTPException(status_code=404, detail="Provider not found")

    if len(challenge) > CHALLENGE_LENGTH_LIMIT:
        raise HTTPException(status_code=400, detail="Challenge too long")

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
async def success(request: Request) -> Response:
    """Returns an HTML page verifying and showcasing the token details."""
    token = request.query_params.get("token", None)
    error = None
    is_user_error = False

    if token is None:
        error = "Missing token"

    if not error:
        try:
            decoded = jwt.decode(token, public_key, algorithms=["RS256"])
            kid = jwt.get_unverified_header(token)["kid"]

        except jwt.exceptions.InvalidSignatureError:
            error = "Invalid token signature"
        except jwt.exceptions.DecodeError:
            error = "Error decoding token"
        except jwt.exceptions.ExpiredSignatureError:
            error = (
                f"Token expired. For security reasons, "
                f"tokens are only valid for {TOKEN_DURATION.days} days."
            )
            is_user_error = True
        except jwt.exceptions.ImmatureSignatureError:
            error = "Token not yet valid. Do you have a time machine?"
            is_user_error = True
        except jwt.exceptions.PyJWTError:
            error = "Error decoding token"

    if error:
        return templates.TemplateResponse(
            "failure.jinja2", {"request": request, "reason": error, "is_user_error": is_user_error}
        )

    if decoded["provider"] in providers:
        human_provider = providers[decoded["provider"]].human_identifier
    else:
        human_provider = decoded["provider"].title()

    return templates.TemplateResponse(
        "success.jinja2",
        {
            "request": request,
            "token": token,
            "decoded": decoded,
            "datetime": datetime,
            "kid": kid,
            "human_provider": human_provider,
        },
    )


@app.get("/rsa.pub")
async def get_public_key() -> Response:
    """Returns the public key used to sign the tokens in PEM format."""
    return Response(
        public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.PKCS1
        ).decode("utf-8")
    )


def create_token(identity: str, challenge: str, provider: str) -> str:
    """Create a signed token with the given identity and challenge."""
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
