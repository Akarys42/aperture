import hashlib
from typing import TypeVar, Iterable, Optional
import re
import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

T = TypeVar("T")


def filter_none(i: Iterable[Optional[T]]) -> Iterable[T]:
    return filter(lambda x: x is not None, i)


def calculate_key_fingerprint(key: RSAPublicKey) -> str:
    openssh_content = key.public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    ).decode("utf-8")

    content = re.match("ssh-rsa ([A-Za-z0-9+/=]+)", openssh_content).group(1)
    decoded = base64.b64decode(content)
    digest = hashlib.md5(decoded).hexdigest()

    chunks = [digest[i : i + 2] for i in range(0, len(digest), 2)]
    return "MD5:" + ":".join(chunks)
