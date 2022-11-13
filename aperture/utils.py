import base64
import hashlib
import re
from typing import Iterable, Optional, TypeVar

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

T = TypeVar("T")


def filter_none(i: Iterable[Optional[T]]) -> Iterable[T]:
    """Filter out None values from an iterable."""
    return filter(lambda x: x is not None, i)


def calculate_key_fingerprint(key: RSAPublicKey) -> str:
    """
    Calculate the fingerprint of a public key.

    The format is similar to what you'd expect from OpenSSH.
    """
    openssh_content = key.public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    ).decode("utf-8")

    content = re.match("ssh-rsa ([A-Za-z0-9+/=]+)", openssh_content).group(1)
    decoded = base64.b64decode(content)
    digest = hashlib.md5(decoded).hexdigest()

    chunks = [digest[i : i + 2] for i in range(0, len(digest), 2)]
    return "MD5:" + ":".join(chunks)
