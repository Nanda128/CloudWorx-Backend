import json  # noqa: INP001
from typing import Any


def encode_message(message: dict[str, Any]) -> bytes:
    """Encode a message dictionary to bytes"""
    return json.dumps(message).encode("utf-8") + b"\n"


def decode_message(data: bytes) -> dict[str, Any]:
    """Decode bytes to a message dictionary"""
    return json.loads(data.decode("utf-8").strip())
