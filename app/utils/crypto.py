from __future__ import annotations

import base64
import re


def format_public_key_to_pem(public_key_data: str | bytes) -> str:
    """Format a public key to proper PEM format.

    Args:
        public_key_data: Raw public key data as string or bytes

    Returns:
        Properly formatted PEM string

    Raises:
        ValueError: If the input data is invalid

    """
    try:
        public_key_bytes = public_key_data.encode("utf-8") if isinstance(public_key_data, str) else public_key_data

        clean_data = base64.encodebytes(public_key_bytes)

        clean_data = re.sub(rb"[\s\n\r\t\x0b\x0c]", b"", clean_data)

        pem_lines = [clean_data[i : i + 64] for i in range(0, len(clean_data), 64)]

        pem_content = b"\n".join(pem_lines)
        pem_formatted = b"-----BEGIN PUBLIC KEY-----\n" + pem_content + b"\n-----END PUBLIC KEY-----\n"

        return pem_formatted.decode("utf-8")

    except Exception as e:
        msg = f"Failed to format public key to PEM: {e}"
        raise ValueError(msg) from e
