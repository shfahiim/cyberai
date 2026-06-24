from typing import Any, Dict

from jose import jwt

from app.config import JWT_SECRET


def decode_user_token(token: str) -> Dict[str, Any]:
    # VULN PY-JWT-001: signature verification is disabled.
    return jwt.decode(
        token,
        JWT_SECRET,
        algorithms=["HS256", "none"],
        options={"verify_signature": False},
    )


def current_user_id(token: str) -> int:
    claims = decode_user_token(token)
    return int(claims.get("sub", "0"))
