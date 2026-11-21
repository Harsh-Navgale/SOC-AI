import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Literal, Optional

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, field_validator

from app.config import ADMIN_USERNAME, ADMIN_PASSWORD, JWT_SECRET
from app.db import users

logger = logging.getLogger("soc.auth")

JWT_ALGORITHM = "HS256"
TOKEN_TTL_SECONDS = 12 * 60 * 60  # 12 hours

bearer_scheme = HTTPBearer(auto_error=False)


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = TOKEN_TTL_SECONDS
    role: str


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: Literal["admin", "analyst"] = "analyst"

    @field_validator("username")
    @classmethod
    def username_must_be_non_blank(cls, value: str) -> str:
        # username becomes the user document's _id verbatim — a blank or whitespace-only value
        # is a valid Mongo _id, so nothing downstream would ever reject it on its own, and it
        # produces an account that's real (findable, loggable-into) but invisible in any UI that
        # displays the username as a label.
        stripped = value.strip()
        if not stripped:
            raise ValueError("username must not be blank")
        return stripped


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), password_hash.encode())


async def authenticate(username: str, password: str) -> Optional[dict]:
    user = await users.find_one({"_id": username})
    if not user or not verify_password(password, user["password_hash"]):
        return None
    return user


def create_token(username: str, role: str) -> str:
    now = int(time.time())
    payload = {
        "sub": username, "role": role, "iat": now, "exp": now + TOKEN_TTL_SECONDS,
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


# In-memory revocation list, keyed by jti -> exp. Same reasoning as rate_limit.py's buckets:
# this is a single-worker deployment with no shared cache, so a module-level dict is the right
# amount of infrastructure. Entries are pruned in revoke_token() (called rarely, on logout) —
# not in decode_token()'s hot path — since a stale entry is harmless: an expired token already
# fails jwt.decode()'s own exp check before the revocation lookup is ever reached.
_revoked_jtis: dict[str, int] = {}


def revoke_token(token: str) -> None:
    now = int(time.time())
    expired = [jti for jti, exp in _revoked_jtis.items() if exp < now]
    for jti in expired:
        del _revoked_jtis[jti]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError:
        return  # already invalid/expired — nothing to revoke
    _revoked_jtis[payload["jti"]] = payload["exp"]


def decode_token(token: str) -> dict:
    """Shared by the bearer-header auth path (require_auth) and the WebSocket auth path, which
    can't send an Authorization header and instead passes the token as a query param."""
    payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    if payload.get("jti") in _revoked_jtis:
        raise jwt.InvalidTokenError("Token has been revoked")
    return {"username": payload["sub"], "role": payload.get("role", "analyst")}


def require_auth(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> dict:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        return decode_token(credentials.credentials)
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def require_admin(user: dict = Depends(require_auth)) -> dict:
    if user["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    return user


async def bootstrap_admin():
    existing = await users.count_documents({})
    if existing == 0:
        await users.insert_one({
            "_id": ADMIN_USERNAME,
            "password_hash": hash_password(ADMIN_PASSWORD),
            "role": "admin",
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
        logger.info("Bootstrapped initial admin user '%s'", ADMIN_USERNAME)
