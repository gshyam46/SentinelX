"""
SentinelX — API Dependencies
Shared FastAPI dependencies: auth, database, tier gating, rate limiting, target validation.
"""

import ipaddress
import re
import uuid
from datetime import datetime, timedelta, timezone

import bcrypt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from jwt.exceptions import InvalidTokenError
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.config import get_settings
from backend.db.session import get_db
from backend.models.user import User

settings = get_settings()

# Bearer token scheme
security = HTTPBearer()

# Rate limiter — attached to app.state in main.py
limiter = Limiter(key_func=get_remote_address)

# ---------------------------------------------------------------------------
# Target validation
# ---------------------------------------------------------------------------

# Metadata endpoints that must never be scanned
_METADATA_HOSTS: frozenset[str] = frozenset({
    "metadata.internal",
    "metadata.google.internal",
    "169.254.169.254",      # IMDS (AWS/Azure/GCP)
    "100.100.100.200",      # Alibaba Cloud IMDS
})

_LOOPBACK_RE = re.compile(r"^(localhost|localhost\.localdomain)$", re.IGNORECASE)

# Simplified safe_repr for log lines — redacts values that follow sensitive key names
_SENSITIVE_PATTERN = re.compile(
    r"(?i)(\b(?:secret|password|token|api_?key|cookie|authorization)\b\s*[=:]\s*)['\"]?\S+['\"]?",
)


def safe_repr(obj: object) -> str:
    """Return repr(obj) with sensitive key=value pairs redacted."""
    return _SENSITIVE_PATTERN.sub(r"\1***", repr(obj))


def validate_scan_target(target: str) -> None:
    """
    Raise HTTP 422 if the scan target is a private, loopback, link-local,
    reserved, or cloud-metadata address.
    Called after Pydantic domain validation — target is already stripped of protocol/www.
    """
    host = target.lower().split(":")[0]   # strip optional port

    if _LOOPBACK_RE.match(host):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Scanning localhost is not permitted.",
        )

    if host in _METADATA_HOSTS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Scanning cloud metadata endpoints is not permitted.",
        )

    # If the domain string happens to be a bare IP (schema validator normally blocks this,
    # but defence-in-depth for future schema changes)
    try:
        addr = ipaddress.ip_address(host)
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
        ):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Scanning private, loopback, or reserved IP ranges is not permitted.",
            )
        if str(addr) in _METADATA_HOSTS:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Scanning cloud metadata endpoints is not permitted.",
            )
    except ValueError:
        pass  # Not a bare IP — hostname form, schema validation already enforced format


def hash_password(password: str) -> str:
    """Hash a password with bcrypt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against a bcrypt hash."""
    return bcrypt.checkpw(
        plain_password.encode("utf-8"),
        hashed_password.encode("utf-8"),
    )


def create_access_token(user_id: uuid.UUID, email: str) -> str:
    """Create a JWT access token."""
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.JWT_EXPIRE_MINUTES
    )
    payload = {
        "sub": str(user_id),
        "email": email,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Decode JWT and return the authenticated user."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            credentials.credentials,
            settings.SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except (InvalidTokenError, Exception):
        raise credentials_exception

    result = await db.execute(
        select(User).where(User.id == uuid.UUID(user_id))
    )
    user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        raise credentials_exception

    return user


async def require_paid_tier(
    request: Request,
    current_user: User = Depends(get_current_user),
) -> User:
    """Require the user to have a paid tier subscription and be active."""
    # Dev bypass — gated by env flag + secret header; never active in prod
    if (
        settings.DEV_BYPASS_TIER
        and settings.DEV_BYPASS_SECRET
        and request.headers.get("X-Dev-Bypass") == settings.DEV_BYPASS_SECRET
    ):
        return current_user

    # Defence-in-depth: get_current_user already checks is_active, but enforce again here
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated.",
        )

    if current_user.tier not in ("paid", "enterprise"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This feature requires a paid subscription. Upgrade to access active scanning, full reports, and AI-powered analysis.",
        )
    return current_user
