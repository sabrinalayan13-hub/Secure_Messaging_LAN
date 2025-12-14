import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import jwt, JWTError
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from database import SessionLocal
from model import User

# =========================
# Config (DO NOT HARDCODE)
# =========================
SECRET_KEY = os.getenv("JWT_SECRET")
if not SECRET_KEY or len(SECRET_KEY) < 32:
    raise RuntimeError("JWT_SECRET must be set and at least 32 characters long.")

ALGORITHM = "HS256"  # Consider RS256 later if you want key rotation with public/private keys
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

JWT_ISSUER = os.getenv("JWT_ISSUER", "secure-messaging-lan")
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "secure-messaging-lan-client")

# Standard OAuth2 Bearer token dependency
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12,      # adjust after measuring (12–14 typical)
    bcrypt__ident="2b",
)

# Dummy hash to mitigate user-enumeration timing differences
_DUMMY_HASH = pwd_context.hash("not-the-password")

def utcnow() -> datetime:
    return datetime.now(timezone.utc)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# =========================
# Password hashing
# =========================
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def verify_and_update_password(db: Session, user: User, plain_password: str) -> bool:
    """
    Verify password and upgrade hash if current policy is stronger.
    """
    if not pwd_context.verify(plain_password, user.hashed_password):
        return False

    if pwd_context.needs_update(user.hashed_password):
        user.hashed_password = pwd_context.hash(plain_password)
        db.add(user)
        db.commit()
    return True

def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
    """
    Returns User on success; None on failure.
    Uses dummy hash to reduce username-existence timing leaks.
    """
    user = db.query(User).filter(User.username == username).first()
    if not user:
        pwd_context.verify(password, _DUMMY_HASH)  # burn roughly equal time
        return None

    return user if verify_and_update_password(db, user, password) else None

# =========================
# JWT creation / validation
# =========================
def create_access_token(subject: str, expires_delta: Optional[timedelta] = None) -> str:
    now = utcnow()
    expire = now + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))

    claims = {
        "sub": subject,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "jti": secrets.token_urlsafe(16),  # unique token id (useful if you later add revocation)
        "typ": "access",
    }
    return jwt.encode(claims, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
            options={
                "require_sub": True,
                "require_iat": True,
                "require_nbf": True,
                "require_exp": True,
            },
        )
        username = payload.get("sub")
        if not username:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.username == username).first()
    if not user:
        # Token may be valid but user no longer exists
        raise credentials_exception

    return user
