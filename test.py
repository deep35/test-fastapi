from fastapi import FastAPI, HTTPException, Security, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
import hashlib
import time
from functools import wraps
from typing import Any, Callable
from fastapi.middleware.cors import CORSMiddleware
import logging

logger = logging.getLogger(__name__)
app = FastAPI()

# JWT Secret & Algorithm
JWT_SECRET = "f155de6fdee099a98ca63d9d5a7930254f1f3319a8959e5c97aab6620d4d815d"
JWT_ALGORITHM = "HS256"

# Security Dependency
security = HTTPBearer()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change this to specific origin in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def rate_limit(max_calls: int, period: int):
    """
    Rate limiting decorator that allows up to `max_calls` requests in a `period` seconds window.
    After exceeding, the user must wait for the full `period` to reset the count.
    """
    usage: dict[str, list[float]] = {}

    def decorator(func: Callable[[Request], Any]) -> Callable[[Request], Any]:
        @wraps(func)
        async def wrapper(request: Request, *args, **kwargs) -> Any:
            if not request.client:
                raise ValueError("Request has no client information")

            ip_address: str = request.client.host
            logger.info(f"IP from api call : {ip_address}")
            unique_id: str = hashlib.sha256(ip_address.encode()).hexdigest()

            now = time.time()
            timestamps = usage.get(unique_id, [])

            # Remove timestamps older than the period
            timestamps = [t for t in timestamps if now - t < period]
            usage[unique_id] = timestamps  # Update tracking dictionary

            if len(timestamps) < max_calls:
                timestamps.append(now)
                return await func(request, *args, **kwargs)

            # If max_calls is exceeded, check if full period has passed since first request
            first_request_time = timestamps[0]
            if now - first_request_time >= period:
                # Reset and allow request
                usage[unique_id] = [now]
                return await func(request, *args, **kwargs)

            # Calculate remaining wait time
            wait_time = period - (now - first_request_time)
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded. Retry after {wait_time:.2f} seconds",
            )

        return wrapper
    return decorator

# Verify JWT Token
def verify_jwt(credentials: HTTPAuthorizationCredentials = Security(security)):
    token = credentials.credentials  # Extract token correctly
    try:
        jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return True  # Valid token
    except ExpiredSignatureError:
        raise HTTPException(status_code=403, detail="Token expired")
    except InvalidTokenError:
        raise HTTPException(status_code=403, detail="Invalid token")

# 🚀 Secure the `/sheet_warning/` Route
@app.post("/sheet_warning/")
@rate_limit(max_calls=5, period=60)  # 5 calls allowed per 60 seconds
async def sheet_warning(request: Request, valid: bool = Depends(verify_jwt)):
    return {"message": "Valid user"}  # ✅ If JWT is valid
