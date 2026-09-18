from typing import Annotated

import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jwt.exceptions import InvalidTokenError

from app.core.security import (
    ALGORITHM,
    SECRET_KEY,
    create_access_token,
    hash_password,
    verify_password,
)


app = FastAPI()


oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token"
)


fake_user = {
    "id": 1,
    "username": "jay",
    "password_hash": hash_password("secret123"),
}

@app.post("/token")
async def login(
    username: str,
    password: str,
):
    if username != fake_user["username"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    if not verify_password(
        password,
        fake_user["password_hash"]
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    access_token = create_access_token(
        fake_user["id"]
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
    }

def decode_access_token(token: str) -> int:
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )

        user_id = payload.get("sub")

        if user_id is None:
            raise ValueError("Missing subject")

        return int(user_id)

    except (InvalidTokenError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={
                "WWW-Authenticate": "Bearer"
            },
        )

async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)]
):
    user_id = decode_access_token(token)

    if user_id != fake_user["id"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    return fake_user

@app.get("/users/me")
async def get_me(
    current_user=Depends(get_current_user)
):
    return {
        "id": current_user["id"],
        "username": current_user["username"],
    }