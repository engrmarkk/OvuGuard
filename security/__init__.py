from jose import JWTError, jwt
from environmentals import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES
from datetime import datetime, timedelta
from fastapi import status, Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from database import get_db
from models import Users

auth_scheme = HTTPBearer(scheme_name="Bearer", auto_error=False)


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(token: str, credentials_exception):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        if not isinstance(user_id, str):
            raise credentials_exception
        return user_id
    except JWTError:
        raise credentials_exception


def get_current_user(
    request: Request,
    token: HTTPAuthorizationCredentials = Depends(auth_scheme),
    db: Session = Depends(get_db),
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if token is None:
        raise credentials_exception

    # Extract user_id from the token string
    user_id: str = verify_token(token.credentials, credentials_exception)

    # Query the database for the full user object
    user = db.query(Users).filter(Users.id == user_id).first()
    if not user:
        raise credentials_exception

    request.state.user_id = user_id
    return user
