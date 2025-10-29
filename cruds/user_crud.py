from models import Users
from helpers import hash_password
from datetime import datetime, timedelta
from fastapi import Request, HTTPException
from logger import logger
from sqlalchemy import func, desc


async def email_exists(db, email: str):
    return db.query(Users).filter(Users.email.ilike(email)).first()


def get_user_id_from_request(request: Request):
    user_id = request.state.user_id
    logger.info(f"user_id: {user_id}")
    if not user_id:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return user_id


# create User
async def create_user(
    db,
    email,
    password,
    full_name,
    company,
    country,
    phone,
    registration_type,
    company_size,
    industry,
):
    user = Users(
        email=email,
        password=hash_password(password),
        full_name=full_name,
        company=company,
        country=country,
        phone=phone,
        registration_type=registration_type,
        company_size=company_size,
        industry=industry,
    )
    db.add(user)
    db.commit()
    return user


# get user by user id
async def get_user_by_id(db, user_id: str):
    return db.query(Users).filter(Users.id == user_id).first()
