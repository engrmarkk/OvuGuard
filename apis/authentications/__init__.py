from fastapi import APIRouter, status, Depends, HTTPException
from sqlalchemy.orm import Session
from helpers.res_ponse import return_response
import schemas.users as user_schema
from security import get_db, create_access_token
from helpers import verify_password
from cruds import email_exists, create_user, phone_number_exist
from logger import logger
from helpers import validate_correct_email, validate_phone_number

auth_router = APIRouter(prefix="/auth", tags=["Authentications"])


# login
@auth_router.post("/login", status_code=status.HTTP_200_OK)
async def login(request_data: user_schema.LogIn, db: Session = Depends(get_db)):
    is_valid, normalized_email = await validate_correct_email(request_data.email)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=normalized_email
        )
    user = await email_exists(db, normalized_email)
    if not user or not verify_password(request_data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid credentials"
        )
    return return_response(
        "Login successful", {"token": create_access_token({"sub": user.id})}
    )


# register
@auth_router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(request_data: user_schema.SignUp, db: Session = Depends(get_db)):
    if request_data.registration_type not in ["individual", "company"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid Registration Type"
        )
    is_valid, normalized_email = await validate_correct_email(request_data.email)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=normalized_email
        )
    phone_number_error = validate_phone_number(request_data.phone)
    if phone_number_error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=phone_number_error
        )
    user = await email_exists(db, normalized_email)
    if user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Email already exists"
        )
    if request_data.phone:
        if await phone_number_exist(db, request_data.phone):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Phone number already exists",
            )
    user = await create_user(
        db,
        normalized_email,
        request_data.password,
        request_data.full_name,
        request_data.company,
        request_data.country,
        request_data.phone,
        request_data.registration_type,
        request_data.company_size,
        request_data.industry,
    )
    return return_response(
        "User created successfully", {"token": create_access_token({"sub": user.id})}
    )
