from fastapi import APIRouter, status, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy.orm import Session
from helpers.res_ponse import return_response
import schemas.users as user_schema
from logger import logger
from database import get_db
from security import get_current_user
from models import Users

user_router = APIRouter(prefix="/user", tags=["Users"])


@user_router.get(
    "/me", response_model=user_schema.APIResponse[user_schema.UserResponse]
)
async def get_current_user(current_user: Users = Depends(get_current_user)):
    return user_schema.APIResponse(msg="User retrieved successfully", data=current_user)
