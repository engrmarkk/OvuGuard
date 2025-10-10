from database import Base
from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    ForeignKey,
    DateTime,
    Float,
    Text,
    Enum as SQLAlchemyEnum,
)

# from sqlalchemy.orm import relationship
# from helpers import generate_uuid, format_datetime
from datetime import datetime, timedelta
from enum import Enum
from models.model_similarities import TimestampMixin, UUIDPrimaryKeyMixin


# class Gender(Enum):
#     MALE = "male"
#     FEMALE = "female"


class Users(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "users"
    email = Column(String(50), unique=True)
    password = Column(Text)
    phone = Column(String(50), unique=True)
    full_name = Column(String(70))
    country = Column(String(70))
    company = Column(String(70))
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    webhook_url = Column(Text)
    api_limit = Column(Integer, default=100)
    trial_end_date = Column(DateTime)
    plan_type = Column(String(50), default="free_trial")
