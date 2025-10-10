from database import Base
from sqlalchemy import Column, DateTime, String
from datetime import datetime
from helpers import generate_uuid


class UUIDPrimaryKeyMixin:
    id = Column(String(50), primary_key=True, default=generate_uuid)


# created at and updated at similarities
class TimestampMixin:
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
