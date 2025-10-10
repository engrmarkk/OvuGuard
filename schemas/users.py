from pydantic import BaseModel, EmailStr, model_serializer
from datetime import datetime
from typing import Dict, Any, List, Optional, TypeVar, Generic, Union

T = TypeVar("T")


class ShowUserSchema(BaseModel):
    email: Optional[EmailStr]


class Tenant(BaseModel):
    id: str
    name: str


class UserResponse(BaseModel):
    id: str
    full_name: str
    email: EmailStr
    country: str
    phone: str
    company: str


class User(BaseModel):
    id: str


class Event(BaseModel):
    tenant_id: str
    event_id: str
    timestamp: datetime
    source_type: str
    account_id: str
    amount: float
    currency: str = "NGN"
    device_id: Optional[str] = None
    ip: Optional[str] = None
    geo: Optional[Dict[str, float]] = None
    user_agent: Optional[str] = None
    merchant_id: Optional[str] = None
    raw_payload: Optional[Dict[str, Any]] = None


class Score(BaseModel):
    score: float
    action: str
    reason: str
    meta: Optional[Dict[str, Any]] = None


class Alert(BaseModel):
    id: str
    event_id: str
    score: Score
    timestamp: datetime


class PluginInput(BaseModel):
    wasm_binary: bytes
    name: str


class PluginOutput(BaseModel):
    action: str
    score: float
    reason: str


class Consent(BaseModel):
    tenant_id: str
    scope: str
    authorized: bool
    signature: str


class SignUp(BaseModel):
    full_name: str
    email: EmailStr
    password: str
    country: str
    phone: str
    company: str


class LogIn(BaseModel):
    email: EmailStr
    password: str


class Invite(BaseModel):
    email: EmailStr
    role: str = "member"


class AnalyticsResponse(BaseModel):
    total_txns: int
    blocked: int
    alerted: int
    avg_score: float
    trends: List[Dict[str, Any]]


# APIRESPONSE


class Pagination(BaseModel):
    total_items: int
    page: int
    per_page: int
    total_pages: int


class APIResponse(BaseModel, Generic[T]):
    msg: str
    data: Union[T, List[T]]
    pagination: Optional[Pagination] = None

    @model_serializer
    def serialize_model(self):
        data = self.__dict__.copy()
        if not self.pagination:
            data.pop("pagination", None)
        return data
