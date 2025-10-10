from cruds import get_user_id_from_request
from slowapi import Limiter
from environmentals import REDIS_URL

limiter = Limiter(
    key_func=get_user_id_from_request,
    storage_uri=REDIS_URL,
)
