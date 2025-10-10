import uuid
from passlib.hash import pbkdf2_sha256 as hasher
import re
import random
import secrets
import string
from datetime import datetime
from email_validator import validate_email, EmailNotValidError
import json
from connections.redis_connection import redis_conn
from logger import logger


def format_datetime(date_time):
    return date_time.strftime("%d-%b-%Y")


# generate token
def generate_token():
    return str(random.randint(1000, 9999))


def generate_uuid():
    return str(uuid.uuid4().hex)


def hash_password(password):
    return hasher.hash(password)


def verify_password(password, hashed_password):
    return hasher.verify(password, hashed_password)


async def validate_correct_email(email):
    try:
        validated_email = validate_email(email)
        normalized_email = validated_email.email
        return True, normalized_email
    except EmailNotValidError as e:
        return False, str(e)


async def redis_save_or_get(key, value, expire=None, dump_json=True):
    try:
        await redis_conn.init_connection()
        result = await redis_conn.get(key)

        if result:
            return json.loads(result) if dump_json else result

        value_to_save = json.dumps(value) if dump_json else value
        await redis_conn.set(key, value_to_save, expire)
        return value

    except Exception as e:
        logger.exception(f"Redis save or get failed: {e}")
        raise


# validate phone number
def validate_phone_number(phone_number):
    if not phone_number.isnumeric():
        return "Invalid phone number"
    if len(phone_number) != 11:
        return "Invalid phone number"
    return None
