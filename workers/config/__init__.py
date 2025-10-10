from celery import Celery, shared_task
import os
from datetime import datetime
import workers.schedule as celeryConfig
from dotenv import load_dotenv
from logger import logger
from environmentals import REDIS_URL

load_dotenv()


def make_celery():
    celery = Celery(
        "workers",
        backend=REDIS_URL,
        broker=REDIS_URL,
    )
    celery.conf.update(vars(celeryConfig))

    return celery


celery = make_celery()


@shared_task
def add_numbers(x, y):
    logger.info("Adding")
    return x + y
