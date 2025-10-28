# from sqlalchemy import create_engine
# from sqlalchemy.ext.declarative import declarative_base
# from sqlalchemy.orm import sessionmaker
# from environmentals import SQLALCHEMY_DATABASE_URI

# the below is the connection to the database, the connect_args is used to avoid error
# engine = create_engine(
#     SQLALCHEMY_DATABASE_URI,
#     pool_pre_ping=True,
    # pool_recycle=300,
    # pool_timeout=30,
    # max_overflow=10,
    # pool_size=5,
    # echo_pool=True,
    # connect_args={
    #     "keepalives": 1,
    #     "keepalives_idle": 30,
    #     "keepalives_interval": 10,
    #     "keepalives_count": 5,
    #     "connect_timeout": 30,
    # },
# )

# Db_Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
#
# Base = declarative_base()


# The function below is used to get a database session
# def get_db():
#     db = Db_Session()
#     try:
#         yield db
#     finally:
#         db.close()


# to upgrade the database
# alembic upgrade head


from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from environmentals import SQLALCHEMY_DATABASE_URI
from tenacity import retry, wait_fixed, stop_after_attempt, before_log
from logger import logger
import time
import logging


# --- STEP 1: Create engine with retry ---
@retry(
    stop=stop_after_attempt(5),        # retry 5 times
    wait=wait_fixed(3),                # wait 3 seconds each
    before=before_log(logger, logging.INFO)
)
def create_engine_with_retry():
    return create_engine(
        SQLALCHEMY_DATABASE_URI,
        pool_pre_ping=True,            # checks connection before using
        pool_recycle=1800,             # recycle every 30 minutes
        connect_args={
            "keepalives": 1,
            "keepalives_idle": 30,
            "keepalives_interval": 10,
            "keepalives_count": 5,
            "connect_timeout": 30,
        },
    )

engine = create_engine_with_retry()
Db_Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

# --- STEP 2: Create resilient DB session ---
def get_db():
    db = None
    for attempt in range(3):  # retry session if SSL connection drops
        try:
            db = Db_Session()
            yield db
            break
        except Exception as e:
            logger.warning(f"DB session error ({e}), retrying in 2s...")
            time.sleep(2)
        finally:
            if db:
                db.close()
