from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from environmentals import SQLALCHEMY_DATABASE_URI

# the below is the connection to the database, the connect_args is used to avoid error
engine = create_engine(
    SQLALCHEMY_DATABASE_URI,
    pool_pre_ping=True,
    pool_recycle=300,
    pool_timeout=30,
    max_overflow=10,
    pool_size=5,
    echo_pool=True,
    connect_args={
        "keepalives": 1,
        "keepalives_idle": 30,
        "keepalives_interval": 10,
        "keepalives_count": 5,
        "connect_timeout": 30,
    },
)

Db_Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)

Base = declarative_base()


# The function below is used to get a database session
def get_db():
    db = Db_Session()
    try:
        yield db
    finally:
        db.close()


# to upgrade the database
# alembic upgrade head
