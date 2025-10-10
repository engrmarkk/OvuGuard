import logging
from environmentals import FILE_NAME

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    filename=FILE_NAME,
    # filename='/app/logs/app.log',
    filemode="a",
    datefmt="%d-%b-%y %H:%M:%S",
)

logger = logging.getLogger(__name__)
