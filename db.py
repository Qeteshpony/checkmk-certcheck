import sqlite3
import logging
from pathlib import Path

# Use config.py if it exists, else use config_default.py
try:
    from config import config
except ImportError:
    from config_default import config

logger = logging.getLogger(__name__)

scriptpath = Path(__file__).readlink().parent if Path(__file__).is_symlink() else Path(__file__).parent
dbfile = scriptpath / config.get("DATABASEFILE", "certs.sqlite")
logger.debug(f"DB-File: {dbfile}")

db_init = not dbfile.is_file()  # check if the db needs initialization
db = sqlite3.connect(dbfile)
db.row_factory = sqlite3.Row
db.execute("PRAGMA journal_mode=WAL")

if db_init:
    logger.debug(f"DB file does not exist at {dbfile}. Initializing...")
    with open("certs_structure.sql") as f:
        db.executescript(f.read())
    db.commit()
