import sqlite3
import logging
from pathlib import Path

# Use config.py if it exists, else use config_default.py
try:
    from config import config
except ImportError:
    from config_default import config

logger = logging.getLogger(__name__)

class DB:
    def __init__(self):
        scriptpath = Path(__file__).readlink().parent if Path(__file__).is_symlink() else Path(__file__).parent
        dbfilename = config.get("DATABASEFILE", "certs.sqlite")
        if dbfilename.startswith("/"):
            dbfile = Path(dbfilename)
        else:
            dbfile = scriptpath / dbfilename
        logger.debug(f"DB-File: {dbfile}")

        db_init_needed = not dbfile.is_file()  # check if the db needs initialization
        self.conn = sqlite3.connect(dbfile)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")

        if db_init_needed:
            logger.debug(f"DB file does not exist at {dbfile}. Initializing...")
            self._db_init()

    def _db_init(self):
        with open("certs_structure.sql") as f:
            self.conn.executescript(f.read())
        self.conn.commit()
