from os import setsid
import subprocess
from requests_cache import CachedSession, SQLiteCache
from datetime import datetime
import time
import logging
from sys import argv
from db import DB
from pathlib import Path

# Use config.py if it exists, else use config_default.py
try:
    from config import config
except ImportError:
    from config_default import config

logger = logging.getLogger(__name__)

cachepath = Path(config.get("CACHEPATH", "/run"))


scriptpath = Path(__file__).readlink().parent if Path(__file__).is_symlink() else Path(__file__).parent

db = DB().conn

if cachepath == ".":
    cachepath = scriptpath

certdomains = []
readable = False

# Session Settings
backend = SQLiteCache(cachepath / "http_cache.sqlite")
session = CachedSession(
    backend=backend,
    expire_after=3600,  # it should be enough to refresh data once an hour
    stale_if_error=3600*12,  # if the server does return an error, use cached data for max 12 hours
    stale_while_revalidate=3600,  # use old values while getting a new response to speed things up
)


def iso_to_ts(iso_string: str) -> int:
    return int(datetime.strptime(iso_string, "%Y-%m-%dT%H:%M:%S").timestamp())


def parsedata(data: dict, domain: str) -> None:
    """
    Let's go through the data we got and parse it
    :param data: dictionary of all certificates for the specified domain
    :param domain: domain of the certificates
    """
    cur = db.cursor()
    cur.execute("BEGIN TRANSACTION")
    for entry in data:
        # store certs in database
        cert = {
            "serial": entry["serial_number"],
            "domain": domain,
            "name": str(entry["name_value"]).replace("\n", ", "),  # the certs are listed with \n's
            "notbefore": iso_to_ts(entry["not_before"]),
            "notafter": iso_to_ts(entry["not_after"]),
        }
        logger.debug(f"parsing: {cert}")
        cur.execute("SELECT name FROM certs WHERE serial = :serial AND domain = :domain", cert)
        rows = cur.fetchall()
        if not rows:
            logger.debug("INSERT")
            cur.execute("""
                        INSERT INTO certs (serial, domain, name, notbefore, notafter) 
                        VALUES (:serial, :domain, :name, :notbefore, :notafter)
                        """,
                        cert)
    cur.execute(f"INSERT OR REPLACE INTO lastupdates VALUES ('{domain}', {int(time.time())})")
    db.commit()
    cur.close()


def getdata(domains: list) -> None:
    for domain in domains:
        logger.debug(f"Getting data for {domain}")
        url = f"https://crt.sh/json?identity={domain}&exclude=expired"
        logger.debug(f"URL: {url}")
        response = session.get(url, timeout=config["TIMEOUT"])
        logger.debug(f"HTTP {response.status_code}: {response.text}")
        if response.status_code == 200:  # check response code - we only go on when it was 200
            res = response.json()  # turn the response into a dictionary
            logger.debug(f"Got data for {len(res)} certificates")
            parsedata(res, domain)  # parse the data
        else:  # any other status code is a problem
            logger.error(f"Cert-data for {domain} can't be loaded. Status: {response.status_code}: {response.text}")


def open_subprocess(domains: list) -> None:
    commandlist = ["/usr/bin/env", "python3", str(Path(__file__).absolute()), *domains]
    logger.debug(f"Opening subprocess with command: {' '.join(commandlist)}")
    subprocess.Popen(
        commandlist,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=setsid
    )


def main():
    while "-d" in argv:
        logger.info("Setting loglevel to debug...")
        logger.setLevel(logging.DEBUG)
        argv.remove("-d")

    logging.basicConfig()
    logger.debug(f"Cache path: {cachepath}")

    if len(argv) < 2:
        logger.error(f"Usage: {argv[0]} <domain> [<domain> ...]")
        exit(1)

    getdata(argv[1:])

    # finish and close db
    db.execute("PRAGMA wal_checkpoint(FULL)")
    db.close()

if __name__ == "__main__":
    main()
