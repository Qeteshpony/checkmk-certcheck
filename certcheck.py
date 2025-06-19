#!/usr/bin/env python3
import logging
import sqlite3
from pathlib import Path
from sys import argv, stderr
from colorama import Fore, Style
from datetime import datetime, timedelta
import crtsh

# Use config.py if it exists, else use config_default.py
try:
    from config import config
except ImportError:
    from config_default import config

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)s(%(name)s): %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

while "-d" in argv:
    logging.getLogger().setLevel(logging.DEBUG)
    argv.remove("-d")

filterdays = config.get("FILTERDAYS", 7)
excludefile = config.get("EXCLUDEFILE", "excludecert.txt")

scriptpath = Path(__file__).readlink().parent if Path(__file__).is_symlink() else Path(__file__).parent
dbfile = scriptpath / config.get("DATABASEFILE", "certs.sqlite")
logging.debug(f"dbfile: {dbfile}")
certdomains = []
readable = False

if len(argv) > 1:  # we got command line options - use those
    readable = True  # in this case we want human readable output
    certdomains = argv[1:]
elif Path(__file__).is_symlink():  # no command line options but linked from somewhere so we assume its checkmk time
    certdomains = Path(__file__).name.split(",")  # get filename to determain the domains
else:  # can't do anything without knowing what domain to check
    print("No domains specified", file=stderr)
    exit(1)

db_init = not dbfile.is_file()  # check if the db needs initialization
db = sqlite3.connect(dbfile)
db.row_factory = sqlite3.Row

if db_init:
    # init database
    with open(scriptpath / "certs_structure.sql") as f:
        db.executescript(f.read())
    db.commit()

def readable_output(certs: dict) -> None:
    """
    Create a nice list of the parsed certificates and print it
    :param certs: parsed certificates
    """
    for name, cert in sorted(certs.items()):
        notafter = datetime.fromtimestamp(cert['notafter'])
        if notafter > datetime.now() + timedelta(days=7):
            # cert is still valid for more than 7 days
            color = Fore.GREEN
        elif notafter > datetime.now() + timedelta(days=1):
            # cert is still valid for more than a day
            color = Fore.YELLOW
        else:
            # cert is about to become invalid or already is
            color = Fore.RED
        print(f"{name}: {color}{notafter}{Style.RESET_ALL}")

def checkmk(certs: dict, domainnames: list) -> None:
    """
    Create checkmk compatible output
    :param certs: dictionary of certificates
    :param domainnames: name of the parsed domain
    """
    status = 0
    output_ok = []
    output_warn = []
    output_crit = []
    for name, cert in sorted(certs.items()):  # go through the certs in alphabetical order
        notafter = datetime.fromtimestamp(cert['notafter'])
        if notafter > datetime.now() + timedelta(days=7):
            # cert is still valid for more than 7 days
            output_ok.append(f"{name}: {notafter} (OK)")
        elif notafter > datetime.now() + timedelta(days=1):
            # cert is still valid for more than a day
            output_warn.append(f"{name}: {notafter} (WARN)")
        else:
            # cert is about to become invalid or already is
            output_crit.append(f"{name}: {notafter} (CRIT)")

    # set status for checkmk
    if len(output_warn):
        status = 1
    if len(output_crit):
        status = 2

    print(f'{status} "Certificate Validity {", ".join(domainnames)}" ', end="")  # print the status and service name
    print(f"OK={len(output_ok)}|WARN={len(output_warn)}|CRIT={len(output_crit)} ", end="")  # print the metric
    for line in output_crit:  # print all the critical ones first
        print(line + "\\n", end="")
    for line in output_warn:  # the ones with warn level second
        print(line + "\\n", end="")
    for line in output_ok:  # and last the ok ones
        print(line + "\\n", end="")
    print(f"Showing only certificates that are less than {filterdays} days overdue.")  # info line

def readexcludes() -> list:
    certnames = []
    excludefilepath = Path(__file__).parent / excludefile
    if excludefilepath.is_file():  # check if the excludes file exists
        logging.debug(f"Reading excluded certnames from {excludefilepath}")
        with open(excludefilepath) as f:
            for certname in f.read().splitlines():  # read all lines and iterate over them
                certname = certname.strip()  # remove whitespace
                if not certname.startswith("#") and certname:  # filter comments and empty lines
                    logging.debug(f"Adding certname {certname} to excludes list")
                    certnames.append(certname)
    return certnames

def getcerts(domain: str, excludes: list) -> dict:
    cur = db.cursor()
    cur.execute("""
                    SELECT c.* FROM certs c
                    JOIN (
                        SELECT name, MAX(notafter) AS max_notafter
                        FROM certs
                        GROUP BY name
                    ) AS latest
                    ON c.name = latest.name AND c.notafter = latest.max_notafter
                    WHERE c.domain = ?
                """,
                (domain,))
    certs = {}
    for cert in cur.fetchall():
        if cert["name"] not in excludes:
            certs[cert["name"]] = dict(cert)
    return certs


def main() -> None:
    """
    Run this when the script was invoked on the command line
    """
    # call sub process to update the database in the background
    crtsh.open_subprocess(certdomains)

    certs = {}
    excludes = readexcludes()
    for domain in certdomains:   # go through all domains in the list
        logging.debug(f"Getting data for {domain}")
        certs.update(getcerts(domain, excludes))
    if readable:  # create human readable output
        readable_output(certs)
    else:  # create output for checkmk
        checkmk(certs, certdomains)


if __name__ == "__main__":
    main()
