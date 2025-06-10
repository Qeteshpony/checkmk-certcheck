#!/usr/bin/env python3
import logging
from os import path, readlink
from sys import argv, stderr
from requests_cache import CachedSession, SQLiteCache
from colorama import Fore, Style
from datetime import datetime, timedelta

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

cachepath = config.get("CACHEPATH", "/run")
filterdays = config.get("FILTERDAYS", 7)
excludefile = config.get("EXCLUDEFILE", "excludecert.txt")
certdomains = []
readable = False

if len(argv) > 1:  # we got command line options - use those
    readable = True  # in this case we want human readable output
    certdomains = argv[1:]
elif path.islink(__file__):  # no command line options but we're linked from somewhere so we assume its checkmk time
    certdomains = path.basename(__file__).split(",")  # get filename to determain the domains

    if cachepath == ".":  # only if the cache path is set to "." we want it to be the directory of the script
        cachepath = path.dirname(readlink(__file__))  # get path of the original file for cache location
else:  # can't do anything without knowing what domain to check
    print("No domains specified", file=stderr)
    exit(1)

if cachepath == "":  # workaround for when the link is the same directory as the script
    cachepath = "."

# Session Settings
backend = SQLiteCache(cachepath+"/http_cache.sqlite")
session = CachedSession(
    backend=backend,
    expire_after=3600,  # it should be enough to refresh data once an hour
    stale_if_error=3600*12,  # if the server does return an error, use cached data for max 12 hours
    stale_while_revalidate=600,  # use old values while getting a new response to speed things up
)

def parsedata(data: dict, excludes: list) -> dict:
    """
    Let's go through the data we got and parse it
    :param excludes: excluded domains
    :param data: dictionary of all certificates for the speicied domain
    :return: dictionary of all current certificates for the specified domain
    """
    certs = {}
    for cert in data:
        # convert timestamps into datetime objects
        cert["not_before"] = datetime.strptime(cert["not_before"], "%Y-%m-%dT%H:%M:%S")
        cert["not_after"] = datetime.strptime(cert["not_after"], "%Y-%m-%dT%H:%M:%S")
        # create list of last certs and filter out old ones
        cert_name = str(cert["name_value"]).replace("\n", ", ")  # the certs are listed with \n's
        not_after = cert["not_after"]
        if ((cert_name not in certs.keys() or  # if cert is not in the list
                not_after > certs.get(cert_name).get("not_after")) and  # or newer
                not_after > datetime.now() - timedelta(days=filterdays) and  # unless it is too old
                cert_name not in excludes):  # or excluded manually
            certs[cert_name] = cert  # then add or overwrite it
    logging.debug(f"{len(certs)} certificate(s) left after filtering")
    return certs

def readable_output(certs: dict) -> None:
    """
    Create a nice list of the parsed certificates and print it
    :param certs: parsed certificates
    """
    for name, cert in sorted(certs.items()):
        if cert['not_after'] > datetime.now() + timedelta(days=7):  # cert is still valid for more than 7 days
            color = Fore.GREEN
        elif cert['not_after'] > datetime.now() + timedelta(days=1):  # cert is still valid for more than a day
            color = Fore.YELLOW
        else:  # cert is about to become invalid or already is
            color = Fore.RED
        print(f"{name}: {color}{cert.get('not_after')}{Style.RESET_ALL}")

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
        if cert['not_after'] > datetime.now() + timedelta(days=7):  # cert is still valid for more than 7 days
            output_ok.append(f"{name}: {cert['not_after']} (OK)")
        elif cert['not_after'] > datetime.now() + timedelta(days=1):  # cert is still valid for more than a day
            output_warn.append(f"{name}: {cert['not_after']} (WARN)")
        else:  # cert is about to become invalid or already is
            output_crit.append(f"{name}: {cert['not_after']} (CRIT)")

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
    excludefilepath = path.dirname(__file__)+"/"+excludefile
    if path.isfile(excludefilepath):  # check if the excludes file exists
        logging.debug(f"Reading excluded certnames from {excludefilepath}")
        with open(excludefilepath) as f:
            for certname in f.read().splitlines():  # read all lines and iterate over them
                certname = certname.strip()  # remove whitespace
                if not certname.startswith("#") and certname:  # filter comments and empty lines
                    logging.debug(f"Adding certname {certname} to excludes list")
                    certnames.append(certname)
    return certnames

def main() -> None:
    """
    Run this when the script was invoked on the command line
    """
    parsed = {}
    excludes = readexcludes()
    for domain in certdomains:   # go through all domains in the list
        logging.debug(f"Getting data for {domain}")
        # get data from crt.sh
        response = session.get(f"https://crt.sh/json?identity={domain}", timeout=config["TIMEOUT"])
        if response.status_code == 200:  # check response code - we only go on when it was 200
            res = response.json()  # turn the response into a dictionary
            logging.debug(f"Got data for {len(res)} certificates")
            parsed.update(parsedata(res, excludes))  # parse the data
        else:  # any other status code is a problem
            logging.error(f"Cert-data for {domain} can't be loaded. Status: {response.status_code}: {response.text}")
            exit(1)
    if readable:  # create human readable output
        readable_output(parsed)
    else:  # create output for checkmk
        checkmk(parsed, certdomains)


if __name__ == "__main__":
    main()
