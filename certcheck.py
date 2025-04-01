#!/usr/bin/env python3
import os
import logging
from os import path
from sys import argv, stderr
from requests_cache import CachedSession, SQLiteCache
from colorama import Fore, Style
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)s:%(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p')
certdomains = []
cachepath = "."
readable = False
filterdays = 7

if len(argv) > 1:
    readable = True
    certdomains = argv[1:]
elif path.islink(__file__):
    certdomains = [path.basename(__file__)]
    cachepath = path.dirname(os.readlink(__file__))
else:
    print("No domains specified", file=stderr)
    exit(1)
if cachepath == "":
    cachepath = "."
backend = SQLiteCache(cachepath+"/http_cache.sqlite")
session = CachedSession(backend=backend)
session.settings.expire_after = 3600


def parsedata(data: dict) -> dict:
    certs = {}
    for cert in data:
        # convert timestamps into datetime objects
        cert["not_before"] = datetime.strptime(cert["not_before"], "%Y-%m-%dT%H:%M:%S")
        cert["not_after"] = datetime.strptime(cert["not_after"], "%Y-%m-%dT%H:%M:%S")
        # create list of last certs and filter out old ones
        cert_name = str(cert["name_value"]).replace("\n", ", ")
        not_after = cert["not_after"]
        if ((cert_name not in certs.keys() or  # if cert is not in the list
             not_after > certs.get(cert_name).get("not_after")) and  # or newer
                not_after > datetime.now() - timedelta(days=filterdays)):  # unless it is older than 30 days
            certs[cert_name] = cert  # then add or overwrite it
    return certs

def readable_output(certs: dict) -> None:
    for name, cert in certs.items():
        if cert['not_after'] > datetime.now() + timedelta(days=7):
            color = Fore.GREEN
        elif cert['not_after'] > datetime.now() + timedelta(days=1):
            color = Fore.YELLOW
        else:
            color = Fore.RED
        print(f"{name}: {color}{cert.get('not_after')}{Style.RESET_ALL}")

def checkmk(certs: dict, domainname) -> None:
    status = 0
    output = ""
    certsok = 0
    certswarn = 0
    certscrit = 0
    for name, cert in sorted(certs.items()):
        if cert['not_after'] > datetime.now() + timedelta(days=7):
            certsok += 1
            output += f"{name}: {cert['not_after']} (OK)\\n"
        elif cert['not_after'] > datetime.now() + timedelta(days=1):
            certswarn += 1
            output += f"{name}: {cert['not_after']} (WARN)\\n"
        else:
            certscrit += 1
            output += f"{name}: {cert['not_after']} (CRIT)\\n"
    if certswarn > 0:
        status = 1
    if certscrit > 0:
        status = 2
    metric = f"OK={certsok}|WARN={certswarn}|CRIT={certscrit}"
    output += f"Showing only certificates that are less than {filterdays} days overdue."
    print(f'{status} "Certificate Validity {domainname}" {metric} {output}')

for domain in certdomains:
    response = session.get(f"https://crt.sh/json?identity={domain}", timeout=30)
    if response.status_code == 200:
        res = response.json()
        parsed = parsedata(res)
        if readable:
            readable_output(parsed)
        else:
            checkmk(parsed, domain)
    else:
        logging.error(f"Cert-data for {domain} can't be loaded. Status: {response.status_code}: {response.text}")
        exit(1)




