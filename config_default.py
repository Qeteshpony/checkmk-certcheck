# create a copy of this file and name it config.py if you want to change settings

config = {
    "CACHEPATH": "/run",  # Location of cache file. Set to "." for script dir.
                          # Default: "/run" which is useful for checkmk
    "FILTERDAYS": 7,  # Filter out any certs older than x days. Default: 7
    "EXCLUDEFILE": "excludecerts.txt",  # file name for the excludes file
    "TIMEOUT": 30,  # timeout for crt.sh responses
    "DATABASEFILE": "certs.sqlite",  # database file
}
