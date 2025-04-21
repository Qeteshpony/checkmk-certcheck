# What is this?

This script uses the certificate transparency log database under https://crt.sh/ to get the list 
of all certificates under a certain domain and provides either a human-readable output or a single-line
output for checkmk. 

# How to use

Just copy the script to your machine, make sure the requirements are met and it is executable. 

### Manual check
Call the script directly with `./certcheck <domain>` to get an overview of all certificates under that domain

### checkmk

Create symlinks to this script with just the domain name as the name in `/usr/lib/check_mk_agent/local`

You can join several domains together to have them checked as a single service:

```
cd /usr/lib/check_mk_agent/local
ln -s <script-path>/certcheck.py example.com,example.org
``` 

This will create one service per symlink, showing the state of all certificates under the listed domains, 
switching to WARN when any certificates are valid for less than a week and to critical if any are 
valid less than a day.

You can exclude single certificates from the check by creating a file named "certexclude.txt" in the same location
as the link and list all excluded certs, one per line.