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

This will create one service per domain showing the state of all certificates under that domain, 
switching to WARN when any certificates are valid for less than a week and to critical if any are 
valid less than a day.