# What is this?

This script uses the certificate transparency log database under https://crt.sh/ to get the list 
of all certificates under a certain domain and provides either a human-readable output or a single-line
output for checkmk. 

# How to use

Just copy the script to your machine, e.g. by cloning this git to `/opt` make sure the requirements are met and 
make certcheck.py executable by calling `chmod +x certcheck.py`. 

### Manual check
Call the script directly with `./certcheck.py <domain>` to get an overview of all certificates under that domain

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

### Caching

The script uses two levels of caching: 

First the http requests to crt.sh are cached to keep the amount of requests sento crt.sh low. 
This is achieved by using the requests-cache module with fine tuned settings:

- Cache every response for one hour
- Use stale values for another hour while trying to update the cache in the background in 
  case of slow or failed responses
- Use the old cache for another 12 hours if crt.sh does not respond

The http cache is by default stored in `/run` since there is no need to keep it permanently 
but you can change that in the config.

The second level cache is done by storing the information about all certificates in a local sqlite database. 
This makes sure that even if crt.sh returns incomplete data (which seems to happen quite often) there won't be a false
alarm in checkmk. 

At the same time this allows us to only request the currently active certificates from crt.sh since the expired ones 
are still on our local database. This improves the response time of crt.sh a lot, especially for domains with a long 
history of certificates and many subdomains. 

Since the script starts the database updates in the background every time it gets invoked, 
the first request for a domain will always return empty values. **This is normal and expected**! 
Once the cache is populated you get correct results. 

In case the script does not seem to work at all, check if you get a response when opening 
[crt.sh/json?identity=*yourdomain*&exclude=expired](https://crt.sh/json?identity=example.com&exclude=expired) 
in your browser

You can also call the update script directly with `python3 crtsh.py <domain> -d` for a debugging output