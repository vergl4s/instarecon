InstaRecon
=======

Automated basic digital reconnaissance. Great for getting an initial footprint of your targets.

* Direct and reverse DNS lookups
* Domain and IP Whois lookups
* Google dorks to get subdomains that relate to a target
* Shodan lookups
* Reverse DNS lookups on CIDRs related to targets

InstaRecon will never scan a target directly. Information is retrieved from DNS/Whois servers, Google, and Shodan.

###Installing on Kali Linux
Simply install dependencies using pip.

```bash
pip install -r requirements.txt
```
or
```bash
pip install pythonwhois ipwhois ipaddress shodan
```

###Example
```bash
ipscraper google.com 
ipscraper 8.8.8.8
```

