IPscraper
=======

OSINT scraper that tries to gather information on IP addresses and domain names.


###Installing on Kali Linux
~~This is an ugly workaround, because, for some reason, Kali decided to stay on python3.2~~. Decided to ditch python 3 and changed to code to python 2. Simply add dependencies using pip.

```bash
pip install -r requirements.txt
```
or
```bash
pip install pythonwhois ipwhois ipaddress
```



###Usage example
```bash
ipscraper google.com 8.8.8.8 8.8.8.0/24
```
