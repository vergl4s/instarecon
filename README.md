InstaRecon
=======

Automated basic digital reconnaissance. Great for getting an initial footprint of your targets.

* Direct and reverse DNS lookups
* Domain and IP Whois lookups
* Google dorks to get subdomains that relate to a target
* [Shodan](https://www.shodan.io/) lookups
* Reverse DNS lookups on CIDRs related to targets

InstaRecon will never scan a target directly. Information is retrieved from DNS/Whois servers, Google, and [Shodan](https://www.shodan.io/).

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
./instarecon.py -s <shodan_key> github.com
# Scanning 1/1 hosts
# Shodan key provided - <shodan_key>

____________________ Scanning github.com ____________________

# Doing DNS/Whois lookups
[-] Domain: github.com
[-] IP: 192.30.252.130
[-] Reverse domain: github.com

[-] Whois domain:
Domain Name: github.com
Registry Domain ID: 1264983250_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.markmonitor.com
Registrar URL: http://www.markmonitor.com
Updated Date: 2015-01-08T04:00:18-0800
Creation Date: 2007-10-09T11:20:50-0700
Registrar Registration Expiration Date: 2020-10-09T11:20:50-0700
Registrar: MarkMonitor, Inc.
Registrar IANA ID: 292
Registrar Abuse Contact Email: abusecomplaints@markmonitor.com
Registrar Abuse Contact Phone: +1.2083895740
Domain Status: clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)
Domain Status: clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)
Domain Status: clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)
Registry Registrant ID: 
Registrant Name: GitHub Hostmaster
Registrant Organization: GitHub, Inc.
Registrant Street: 88 Colin P Kelly Jr St, 
Registrant City: San Francisco
Registrant State/Province: CA
Registrant Postal Code: 94107
Registrant Country: US
Registrant Phone: +1.4157354488
Registrant Phone Ext: 
Registrant Fax: 
Registrant Fax Ext: 
Registrant Email: hostmaster@github.com
Registry Admin ID: 
Admin Name: GitHub Hostmaster
Admin Organization: GitHub, Inc.
Admin Street: 88 Colin P Kelly Jr St, 
Admin City: San Francisco
Admin State/Province: CA
Admin Postal Code: 94107
Admin Country: US
Admin Phone: +1.4157354488
Admin Phone Ext: 
Admin Fax: 
Admin Fax Ext: 
Admin Email: hostmaster@github.com
Registry Tech ID: 
Tech Name: GitHub Hostmaster
Tech Organization: GitHub, Inc.
Tech Street: 88 Colin P Kelly Jr St, 
Tech City: San Francisco
Tech State/Province: CA
Tech Postal Code: 94107
Tech Country: US
Tech Phone: +1.4157354488
Tech Phone Ext: 
Tech Fax: 
Tech Fax Ext: 
Tech Email: hostmaster@github.com
Name Server: ns4.p16.dynect.net
Name Server: ns3.p16.dynect.net
Name Server: ns2.p16.dynect.net
Name Server: ns1.p16.dynect.net
DNSSEC: unsigned
URL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/
>>> Last update of WHOIS database: 2015-03-10T17:16:54-0700 <<<

[-] Whois IP:
asn: 36459
asn_cidr: 192.30.252.0/24
asn_country_code: US
asn_date: 2012-11-15
asn_registry: arin
net0_abuse_emails: abuse@github.com
net0_address: 88 Colin P Kelly Jr Street
net0_cidr: 192.30.252.0/22
net0_city: San Francisco
net0_country: US
net0_created: 2012-11-15T00:00:00
net0_description: GitHub, Inc.
net0_handle: NET-192-30-252-0-1
net0_name: GITHUB-NET4-1
net0_postal_code: 94107
net0_range: 192.30.252.0 - 192.30.255.255
net0_state: CA
net0_tech_emails: hostmaster@github.com
net0_updated: 2013-01-05T00:00:00

# Querying Shodan for open ports
[-] Shodan:
Organization: GitHub
Port: 80
Banner: HTTP/1.0 301 Moved Permanently
    Content-length: 0
    Location: https://192.30.252.130/
    Connection: close
Port: 22
Banner: SSH-2.0-libssh-0.6.0
    Key type: ssh-rsa
    Key: AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PH
    kccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETY
    P81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoW
    f9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lG
    HSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==
    Fingerprint: 16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48

# Querying Google for subdomains, this might take a while
[-] Subdomains:
ajaxorg.github.com
amsul.github.com
bounty.github.com
bradfrost.github.com
brownplt.github.com
cucumber.github.com
daid.github.com
developer.github.com
dodgeball.github.com
education.github.com
eightmedia.github.com
enterprise.github.com
eonasdan.github.com
erkie.github.com
eternicode.github.com
exploringdata.github.com
fezvrasta.github.com
fgnass.github.com
filosottile.github.com
fontforge.github.com
fortawesome.github.com
gist.github.com
github.github.com
guides.github.com
help.github.com
hpneo.github.com
hubot.github.com
imakewebthings.github.com
ipython.github.com
jakewharton.github.com
janpaepke.github.com
jasny.github.com
jgilfelt.github.com
jobs.github.com
kohana.github.com
learnboost.github.com
mac.github.com
makeusabrew.github.com
man.github.com
mapbox.github.com
matplotlib.github.com
mbostock.github.com
mindmup.github.com
mojombo.github.com
mozilla.github.com
mrdoob.github.com
msysgit.github.com
mustache.github.com
mxcl.github.com
n1k0.github.com
nltk.github.com
novus.github.com
osxfuse.github.com
owin.github.com
pages.github.com
panrafal.github.com
philogb.github.com
pikock.github.com
pnts.github.com
raw.github.com
rg3.github.com
rosedu.github.com
rtyley.github.com
shop.github.com
silviomoreto.github.com
somatonic.github.com
sorich87.github.com
square.github.com
status.github.com
stemkoski.github.com
swannodette.github.com
tobie.github.com
tomchristie.github.com
training.github.com
try.github.com
twbs.github.com
twitter.github.com
ubuwaits.github.com
vitalets.github.com
wagerfield.github.com
webpack.github.com
westonruter.github.com
windows.github.com
yui.github.com

[-] Possible LinkedIn page: https://www.linkedin.com/company/github

# Reverse DNS lookup on range 192.30.252.0/24 (taken from github.com)
192.30.252.80 ns1.github.com
192.30.252.81 ns2.github.com
192.30.252.86 live.github.com
192.30.252.87 live.github.com
192.30.252.88 live.github.com
192.30.252.97 ops-lb-ip1.iad.github.com
192.30.252.98 ops-lb-ip2.iad.github.com
192.30.252.128 github.com
192.30.252.129 github.com
192.30.252.130 github.com
192.30.252.131 github.com
192.30.252.132 assets.github.com
192.30.252.133 assets.github.com
192.30.252.134 assets.github.com
192.30.252.135 assets.github.com
192.30.252.136 api.github.com
192.30.252.137 api.github.com
192.30.252.138 api.github.com
192.30.252.139 api.github.com
192.30.252.140 gist.github.com
192.30.252.141 gist.github.com
192.30.252.142 gist.github.com
192.30.252.143 gist.github.com
192.30.252.144 codeload.github.com
192.30.252.145 codeload.github.com
192.30.252.146 codeload.github.com
192.30.252.147 codeload.github.com
192.30.252.148 ssh.github.com
192.30.252.149 ssh.github.com
192.30.252.150 ssh.github.com
192.30.252.151 ssh.github.com
192.30.252.152 pages.github.com
192.30.252.153 pages.github.com
192.30.252.154 pages.github.com
192.30.252.155 pages.github.com
192.30.252.156 githubusercontent.github.com
192.30.252.157 githubusercontent.github.com
192.30.252.158 githubusercontent.github.com
192.30.252.159 githubusercontent.github.com
192.30.252.192 github-smtp2-ext1.iad.github.net
192.30.252.193 github-smtp2-ext2.iad.github.net
192.30.252.194 github-smtp2-ext3.iad.github.net
192.30.252.195 github-smtp2-ext4.iad.github.net
192.30.252.196 github-smtp2-ext5.iad.github.net
192.30.252.197 github-smtp2-ext6.iad.github.net
192.30.252.198 github-smtp2-ext7.iad.github.net
192.30.252.199 github-smtp2-ext8.iad.github.net
```

