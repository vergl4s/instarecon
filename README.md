InstaRecon
=======

Automated basic digital reconnaissance. Great for getting an initial footprint of your targets and discovering additional subdomains. InstaRecon will do:

* DNS (direct, PTR, MX, NS) lookups
* Whois (domains and IP) lookups
* Google dorks in search of subdomains
* [Shodan](https://www.shodan.io/) lookups
* Reverse DNS lookups on entire CIDRs

...all printed nicely on your console or csv file. 

InstaRecon will never scan a target directly. Information is retrieved from DNS/Whois servers, Google, and [Shodan](https://www.shodan.io/).

###Installing with pip
Simply install dependencies using pip. Tested on Ubuntu 14.04 and Kali Linux 1.1.0a.

```bash
pip install -r requirements.txt
```
or
```bash
pip install pythonwhois ipwhois ipaddress shodan
```

###Example
```bash
$ ./instarecon.py -s <shodan_key> -o ~/Desktop/github.com.csv github.com
# InstaRecon v0.1 - by Luis Teixeira (teix.co)
# Scanning 1/1 hosts
# Shodan key provided - <shodan_key>

# ____________________ Scanning github.com ____________________ #

# DNS lookups
[*] Domain: github.com

[*] IPs & reverse DNS: 
192.30.252.130 - github.com

[*] NS records:
ns4.p16.dynect.net
    204.13.251.16 - ns4.p16.dynect.net
ns3.p16.dynect.net
    208.78.71.16 - ns3.p16.dynect.net
ns2.p16.dynect.net
    204.13.250.16 - ns2.p16.dynect.net
ns1.p16.dynect.net
    208.78.70.16 - ns1.p16.dynect.net

[*] MX records:
ALT2.ASPMX.L.GOOGLE.com
    173.194.64.27 - oa-in-f27.1e100.net
ASPMX.L.GOOGLE.com
    74.125.203.26
ALT3.ASPMX.L.GOOGLE.com
    64.233.177.26
ALT4.ASPMX.L.GOOGLE.com
    173.194.219.27
ALT1.ASPMX.L.GOOGLE.com
    74.125.25.26 - pa-in-f26.1e100.net

# Whois lookups

[*] Whois domain:
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
Name Server: ns1.p16.dynect.net
Name Server: ns2.p16.dynect.net
Name Server: ns4.p16.dynect.net
Name Server: ns3.p16.dynect.net
DNSSEC: unsigned
URL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/
>>> Last update of WHOIS database: 2015-05-04T06:48:47-0700

[*] Whois IP:
asn: 36459
asn_cidr: 192.30.252.0/24
asn_country_code: US
asn_date: 2012-11-15
asn_registry: arin
net 0:
    cidr: 192.30.252.0/22
    range: 192.30.252.0 - 192.30.255.255
    name: GITHUB-NET4-1
    description: GitHub, Inc.
    handle: NET-192-30-252-0-1
    
    address: 88 Colin P Kelly Jr Street
    city: San Francisco
    state: CA
    postal_code: 94107
    country: US
    
    abuse_emails: abuse@github.com
    tech_emails: hostmaster@github.com
    
    created: 2012-11-15 00:00:00
    updated: 2013-01-05 00:00:00

# Querying Shodan for open ports
[*] Shodan:
IP: 192.30.252.130
Organization: GitHub
ISP: GitHub

Port: 22
Banner: SSH-2.0-libssh-0.6.0
    Key type: ssh-rsa
    Key: AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PH
    kccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETY
    P81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoW
    f9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lG
    HSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==
    Fingerprint: 16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48
Port: 80
Banner: HTTP/1.1 301 Moved Permanently
    Content-length: 0
    Location: https://192.30.252.130/
    Connection: close

# Querying Google for subdomains and Linkedin pages, this might take a while
[*] Possible LinkedIn page: https://au.linkedin.com/company/github
[*] Subdomains:
blueimp.github.com
    199.27.75.133
bounty.github.com
    199.27.75.133
designmodo.github.com
    199.27.75.133
developer.github.com
    199.27.75.133
digitaloxford.github.com
    199.27.75.133
documentcloud.github.com
    199.27.75.133
education.github.com
    50.19.229.116 - ec2-50-19-229-116.compute-1.amazonaws.com
    50.17.253.231 - ec2-50-17-253-231.compute-1.amazonaws.com
    54.221.249.148 - ec2-54-221-249-148.compute-1.amazonaws.com
enterprise.github.com
    54.243.192.65 - ec2-54-243-192-65.compute-1.amazonaws.com
    54.243.49.169 - ec2-54-243-49-169.compute-1.amazonaws.com
erkie.github.com
    199.27.75.133
eternicode.github.com
    199.27.75.133
facebook.github.com
    199.27.75.133
fortawesome.github.com
    199.27.75.133
gist.github.com
    192.30.252.141 - gist.github.com
guides.github.com
    199.27.75.133
h5bp.github.com
    199.27.75.133
harvesthq.github.com
    199.27.75.133
help.github.com
    199.27.75.133
hexchat.github.com
    199.27.75.133
hubot.github.com
    199.27.75.133
ipython.github.com
    199.27.75.133
janpaepke.github.com
    199.27.75.133
jgilfelt.github.com
    199.27.75.133
jobs.github.com
    54.163.15.207 - ec2-54-163-15-207.compute-1.amazonaws.com
kangax.github.com
    199.27.75.133
karlseguin.github.com
    199.27.75.133
kouphax.github.com
    199.27.75.133
learnboost.github.com
    199.27.75.133
liferay.github.com
    199.27.75.133
lloyd.github.com
    199.27.75.133
mac.github.com
    199.27.75.133
mapbox.github.com
    199.27.75.133
matplotlib.github.com
    199.27.75.133
mbostock.github.com
    199.27.75.133
mdo.github.com
    199.27.75.133
mindmup.github.com
    199.27.75.133
mrdoob.github.com
    199.27.75.133
msysgit.github.com
    199.27.75.133
nativescript.github.com
    199.27.75.133
necolas.github.com
    199.27.75.133
nodeca.github.com
    199.27.75.133
onedrive.github.com
    199.27.75.133
pages.github.com
    199.27.75.133
panrafal.github.com
    199.27.75.133
parquet.github.com
    199.27.75.133
pnts.github.com
    199.27.75.133
raw.github.com
    199.27.75.133
rg3.github.com
    199.27.75.133
rosedu.github.com
    199.27.75.133
schacon.github.com
    199.27.75.133
scottjehl.github.com
    199.27.75.133
shop.github.com
    192.30.252.129 - github.com
shopify.github.com
    199.27.75.133
status.github.com
    184.73.218.119 - ec2-184-73-218-119.compute-1.amazonaws.com
    107.20.225.214 - ec2-107-20-225-214.compute-1.amazonaws.com
thoughtbot.github.com
    199.27.75.133
tomchristie.github.com
    199.27.75.133
training.github.com
    199.27.75.133
try.github.com
    199.27.75.133
twbs.github.com
    199.27.75.133
twitter.github.com
    199.27.75.133
visualstudio.github.com
    54.192.134.13 - server-54-192-134-13.syd1.r.cloudfront.net
    54.230.135.112 - server-54-230-135-112.syd1.r.cloudfront.net
    54.192.134.21 - server-54-192-134-21.syd1.r.cloudfront.net
    54.230.134.194 - server-54-230-134-194.syd1.r.cloudfront.net
    54.192.133.169 - server-54-192-133-169.syd1.r.cloudfront.net
    54.192.133.193 - server-54-192-133-193.syd1.r.cloudfront.net
    54.230.134.145 - server-54-230-134-145.syd1.r.cloudfront.net
    54.240.176.208 - server-54-240-176-208.syd1.r.cloudfront.net
wagerfield.github.com
    199.27.75.133
webcomponents.github.com
    199.27.75.133
webpack.github.com
    199.27.75.133
weheart.github.com
    199.27.75.133

# Reverse DNS lookup on range 192.30.252.0/22
192.30.252.80 - ns1.github.com
192.30.252.81 - ns2.github.com
192.30.252.86 - live.github.com
192.30.252.87 - live.github.com
192.30.252.88 - live.github.com
192.30.252.97 - ops-lb-ip1.iad.github.com
192.30.252.98 - ops-lb-ip2.iad.github.com
192.30.252.128 - github.com
192.30.252.129 - github.com
192.30.252.130 - github.com
192.30.252.131 - github.com
192.30.252.132 - assets.github.com
192.30.252.133 - assets.github.com
192.30.252.134 - assets.github.com
192.30.252.135 - assets.github.com
192.30.252.136 - api.github.com
192.30.252.137 - api.github.com
192.30.252.138 - api.github.com
192.30.252.139 - api.github.com
192.30.252.140 - gist.github.com
192.30.252.141 - gist.github.com
192.30.252.142 - gist.github.com
192.30.252.143 - gist.github.com
192.30.252.144 - codeload.github.com
192.30.252.145 - codeload.github.com
192.30.252.146 - codeload.github.com
192.30.252.147 - codeload.github.com
192.30.252.148 - ssh.github.com
192.30.252.149 - ssh.github.com
192.30.252.150 - ssh.github.com
192.30.252.151 - ssh.github.com
192.30.252.152 - pages.github.com
192.30.252.153 - pages.github.com
192.30.252.154 - pages.github.com
192.30.252.155 - pages.github.com
192.30.252.156 - githubusercontent.github.com
192.30.252.157 - githubusercontent.github.com
192.30.252.158 - githubusercontent.github.com
192.30.252.159 - githubusercontent.github.com
192.30.252.192 - github-smtp2-ext1.iad.github.net
192.30.252.193 - github-smtp2-ext2.iad.github.net
192.30.252.194 - github-smtp2-ext3.iad.github.net
192.30.252.195 - github-smtp2-ext4.iad.github.net
192.30.252.196 - github-smtp2-ext5.iad.github.net
192.30.252.197 - github-smtp2-ext6.iad.github.net
192.30.252.198 - github-smtp2-ext7.iad.github.net
192.30.252.199 - github-smtp2-ext8.iad.github.net
192.30.253.1 - ops-puppetmaster1-cp1-prd.iad.github.com
192.30.253.2 - janky-nix101-cp1-prd.iad.github.com
192.30.253.3 - janky-nix102-cp1-prd.iad.github.com
192.30.253.4 - janky-nix103-cp1-prd.iad.github.com
192.30.253.5 - janky-nix104-cp1-prd.iad.github.com
192.30.253.6 - janky-nix105-cp1-prd.iad.github.com
192.30.253.7 - janky-nix106-cp1-prd.iad.github.com
192.30.253.8 - janky-nix107-cp1-prd.iad.github.com
192.30.253.9 - janky-nix108-cp1-prd.iad.github.com
192.30.253.10 - gw.internaltools-esx1-cp1-prd.iad.github.com
192.30.253.11 - janky-chromium101-cp1-prd.iad.github.com
192.30.253.12 - gw.internaltools-esx2-cp1-prd.iad.github.com
192.30.253.13 - github-mon2ext-cp1-prd.iad.github.net
192.30.253.16 - github-smtp2a-ext-cp1-prd.iad.github.net
192.30.253.17 - github-smtp2b-ext-cp1-prd.iad.github.net
192.30.253.23 - ops-bastion1-cp1-prd.iad.github.com
192.30.253.30 - github-slowsmtp1-ext-cp1-prd.iad.github.net
192.30.254.1 - github-lb3a-cp1-prd.iad.github.com
192.30.254.2 - github-lb3b-cp1-prd.iad.github.com
192.30.254.3 - github-lb3c-cp1-prd.iad.github.com
192.30.254.4 - github-lb3d-cp1-prd.iad.github.com
# Saving output csv file
# Done
```

###TODO
* Shodan robots.txt
* Improve output files - CSV needs to look better. Possibly add XML or HTML? Also possibly use a logger for this.
* Make a proper GitHub release for v0.1 (https://github.com/blog/1547-release-your-software).
* Improve Google crawler performance, implement random headers and user-agents.
* Scan threading.
* LinkedIn page scraping. Possibly other sources?
* Pip installable? (https://packaging.python.org/en/latest/distributing.html).
* Allow proxy settings to be set.