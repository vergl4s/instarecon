InstaRecon
=======

Automated basic digital reconnaissance. Great for getting an initial footprint of your targets.

* Direct and reverse DNS lookups
* MX and NS lookups
* Domain and IP Whois lookups
* Google queries to get subdomains
* [Shodan](https://www.shodan.io/) lookups
* Reverse DNS lookups on entire CIDRs looking for subdomains

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
$ ./instarecon.py -s <shodan_key> -o ~/Desktop/github.csv github.com
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
    173.194.64.26 - oa-in-f26.1e100.net
ASPMX.L.GOOGLE.com
    74.125.204.27
ALT3.ASPMX.L.GOOGLE.com
    173.194.74.26 - qe-in-f26.1e100.net
ALT4.ASPMX.L.GOOGLE.com
    74.125.137.26 - yh-in-f26.1e100.net
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
Name Server: ns4.p16.dynect.net
Name Server: ns3.p16.dynect.net
Name Server: ns2.p16.dynect.net
DNSSEC: unsigned
URL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/
>>> Last update of WHOIS database: 2015-04-09T20:41:54-0700 <<<

The Data in MarkMonitor.com\'s WHOIS database is provided by MarkMonitor.com for
information purposes, and to assist persons in obtaining information about or
related to a domain name registration record.  MarkMonitor.com does not guarantee
its accuracy.  By submitting a WHOIS query, you agree that you will use this Data
only for lawful purposes and that, under no circumstances will you use this Data to:
 (1) allow, enable, or otherwise support the transmission of mass unsolicited,
     commercial advertising or solicitations via e-mail (spam); or
 (2) enable high volume, automated, electronic processes that apply to
     MarkMonitor.com (or its systems).
MarkMonitor.com reserves the right to modify these terms at any time.
By submitting this query, you agree to abide by this policy.

MarkMonitor is the Global Leader in Online Brand Protection.

MarkMonitor Domain Management(TM)
MarkMonitor Brand Protection(TM)
MarkMonitor AntiPiracy(TM)
MarkMonitor AntiFraud(TM)
Professional and Managed Services

Visit MarkMonitor at http://www.markmonitor.com
Contact us at +1.8007459229
In Europe, at +44.02032062220
--

[*] Whois IP:
asn: 36459
asn_cidr: 192.30.252.0/22
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

[*] Shodan:
IP: 192.30.252.130
Organization: GitHub
Port: 80
Banner: HTTP/1.1 301 Moved Permanently
    Content-length: 0
    Location: https://192.30.252.130/
    Connection: closePort: 22
Banner: SSH-2.0-libssh-0.6.0
    Key type: ssh-rsa
    Key: AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PH
    kccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETY
    P81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoW
    f9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lG
    HSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==
    Fingerprint: 16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48

# Querying Google for subdomains and Linkedin pages, this might take a while

[*] Possible LinkedIn page: https://au.linkedin.com/company/github

[*] Subdomains:
addyosmani.github.com
    199.27.78.133
ajaxorg.github.com
    199.27.78.133
bem.github.com
    199.27.78.133
benweet.github.com
    199.27.78.133
bonsaiden.github.com
    199.27.78.133
bradfrost.github.com
    199.27.78.133
chad.github.com
    199.27.78.133
cocoapods.github.com
    199.27.78.133
daid.github.com
    199.27.78.133
developer.github.com
    199.27.78.133
documentcloud.github.com
    199.27.78.133
dodgeball.github.com
    54.235.176.183 - ec2-54-235-176-183.compute-1.amazonaws.com
    54.83.198.34 - ec2-54-83-198-34.compute-1.amazonaws.com
    54.243.199.14 - ec2-54-243-199-14.compute-1.amazonaws.com
education.github.com
    50.19.229.116 - ec2-50-19-229-116.compute-1.amazonaws.com
    50.17.253.231 - ec2-50-17-253-231.compute-1.amazonaws.com
    23.23.134.127 - ec2-23-23-134-127.compute-1.amazonaws.com
enterprise.github.com
    54.235.148.255 - ec2-54-235-148-255.compute-1.amazonaws.com
    54.235.132.86 - ec2-54-235-132-86.compute-1.amazonaws.com
fgnass.github.com
    199.27.78.133
fluent.github.com
    199.27.78.133
fontforge.github.com
    199.27.78.133
fortawesome.github.com
    199.27.78.133
gabrielecirulli.github.com
    199.27.78.133
gist.github.com
    192.30.252.143 - gist.github.com
greggman.github.com
    199.27.78.133
guides.github.com
    199.27.78.133
help.github.com
    199.27.78.133
hpneo.github.com
    199.27.78.133
hubot.github.com
    199.27.78.133
imakewebthings.github.com
    199.27.78.133
jackaudio.github.com
    199.27.78.133
jakewharton.github.com
    199.27.78.133
jashkenas.github.com
    199.27.78.133
jdewit.github.com
    199.27.78.133
jgilfelt.github.com
    199.27.78.133
jobs.github.com
    54.163.15.207 - ec2-54-163-15-207.compute-1.amazonaws.com
kangax.github.com
    199.27.78.133
kentonv.github.com
    199.27.78.133
kripken.github.com
    199.27.78.133
learnboost.github.com
    199.27.78.133
lhorie.github.com
    199.27.78.133
mac.github.com
    199.27.78.133
makeusabrew.github.com
    199.27.78.133
manns.github.com
    199.27.78.133
mapbox.github.com
    199.27.78.133
matplotlib.github.com
    199.27.78.133
mbostock.github.com
    199.27.78.133
mementoweb.github.com
    199.27.78.133
mgcrea.github.com
    199.27.78.133
mindmup.github.com
    199.27.78.133
mrdoob.github.com
    199.27.78.133
msysgit.github.com
    199.27.78.133
mustache.github.com
    199.27.78.133
mxcl.github.com
    199.27.78.133
n1k0.github.com
    199.27.78.133
nodeca.github.com
    199.27.78.133
novus.github.com
    199.27.78.133
osxfuse.github.com
    199.27.78.133
pages.github.com
    199.27.78.133
panrafal.github.com
    199.27.78.133
pcottle.github.com
    199.27.78.133
philipwalton.github.com
    199.27.78.133
pnts.github.com
    199.27.78.133
raw.github.com
    199.27.78.133
rg3.github.com
    199.27.78.133
robotframework.github.com
    199.27.78.133
rogerdudler.github.com
    199.27.78.133
scottjehl.github.com
    199.27.78.133
shop.github.com
    192.30.252.128 - github.com
shopify.github.com
    199.27.78.133
silviomoreto.github.com
    199.27.78.133
square.github.com
    199.27.78.133
status.github.com
    184.73.218.119 - ec2-184-73-218-119.compute-1.amazonaws.com
    107.20.225.214 - ec2-107-20-225-214.compute-1.amazonaws.com
stedolan.github.com
    199.27.78.133
swarmsim.github.com
    199.27.78.133
technoweenie.github.com
    199.27.78.133
thinktecture.github.com
    199.27.78.133
thoughtbot.github.com
    199.27.78.133
tomchristie.github.com
    199.27.78.133
topcoat.github.com
    199.27.78.133
training.github.com
    199.27.78.133
try.github.com
    199.27.78.133
twbs.github.com
    199.27.78.133
twitter.github.com
    199.27.78.133
vitalets.github.com
    199.27.78.133
windows.github.com
    199.27.78.133
yui.github.com
    199.27.78.133

# Reverse DNS lookup on range(s) 192.30.252.0/22 (related to github.com)
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

