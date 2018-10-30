InstaRecon
=======

Automated basic digital reconnaissance. Great for getting an initial footprint of your targets and discovering additional subdomains. InstaRecon will do:

* DNS lookups (A, PTR, MX, NS) 
* DNS lookups recursively on all hosts discovered
* Whois (on domain and IP) lookups
* Google dorks looking for subdomains and URLs
* [Shodan](https://www.shodan.io/) lookups
* Reverse DNS lookups on entire CIDRs (only if target is a network)

...all printed nicely on your console or csv file. 

InstaRecon will never scan a target directly. Information is retrieved from DNS/Whois servers, Google, and [Shodan](https://www.shodan.io/).

### Installing

To install simply do:
```bash
pip install -r requirements.txt
```

Dependencies should be automatically installed. Then go:

```bash 
instarecon.py <target>
```
Tested on Ubuntu 14.04 and Kali-Rolling (2016.1).

### TODO
* Shodan robots.txt
* Improve output files - use xlsx instead of csv, as width can be controlled.
* Improve Google crawler performance, implement random headers and user-agents.
* Scan threading.
* LinkedIn page scraping. Possibly other sources?
* ~~Pip installable? (https://packaging.python.org/en/latest/distributing.html).~~
* Allow proxy settings to be set.

### Example
```bash
$ instarecon.py -v -s <shodan_key> -o ~/github.com.csv github.com 
# InstaRecon v0.1.2 - by Luis Teixeira (teix.co)
# Scanning 1/1 hosts
# Shodan key provided - <shodan_key>

# ____________________ Scanning github.com ____________________ #

# DNS lookups
[*] Domain: github.com

[*] IPs & reverse DNS: 
192.30.252.129 - github.com

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
ASPMX.L.GOOGLE.com
    74.125.203.26 - th-in-f26.1e100.net
ALT2.ASPMX.L.GOOGLE.com
    64.233.168.26 - oj-in-f26.1e100.net
ALT3.ASPMX.L.GOOGLE.com
    173.194.219.27 - ya-in-f27.1e100.net
ALT4.ASPMX.L.GOOGLE.com
    173.194.219.27 - ya-in-f27.1e100.net
ALT1.ASPMX.L.GOOGLE.com
    74.125.25.27 - pa-in-f27.1e100.net

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
Name Server: ns2.p16.dynect.net
Name Server: ns1.p16.dynect.net
Name Server: ns4.p16.dynect.net
Name Server: ns3.p16.dynect.net
DNSSEC: unsigned
URL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/
>>> Last update of WHOIS database: 2015-06-17T19:49:18-0700

[*] Whois IP for 192.30.252.129:
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
IP: 192.30.252.129
Organization: GitHub
ISP: GitHub

Port: 80
Banner: HTTP/1.1 301 Moved Permanently
    Content-length: 0
    Location: https://192.30.252.129/
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

# Querying Google for subdomains and Linkedin pages, this might take a while
[*] Possible LinkedIn page: https://au.linkedin.com/company/github
[*] Subdomains:
ajaxorg.github.com
    103.245.222.133
    http://ajaxorg.github.com/ace/
almende.github.com
    103.245.222.133
    http://almende.github.com/chap-links-library/graph.html
    http://almende.github.com/chap-links-library/graph3d.html
benmmurphy.github.com
    103.245.222.133
    http://benmmurphy.github.com/blog/2015/06/09/redis-hot-patch
daid.github.com
    103.245.222.133
    http://daid.github.com/Cura/
designmodo.github.com
    103.245.222.133
    http://designmodo.github.com/Flat-UI/
devbootcamp.github.com
    103.245.222.133
    http://devbootcamp.github.com/
developer.github.com
    103.245.222.133
    https://developer.github.com/
    https://developer.github.com/guides/managing-deploy-keys/
    https://developer.github.com/program/
    https://developer.github.com/v3/
    https://developer.github.com/v3/oauth/
    https://developer.github.com/v3/repos/
education.github.com
    54.221.249.148 - ec2-54-221-249-148.compute-1.amazonaws.com
    54.243.102.92 - ec2-54-243-102-92.compute-1.amazonaws.com
    23.21.251.243 - ec2-23-21-251-243.compute-1.amazonaws.com
    https://education.github.com/
    https://education.github.com/pack
eightmedia.github.com
    103.245.222.133
    http://eightmedia.github.com/hammer.js/
enterprise.github.com
    54.225.131.5 - ec2-54-225-131-5.compute-1.amazonaws.com
    54.243.192.65 - ec2-54-243-192-65.compute-1.amazonaws.com
    https://enterprise.github.com/features
    https://enterprise.github.com/releases/2.1.8
    https://enterprise.github.com/releases/2.2.4
    https://enterprise.github.com/trial
eonasdan.github.com
    103.245.222.133
    https://eonasdan.github.com/bootstrap-datetimepicker/
eternicode.github.com
    103.245.222.133
    http://eternicode.github.com/bootstrap-datepicker/
exacttarget.github.com
    103.245.222.133
    http://exacttarget.github.com/fuelux/
fezvrasta.github.com
    103.245.222.133
    http://fezvrasta.github.com/bootstrap-material-design/bootstrap-elements.html
fgnass.github.com
    103.245.222.133
    http://fgnass.github.com/spin.js/
filosottile.github.com
    103.245.222.133
    http://filosottile.github.com/making-system-calls-from-assembly-in-mac-os-x/
firebase.github.com
    103.245.222.133
    http://firebase.github.com/
flightjs.github.com
    103.245.222.133
    http://flightjs.github.com/
fontforge.github.com
    103.245.222.133
    http://fontforge.github.com/
fortawesome.github.com
    103.245.222.133
    http://fortawesome.github.com/Font-Awesome/
    http://fortawesome.github.com/Font-Awesome/design.html
    http://fortawesome.github.com/Font-Awesome/examples/
    http://fortawesome.github.com/Font-Awesome/get-started/
    http://fortawesome.github.com/Font-Awesome/icons/
gabrielecirulli.github.com
    103.245.222.133
    http://gabrielecirulli.github.com/2048/
geonode.github.com
    103.245.222.133
    http://geonode.github.com/admin_features.html
gist.github.com
    192.30.252.140 - gist.github.com
    https://gist.github.com/
    https://gist.github.com/1508ca289f9ea71646a8
    https://gist.github.com/1600028
    https://gist.github.com/3b95f35d43284a29d25c
    https://gist.github.com/3lvis/9e15d42fa70092213802
    https://gist.github.com/501fa4653745f2190acd
    https://gist.github.com/881345d5d3d68e6fb2c2
    https://gist.github.com/AlastairTaft/d28b79e6523fe817be82
    https://gist.github.com/FoggyF/453bab43ed74d3a3cb1e
    https://gist.github.com/Garog/30183d5a0e93740e23fe
    https://gist.github.com/Indradwi22/0bbee88e032c1494bca0
    https://gist.github.com/RickDB/d2ed54937a5f821e709a
    https://gist.github.com/Sokng/68a182ce14445f3bbc6b
    https://gist.github.com/akisute/291170b50ad87ce95a47
    https://gist.github.com/athkalia/d50ecfaac0b4241c0bef
    https://gist.github.com/d8888a24a215a4ef8d92
    https://gist.github.com/davegomez/5510c9e0f8477d8e438e
    https://gist.github.com/dc0879952de9f344c984
    https://gist.github.com/dhimmel/7760d3eecb447972f836
    https://gist.github.com/dustymabe/ad4be48c948c2e601b85
    https://gist.github.com/eeeeeta/13ec3775a4253b2127ab
    https://gist.github.com/emepyc/a31e032f74df90328901
    https://gist.github.com/f3f69a377252cceac71f
    https://gist.github.com/fb39141ab30b1efa8048
    https://gist.github.com/fsjoyti/e0c259b4183d56aead74
    https://gist.github.com/fupfin/c354f8773fbbcc55124e
    https://gist.github.com/jessedc/837916
    https://gist.github.com/jmoore24/54ebc399546f4da567d7
    https://gist.github.com/jsanz/bcd7d6ae7f8e2c2ee3d7
    https://gist.github.com/jstefek/e6f72c8cee55f0daeb60
    https://gist.github.com/jvarellano/978623ef51b0bbdd00a4
    https://gist.github.com/langner/7820246
    https://gist.github.com/linc01n/29cf02c3c8d295776289
    https://gist.github.com/lucamartinetti/b64ad9daee266b368169
    https://gist.github.com/maddesigns/14acf2436b1432be1520
    https://gist.github.com/maslevx/d28547da804ba79776a4
    https://gist.github.com/mattsah/9198bb5d350c79af3c90
    https://gist.github.com/megabitus98/1b10d95c07d8a98bae4d
    https://gist.github.com/michaelerne/9801fb848cf46add74f8
    https://gist.github.com/michaelsarduino/67d0f793bcee34ffaea4
    https://gist.github.com/noelmace/94cdd8efc54e520a154f
    https://gist.github.com/pastokes/1b1b0c8f290db9cfec84
    https://gist.github.com/pescobar/5600555fa574017ecd26
    https://gist.github.com/philiprbrenan/d955a9c42edd5344353f
    https://gist.github.com/puffstream/be141e41e43a992360ae
    https://gist.github.com/rahatarmanahmed/48c7438f4a90ce122f3e
    https://gist.github.com/riririaan/2e215c397588a619cd4d
    https://gist.github.com/rmsr/d216c86f51ce34f48fa5
    https://gist.github.com/sarigopiram/540ed4a951fe4fc304ba
    https://gist.github.com/sensugaz/1f54678e0fb0285ad9b3
    https://gist.github.com/simonszu/21bf5b504fa18824eecf
    https://gist.github.com/srajagop/4c6d1fe0d887c8de4564
    https://gist.github.com/stephenpardy/c67db785da02e62a8d67
    https://gist.github.com/stevemart/585f932a5c526c375396
    https://gist.github.com/sutezo/38bb1474f5ce29c37dcc
    https://gist.github.com/terrycojones/2b18f23247903fd5213b
    https://gist.github.com/tpoechtrager/d0440d44592f48b099f8
    https://gist.github.com/tranthecoder/b163b64fdfa4bd79e4da
    https://gist.github.com/westernmonster/ea961d95e4689979a4f2
    https://gist.github.com/wjaspers/0919eeb89e0f378c9cdb
    https://gist.github.com/yhuang/435d7418da1b8f29b9a7
guides.github.com
    103.245.222.133
    https://guides.github.com/
    https://guides.github.com/features/mastering-markdown/
    https://guides.github.com/introduction/flow/
    https://guides.github.com/introduction/getting-your-project-on-github/
hanklords.github.com
    103.245.222.133
    http://hanklords.github.com/flickraw/
help.github.com
    103.245.222.133
    https://help.github.com/
    https://help.github.com/articles/adding-links-to-wikis/
    https://help.github.com/articles/be-social/
    https://help.github.com/articles/caching-your-github-password-in-git/
    https://help.github.com/articles/changing-a-remote-s-url/
    https://help.github.com/articles/configuring-a-remote-for-a-fork/
    https://help.github.com/articles/create-a-repo/
    https://help.github.com/articles/creating-pages-with-the-automatic-generator/
    https://help.github.com/articles/creating-releases/
    https://help.github.com/articles/fork-a-repo/
    https://help.github.com/articles/markdown-basics/
    https://help.github.com/articles/set-up-git/
    https://help.github.com/articles/syncing-a-fork/
    https://help.github.com/articles/user-organization-and-project-pages/
    https://help.github.com/articles/using-jekyll-with-pages/
    https://help.github.com/articles/using-pull-requests/
    https://help.github.com/articles/which-remote-url-should-i-use/
    https://help.github.com/articles/writing-on-github/
hubot.github.com
    103.245.222.133
    https://hubot.github.com/
    https://hubot.github.com/docs/
ipython.github.com
    103.245.222.133
    http://ipython.github.com/download.html
    http://ipython.github.com/ipython-doc
ivaynberg.github.com
    103.245.222.133
    http://ivaynberg.github.com/select2/
jakewharton.github.com
    103.245.222.133
    http://jakewharton.github.com/butterknife/
janpaepke.github.com
    103.245.222.133
    http://janpaepke.github.com/ScrollMagic
jgilfelt.github.com
    103.245.222.133
    http://jgilfelt.github.com/android-actionbarstylegenerator/
jobs.github.com
    54.163.15.207 - ec2-54-163-15-207.compute-1.amazonaws.com
    https://jobs.github.com/
    https://jobs.github.com/companies/Trustpilot
    https://jobs.github.com/positions
    https://jobs.github.com/positions%3Fdescription%3DJavaScript
    https://jobs.github.com/positions/1a5cf3c8-139b-11e5-9145-e1c5bb7ec7a9
    https://jobs.github.com/positions/aca57740-1374-11e5-92ea-f56b9efdc6a1
    https://jobs.github.com/positions/cd2fbdde-150b-11e5-90b9-4ee0ac71990f
    https://jobs.github.com/positions/db785c4e-1500-11e5-9251-0079eaacb490
    https://jobs.github.com/positions/f332ea88-1466-11e5-817e-61f408951a63
johnpolacek.github.com
    103.245.222.133
    http://johnpolacek.github.com/superscrollorama/
jsdoc3.github.com
    103.245.222.133
    http://jsdoc3.github.com/
kangax.github.com
    103.245.222.133
    http://kangax.github.com/compat-table/es7
    http://kangax.github.com/es5-compat-table/
karpathy.github.com
    103.245.222.133
    http://karpathy.github.com/2015/05/21/rnn-effectiveness/
mac.github.com
    103.245.222.133
    https://mac.github.com/
mapbox.github.com
    103.245.222.133
    http://mapbox.github.com/wax
matplotlib.github.com
    103.245.222.133
    http://matplotlib.github.com/api/pyplot_api.html
    http://matplotlib.github.com/api/pyplot_summary.html
    http://matplotlib.github.com/gallery.html
mbostock.github.com
    103.245.222.133
    http://mbostock.github.com/
    http://mbostock.github.com/d3/
    http://mbostock.github.com/d3/ex/choropleth.html
    http://mbostock.github.com/d3/ex/population.html
mdboom.github.com
    103.245.222.133
    http://mdboom.github.com/
mgcrea.github.com
    103.245.222.133
    http://mgcrea.github.com/angular-strap/
mrdoob.github.com
    103.245.222.133
    http://mrdoob.github.com/three.js/docs/
msysgit.github.com
    103.245.222.133
    http://msysgit.github.com/
mustache.github.com
    103.245.222.133
    http://mustache.github.com/
mxcl.github.com
    103.245.222.133
    http://mxcl.github.com/homebrew/
nltk.github.com
    103.245.222.133
    http://nltk.github.com/
nodeca.github.com
    103.245.222.133
    http://nodeca.github.com/fontomas/
novus.github.com
    103.245.222.133
    http://novus.github.com/nvd3
    http://novus.github.com/nvd3/ghpages/examples.html
onedrive.github.com
    103.245.222.133
    http://onedrive.github.com/
osxfuse.github.com
    103.245.222.133
    http://osxfuse.github.com/
pages.github.com
    103.245.222.133
    https://pages.github.com/
parquet.github.com
    103.245.222.133
    http://parquet.github.com/
paypal.github.com
    103.245.222.133
    http://paypal.github.com/
pcottle.github.com
    103.245.222.133
    http://pcottle.github.com/learnGitBranching/
pnts.github.com
    103.245.222.133
    http://pnts.github.com/look/happeh-canada-day
    http://pnts.github.com/look/on-stage
    http://pnts.github.com/quote/design-is
    http://pnts.github.com/quote/making-meaning
    http://pnts.github.com/txt/bower-sass-bones
    http://pnts.github.com/txt/color-mixing-with-sass
    http://pnts.github.com/txt/just-say-no-to-unicorns
racker.github.com
    103.245.222.133
    http://racker.github.com/falcon
raw.github.com
    103.245.222.133
    https://raw.github.com/git/git/master/Documentation/RelNotes/2.4.4.txt
    https://raw.github.com/olleota/themes/master/shade/main.html
    https://raw.github.com/pypa/pip/master/contrib/get-pip.py
rg3.github.com
    103.245.222.133
    http://rg3.github.com/youtube-dl/
    http://rg3.github.com/youtube-dl/download.html
rogerdudler.github.com
    103.245.222.133
    http://rogerdudler.github.com/git-guide/
shop.github.com
    192.30.252.128 - github.com
    https://shop.github.com/
    https://shop.github.com/products/invertocat-hoodie
    https://shop.github.com/products/piratocat-shirt
silviomoreto.github.com
    103.245.222.133
    http://silviomoreto.github.com/bootstrap-select/
sinatra.github.com
    103.245.222.133
    http://sinatra.github.com/intro.html
sorich87.github.com
    103.245.222.133
    http://sorich87.github.com/bootstrap-tour/
square.github.com
    103.245.222.133
    http://square.github.com/crossfilter/
    http://square.github.com/cubism/
    http://square.github.com/retrofit/
status.github.com
    107.20.225.214 - ec2-107-20-225-214.compute-1.amazonaws.com
    184.73.218.119 - ec2-184-73-218-119.compute-1.amazonaws.com
    https://status.github.com/
    https://status.github.com/messages
    https://status.github.com/messages/2015-05-24
swarmsim.github.com
    103.245.222.133
    https://swarmsim.github.com/
thehackerwithin.github.com
    103.245.222.133
    http://thehackerwithin.github.com/swinburne/posts/iPython_notebooks
tkf.github.com
    103.245.222.133
    http://tkf.github.com/emacs-ipython-notebook/
tomchristie.github.com
    103.245.222.133
    http://tomchristie.github.com/django-rest-framework/api-guide/serializers
training.github.com
    103.245.222.133
    http://training.github.com/p/branching.html
    https://training.github.com/
    https://training.github.com/kit/downloads/github-git-cheat-sheet.pdf
try.github.com
    103.245.222.133
    http://try.github.com/levels/1/challenges/11
    http://try.github.com/levels/1/challenges/12
    http://try.github.com/levels/1/challenges/16
    http://try.github.com/levels/1/challenges/20
    http://try.github.com/levels/1/challenges/24
    http://try.github.com/levels/1/challenges/25
    http://try.github.com/levels/1/challenges/4
    http://try.github.com/levels/1/challenges/9
    https://try.github.com/
    https://try.github.com/levels/1/challenges/2
twbs.github.com
    103.245.222.133
    http://twbs.github.com/bootstrap/
twitter.github.com
    103.245.222.133
    http://twitter.github.com/bootstrap/
    http://twitter.github.com/typeahead.js/
    http://twitter.github.com/typeahead.js/examples
visionmedia.github.com
    103.245.222.133
    http://visionmedia.github.com/superagent/
vitalets.github.com
    103.245.222.133
    http://vitalets.github.com/x-editable/
voidlinux.github.com
    103.245.222.133
    http://voidlinux.github.com/
wagerfield.github.com
    103.245.222.133
    http://wagerfield.github.com/parallax/
webcomponents.github.com
    103.245.222.133
    http://webcomponents.github.com/
webpack.github.com
    103.245.222.133
    http://webpack.github.com/docs
windows.github.com
    103.245.222.133
    https://windows.github.com/
yui.github.com
    103.245.222.133
    http://yui.github.com/yuicompressor/
zendesk.github.com
    103.245.222.133
    http://zendesk.github.com/

# Saving output csv file
# Done
```