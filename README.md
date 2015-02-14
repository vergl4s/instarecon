IPscraper
=======

OSINT scraper that tries to gather information on IP addresses and domain names.


###Installing on Kali Linux
This is an ugly workaround, because, for some reason, Kali decided to stay on python3.2. I suggest that you take a snapshot of your system before doing this.

```bash
cd /tmp 
wget http://python.org/ftp/python/3.3.2/Python-3.3.2.tgz
tar -xvf Python-3.3.2.tgz 
cd Python-3.3.2 
./configure 
make 
make altinstall 
cd .. 
wget https://bootstrap.pypa.io/get-pip.py 
python3.3 get-pip.py 
git clone https://github.com/vergl4s/ipscraper 
pip3 install -r ipscraper/requirements.txt 
cp ipscraper/ipscraper.py /usr/bin/ 
echo python3.3 /usr/bin/ipscraper.py > /usr/bin/ipscraper 
chmod u+x /usr/bin/ipscraper```

###Usage example
```bash
ipscraper google.com 8.8.8.8 8.8.8.0/24
```
