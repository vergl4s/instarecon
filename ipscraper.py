#!/usr/bin/env python

import sys, socket, argparse
from abc import ABCMeta, abstractmethod
import pythonwhois as whois #https://github.com/joepie91/python-whois
from ipwhois import IPWhois as ipw #https://pypi.python.org/pypi/ipwhois
import ipaddress as ipa #https://docs.python.org/3/library/ipaddress.html
import dns.resolver #http://www.dnspython.org/docs/1.12.0/



class Host(object):
    '''Abstract class for Host being scanned. IP and Name classes inherit from this.'''
    __metaclass__ = ABCMeta

    def __init__(self):

        self.ip = None
        self.names = []
        self.rev_name = None
        self.whois_rev_name = None
        self.whois_name = []
        self.whois_ip = None

        #import pygeoip #http://pygeoip.readthedocs.org/en/v0.3.2/index.html# and http://tech.marksblogg.com/ip-address-lookups-in-python.html
        #geo = pygeoip.GeoIP('/usr/share/GeoIP/GeoIP.dat')
        #and then run
        #print geo.country_code_by_addr(self.ip)

    @abstractmethod
    def resolve(self):
        """"Start scanning process for a Host."""
        pass

    def get_host_by_name(self):
        try:
            return str(dns.resolver.query(self.names[0])[0])
        except Exception as e:
            self.error(e,sys._getframe().f_code.co_name)
            pass

    def get_host_by_addr_socket(self):
        '''Return a triple (hostname, aliaslist, ipaddrlist) - https://docs.python.org/2/library/socket.html#socket.gethostbyaddr'''
        try:
            return socket.gethostbyaddr(str(self.ip))
        except Exception as e:
            self.error(e,sys._getframe().f_code.co_name)
            pass

    def get_host_by_addr(self):
        try:
            #TODO 
            if self.ip.is_private:
                return self.get_host_by_addr_socket()
            else:
                return ipw(str(self.ip)).get_host()[0]
        except Exception as e:
            self.error(e,sys._getframe().f_code.co_name)
            pass        

    def get_whois_by_name(self,name=''):
        try:
            if name:
                return Whois(whois.get_whois(name))
        except Exception as e:
            self.error(e,sys._getframe().f_code.co_name)
            pass

    def get_whois_by_ip(self):
        try:
            if not self.ip.is_private:
                return WhoisIP(ipw(str(self.ip)).lookup())
        except Exception as e:
            self.error(e,sys._getframe().f_code.co_name)
            pass

    def error(self, e, function_name):
        print '[!] Error:', str(e),'| function name:',function_name

class IP(Host):
    '''Host object created from user entry as IP address.'''

    def __init__(self, user_supplied, from_net=False):
        Host.__init__(self)
        self.ip = user_supplied
        self.from_net = from_net

    def get_id(self):
        return self.ip

    def resolve(self):
        self.rev_name = self.get_host_by_addr()
        self.whois_rev_name = self.get_whois_by_name(self.rev_name)
        self.whois_ip = self.get_whois_by_ip()


class Name(Host):
    '''Host object created from user entry as name.'''

    def __init__(self, user_supplied, ip_already_resolved):
        #ip_already_resolved is gathered in Scan.add_host() when checking for valid domains
        #is passed to this function because there is no reason to make the same request twice
        Host.__init__(self)
        self.names.append(user_supplied)
        self.ip = ip_already_resolved

    def get_id(self):
        return self.names[0]

    def resolve(self):
        #self.ip = ipa.ip_address(self.get_host_by_name())

        self.rev_name = self.get_host_by_addr()
        
        self.whois_rev_name = self.get_whois_by_name(self.rev_name)
        self.whois_name.append(self.get_whois_by_name(self.names[0]))
        self.whois_ip = self.get_whois_by_ip()

class Whois(object):
    
    def __init__(self,raw):
        
        if not raw:
            raise ValueError('No raw whois to instantiate object.')
        
        try:
            self.contacts = raw['contacts'] if 'contacts' in raw else None
            self.emails = raw['emails'] if 'emails' in raw else None
            self.status = raw['status'] if 'status' in raw else None
            self.nameservers = raw['nameservers'] if 'nameservers' in raw else None
            self.raw = raw['raw'] if 'raw' in raw else None
            self.registrar = raw['registrar'] if 'registrar' in raw else None
            self.updated_date = raw['updated_date'] if 'updated_date' in raw else None
            self.whois_server = raw['whois_server'] if 'whois_server' in raw else None
        except Exception as e:
            raise e

    def get_results(self):
        return '\n\tcontacts: {}\n\temails: {} \n\tnameservers: {} \n\tregistrar: {}'.format(self.contacts,self.emails,self.nameservers,self.registrar)


class WhoisIP(object):

    def __init__(self,raw):

        if not raw or not raw['nets'][-1]:
            raise ValueError('No raw whois to instantiate object.')

        try:

            self.net = raw['nets'][-1] if 'nets' in raw else None
            if self.net:
                self.parent_nets = raw['nets'][0:-1]            

                #TODO abstract this shit
                self.abuse_emails = self.net['abuse_emails'].replace('\n',', ') if 'abuse_emails' in self.net and self.net['abuse_emails'] else None                
                self.address = self.net['address'].replace('\n',', ') if 'address' in self.net and self.net['address'] else None
                self.description = self.net['description'].replace('\n',', ') if 'description' in self.net and self.net['description'] else None
                self.tech_emails = self.net['tech_emails'].replace('\n',', ') if 'tech_emails' in self.net and self.net['tech_emails'] else None

                self.cidr = self.net['cidr']
                self.country = self.net['country']
                self.state = self.net['state']
                self.city = self.net['city']          
                self.created = self.net['created']
                self.handle = self.net['handle']
                self.misc_emails = self.net['misc_emails']
                self.name = self.net['name']
                self.postal_code = self.net['postal_code']
                self.range = self.net['range']

        except Exception as e:
            raise e

    def get_results(self):
        if self.net:
            return '\n\tcidr: {}\n\trange: {}\n\tcountry: {}\n\tstate: {}\n\tcity: {}\n\taddress: {}\
                        \n\tdescription: {}\n\tabuse_emails: {}\n\ttech_emails: {}'.format(self.cidr,\
                        self.range,self.country, self.state,self.city,self.address,\
                        self.description,self.abuse_emails,self.tech_emails)

        else:
            return None


class Scan(object):
    '''Class that will hold all Host entries, manage threads and scanning pipeline.'''

    def __init__(self,server=None):

        self.dns_server = server
        if self.dns_server:
            #Set DNS server - TODO test this to make sure server is really being changed
            dns.resolver.override_system_resolver(self.dns_server)

        #Hosts that will be scanned
        self.hosts = []
        #Malformed hosts, or names that can't be resolved
        self.bad_hosts = []
        #Just a set that keeps the original values passed by the user; used for a quick search
        self.targets = set()

        #dictionary that'll keep all IPWhois results saved for future use
        self.whois_ip_results = {}

        #CIDRs that were gathered by each IPWhois lookup, will be used by secondary_scan()
        self.cidrs = set()


        #Will hold all results for secondary scan
        self.secondary_scan_results = {}
        #Will hold all results for reverse lookup done by secondary scan
        self.secondary_scan_results['rev_lookups'] = {}


    def populate(self, user_supplied_list):
        for user_supplied in user_supplied_list:
            self.add_host(user_supplied)

        return len(self.hosts)

    def add_host(self, user_supplied, from_net=False):

        host = None


        try:
            #Is it an IP?
            ip = ipa.ip_address(user_supplied.decode('unicode-escape'))
            if not (ip.is_multicast or ip.is_unspecified or ip.is_reserved or ip.is_loopback):

                self.hosts.append(IP(ip,from_net))
                return
            else:
                self.bad_hosts.append(user_supplied)
                return
        except Exception as e:
            #print e
            pass

        try:
            #Is it a valid network range?
            net = ipa.ip_network(user_supplied.decode('unicode-escape'))
            #IP is acceptable as a network, but has num_addresses = 1
            if net.num_addresses != 1:
                for ip in net:
                    scan.add_host(ip, True)
                return
            else:
                self.bad_hosts.append(user_supplied)
        except Exception as e:
            #print e
            pass


        try:
            #is it a valid DNS?
            ip = dns.resolver.query(user_supplied)[0]
            self.hosts.append(Name(user_supplied,ipa.ip_address(str(ip).decode('unicode-escape'))))
            return
        except Exception as e:
            print('[!] Error: Couldn\'t resolve', user_supplied)
            pass

        self.bad_hosts.append(user_supplied)

    def direct_scan(self, feedback=False):
        #Consists of DNS and whois lookups on the target hosts

        if len(self.hosts)>0:

            print '[+] Resolving, please wait'

            #TODO threading
            for host in self.hosts:
                
                host.resolve()

                if host.whois_ip:
                    if host.whois_ip.cidr:
                        self.cidrs.add(host.whois_ip.cidr)

                #TODO IO semaphore
                #TODO not print whois for 
                if feedback:
                    print '\n[+] #### {} ####\n'.format(host.get_id())
                    results = []
                    
                    if len(host.whois_name)>0:
                        print '[+] names:',host.names[0]
                    else:
                        print '[+] names: None'
                    
                    print '[+] rev name:',host.rev_name
                    print '[+] ip:',host.ip
                    
                    if len(host.whois_name)>0:
                        print '[+] whois_name:',host.whois_name[0].get_results()

                    if host.whois_ip:
                        print '[+] whois_ip:',host.whois_ip.get_results()

                    if host.rev_name and host.whois_rev_name:
                        print '[+] whois_rev_name:',host.whois_rev_name.get_results()

            pass 

    def secondary_scan(self, feedback=False):
        #Tries to gather more information and make assumptions based 
        #on information grabbed by direct_scan
        
        print '\n[+] Doing reverse DNS lookup of related network range(s) -',', '.join(s for s in scan.cidrs),'- please wait'

        #TODO threading
        for cidr in self.cidrs:
            net = ipa.ip_network(cidr.decode('unicode-escape'))
            for ip in net:
                try:

                    rev = ipw(ip).get_host()[0]

                    #TODO provide user feedback upon finding match
                    self.secondary_scan_results['rev_lookups'][str(ip)] = rev
                    
                    if feedback:
                        #TODO IO semaphore
                        print str(ip),rev

                except Exception as e:
                    pass


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='IP OSINT scraper')
    parser.add_argument('targets', nargs='+', help='targets')
    #parser.add_argument('-o', '--output', metavar='output', required=False, nargs='?', help='Output filename')
    parser.add_argument('-s', '--server', metavar='server', required=False, nargs=1,type=str,help='DNS server to use')
    parser.add_argument('-t','--scan_type',metavar='scan_type',required=False,nargs=1,default=[1],help='Scan type. (1 - full (default) | 2 - simplified)')
    args = parser.parse_args()
    
    targets = list(set(args.targets))
    scan_type = args.scan_type[0]

    scan = Scan(args.server)
    
    scan.populate(targets)

    print '[+] Scanning',str(len(scan.hosts))+'/'+str(len(targets)),'hosts'
    
    if len(scan.hosts)<1:
        print '[+] No hosts to scan'
    else:

        scan.direct_scan(True)

        if scan_type == 1:
            scan.secondary_scan(True)

                

