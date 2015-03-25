#!/usr/bin/env python
import sys
import socket
import argparse
import requests
#from abc import ABCMeta, abstractmethod
import re
import time
from random import randint

import pythonwhois as whois #http://cryto.net/pythonwhois/usage.html https://github.com/joepie91/python-whois
from ipwhois import IPWhois as ipw #https://pypi.python.org/pypi/ipwhois
import ipaddress as ipa #https://docs.python.org/3/library/ipaddress.html
import dns.resolver,dns.reversename #http://www.dnspython.org/docs/1.12.0/
import shodan #https://shodan.readthedocs.org/en/latest/index.html


class Host(object):
    '''
    Host being scanned. 
    Contains several IP and Domain objects.
    '''

    def __init__(self,domain=None,ips=[],feedback=True):
        
        if ips and domain: #target is domain, but ip was already resolved by scan.add_host()
            self.type = 'domain'
        elif ips: #target is ip
            self.type = 'ip'
        elif domain: #target is domain
            self.type = 'domain'
        else:
            raise ValueError

        self.feedback = feedback

        #Single domain
        self.domain = domain
        
        #Multiple IPs
        self.ips = [ ip for ip in ips ] # if isinstance(user_supplied,ipa.IPv4Address):

        #Subdomains, found through google dorks and reverse cidr lookups
        #Contains multiple Domains
        self.subdomains = {} #TODO change to list of domains



        #WILL REMOVE THE FOLLOWING 
        
        #Whois results for self.ips
        self.whois_ip = None
        #CIDR retrieved from whois_ip in get_specific_cidr()
        self.cidr = None
        #Reverse domains for each IP in self.ips
        #key - IP | value - list of reverse domains
        self.rev_domains = {}

        #Shodan lookup for self.ip
        self.shodan = None

        #MX records - email servers
        #key - domain | value - list of ips
        self.mx = {}
        #NS records - DNS servers
        #key - domain | value - list of ips
        self.ns = {}

        #Whois results for names
        self.whois_domain = None


        #Company LinkedIn page
        self.linkedin_page = None

    def __str__(self):
        if self.type == 'domain':
            return str(self.domain)
        elif self.type == 'ip':
            return str(self.ips[0])

    def dns_lookups(self):
        if self.type == 'domain':
            self.get_ips()
            self.get_rev_domains()

        if self.type == 'ip':
            self.get_rev_domains()
        
        return self
    
    def whois_lookups(self):
        if self.type == 'domain':
            self.get_whois_domain()
            self.get_whois_ip()

        if self.type == 'ip':
            self.get_whois_ip()
            
        return self

    def error(self, e, function_name):
        if self.feedback:
            print '# Error:', str(e),'| function name:',function_name

    @staticmethod
    def _ret_host_by_name(name):
        return dns.resolver.query(name)
    
    @staticmethod
    def _ret_host_by_ip(ip):
        return dns.resolver.query(dns.reversename.from_address(ip),'PTR')

    @staticmethod
    def _ret_mx_by_name(name):
        #rdata.exchange for domains and rdata.preference for integer
        return [str(mx.exchange).rstrip('.') for mx in dns.resolver.query(name,'MX')]

    @staticmethod
    def _ret_ns_by_name(name):
        #rdata.exchange for domains and rdata.preference for integer
        return [str(ns).rstrip('.') for ns in dns.resolver.query(name,'NS')]
       

    def get_ips(self):
        try:
            if self.domain and not self.ips:
                ips = self._ret_host_by_name(self.domain)
                self.ips = [ ipa.ip_address(str(ip).decode('unicode-escape')) for ip in ips ]
        except Exception as e:
            self.error('Host lookup failed for '+self.domain,sys._getframe().f_code.co_name)
            pass        

    def get_rev_domains(self):
        try:
            if self.ips:
                for ip in self.ips:
                    rev_domains = ''
                    try:
                        rev_domains = self._ret_host_by_ip(str(ip))
                    except Exception, e:
                        #TODO only print if verbosity is set
                        self.error('Host lookup failed for '+ip,sys._getframe().f_code.co_name)

                    if rev_domains:
                        self.rev_domains[str(ip)] = []
                        for domain in rev_domains:
                            self.rev_domains[str(ip)].append(str(domain).rstrip('.'))

        except Exception as e:
            self.error(e,sys._getframe().f_code.co_name)
            pass

    def get_mx_records(self):
        try:
            if self.domain:
                mx_list = self._ret_mx_by_name(self.domain)
                for mx in mx_list:
                    self.mx.setdefault(mx,[str(d) for d in self._ret_host_by_name(mx)])
        except Exception, e:
            self.error('MX lookup failed for '+str(self.domain),sys._getframe().f_code.co_name)

    def get_ns_records(self):
        try:
            if self.domain:
                ns_list = self._ret_ns_by_name(self.domain)
                for ns in ns_list:
                    self.ns.setdefault(ns,[str(d) for d in self._ret_host_by_name(ns)])
        except Exception, e:
            #raise e
            self.error('NS lookup failed for '+str(self.domain),sys._getframe().f_code.co_name)


    def get_whois_domain(self,num=0):
        try:
            if self.domain:
                query = whois.get_whois(self.domain)
                
                if 'raw' in query:
                    self.whois_domain = query['raw'][0].lstrip().rstrip()

        except Exception as e:
            self.error(e,sys._getframe().f_code.co_name)
            pass
        
    def get_whois_ip(self):
        try:
            raw_result = ipw(str(self.ips[0])).lookup()
            
            result = {}

            if raw_result:
                if raw_result['nets']:
                    #get results from parent 'nets'
                    for index,net in enumerate(raw_result['nets']):
                        for key,val in net.iteritems():
                            if val:
                                result['net'+str(index)+'_'+key] = net[key].replace('\n',', ') \
                                    if key in net and net[key] else None

                #get all remaining results not in 'nets'
                for key,val in raw_result.iteritems():
                    if key not in ['nets','query']:
                        if type(val) in [dict]:

                            new_dict = {}
                            
                            for key2, val2 in value.iteritems():
                                if val2 != None:
                                    new_dict[key2] = val2
                                    result_is_valid = True

                            result[key] = new_dict

                        else:
                            if raw_result[key]:
                                result[key] = str(raw_result[key]).replace('\n',', ')
                                result_is_valid = True

            self.whois_ip = result
            #Get CIDR from whois_ip and save on self.cidr
            self.get_specific_cidr()

        except Exception as e:
            self.error(e,sys._getframe().f_code.co_name)
            pass

    def print_whois_ip(self):
        try:
            result = ''

            for key,val in sorted(self.whois_ip.iteritems()):
                if val:
                    
                    if type(val) in [dict]:
                        for key2,val2 in val.iteritems():
                            result = '\n'.join([result,key+': '+str(val)]) #Improve, should print dicts right
                    
                    else:
                        result = '\n'.join([result,key+': '+str(val)])
            
            return result.lstrip().rstrip()

        except Exception as e:
            self.error(e,sys._getframe().f_code.co_name)
            pass


    def get_shodan(self, key):
        try:
            shodan_api_key = key
            api = shodan.Shodan(shodan_api_key)
            #TODO IPs
            self.shodan = api.host(self.ips[0])
        except Exception as e:
            self.error(e,sys._getframe().f_code.co_name)
        
    def print_shodan(self):
        try:
            if self.shodan:

                result = ''.join(['Organization: ',self.shodan.get('org','n/a')])

                if self.shodan.get('os','n/a'):
                    result = '\n'.join([result,'OS: ',self.shodan.get('os','n/a')])

                if len(self.shodan['data']) > 0:
                    #result='\n'.join([result,'Services: '])
                    for item in self.shodan['data']:
                        result = '\n'.join([
                            
                            result,
                            'Port: {}'.format(item['port']),
                            'Banner: {}'.format(item['data'].replace('\n','\n\t').rstrip()),

                            ])

                return result

        except Exception as e:
            self.error(e,sys._getframe().f_code.co_name)

    @staticmethod
    def _get_linkedin_page(name):
        try:
            request='http://google.com/search?hl=en&meta=&num=10&q=site:linkedin.com/company%20"'+name+'"'
            google_search = requests.get(request)
            google_results = re.findall('<cite>(.+?)<\/cite>', google_search.text)
            for url in google_results:
                if 'linkedin.com/company/' in url:
                    return re.sub('<.*?>', '', url)
                    
        except Exception as e:
            self.error(e,sys._getframe().f_code.co_name)

    def _subdomains_google_lookup(self,num,counter,sleep_before=False):

        #Sleep some time between 0 - 2.999 seconds - maybe fools google?
        if sleep_before: time.sleep(randint(0,2)+randint(0,1000)*0.001)

        subdomains_to_remove = list(self.subdomains.keys())
        request = 'http://google.com/search?hl=en&meta=&num='+str(num)+'&start='+str(counter)+'&q='
        request = ''.join([request,'site%3A%2A',self.domain])

        for subdomain in self.subdomains.keys():
            #Don't want to remove original name from google query
            if subdomain != self.domain:
                request = ''.join([request,'%20%2Dsite%3A',subdomain])


        google_search = requests.get(request)
        #print request,'\n',google_search

        google_results = re.findall('<cite>(.+?)<\/cite>', google_search.text)


        for url in google_results:
            g_host = url
            g_protocol = ''
            g_pathname = ''

            temp = url.split('://')

            #If there is g_protocol e.g. http://, ftp://, etc
            if len(temp)>1:
                g_protocol = temp[0]
                #remove g_protocol from url
                url = ''.join(temp[1:])

            temp = url.split('/')
            #if there is a pathname after host
            if len(temp)>1:

                g_pathname = '/'.join(temp[1:])
                g_host = temp[0]


            #if domain in subdomain (to make sure it is a subdomain)
            if self.domain in g_host:

                if g_host not in self.subdomains:
                    self.subdomains[g_host] = {}
                    self.subdomains[g_host][g_protocol] = set()
                
                if g_protocol not in self.subdomains[g_host]:
                    self.subdomains[g_host][g_protocol] = set()
                   
                if g_pathname: self.subdomains[g_host][g_protocol].add(g_pathname)

    def google_lookups(self):
        try:
            if len(self.domain)>0:

                #Get Linkedin page
                self.linkedin_page = self._get_linkedin_page(self.domain)

                #Variable to check if there is any new result in the last iteration
                subdomains_in_last_iteration = 0
                #Google 'start from' parameter
                counter = 0
                #Google number of responses
                num = 100
                
                self._subdomains_google_lookup(num,counter,True)

                while len(self.subdomains) > subdomains_in_last_iteration:
                                    
                    subdomains_in_last_iteration = len(self.subdomains)
                
                    self._subdomains_google_lookup(num,counter,True)

                counter = 100
                self._subdomains_google_lookup(num,counter,True)

        except Exception as e:
            self.error(e,sys._getframe().f_code.co_name)

    def print_subdomains(self):
        try:
            result = ''
            for subdomain,value in sorted(self.subdomains.iteritems()):
                if subdomain: result = ''.join([result,subdomain,'\n'])

            return result.lstrip().rstrip()

        except Exception as e:
            self.error(e,sys._getframe().f_code.co_name)

    def print_subdomains_verbose(self):
        try:
            result = ''
            for subdomain,value in sorted(self.subdomains.iteritems()):
                result = ''.join([result,subdomain,'\n'])
                for protocol,value2 in value.iteritems():
                    if len(value2)>0: 
                        #result = ''.join([result,'\t',protocol,'','\n'])
                        for pathname in value2:
                            if pathname: 
                                result = ''.join([result,'\t'])
                                if protocol: result = ''.join([result,protocol,'://'])
                                result = ''.join([result,subdomain,'/',pathname,'\n'])

            result = ''.join([result,'\n'])    

            return result.rstrip()

        except Exception as e:
            self.error(e,sys._getframe().f_code.co_name)


    def get_specific_cidr(self):
        try:
            if self.whois_ip:
                cidrs = []
                num_addresses = 0
                specific_cidr = None

                for key in ['asn_cidr','net0_cidr','net1_cidr','net2_cidr','net3_cidr']:
                    if key in self.whois_ip:
                        
                        #Internal try catch in case some of the CIDR fields is 'NA' (e.g. 7.7.7.7)
                        try:
                            cidrs.append(ipa.ip_network(self.whois_ip[key].decode('unicode-escape'))) 
                        except Exception as e:
                            
                            pass
                        
                for cidr in cidrs:
                    if (cidr.num_addresses < num_addresses) or (num_addresses == 0):
                        specific_cidr = cidr
                        num_addresses = cidr.num_addresses

                    #for biggest cidr do
                    #if (cidr.num_addresses > num_addresses):
                self.cidr = specific_cidr   

        except Exception as e:
            self.error(e,sys._getframe().f_code.co_name)



class IP(Host):
    '''

    '''
    def __init__(self,ip):

        #Whois results for self.ips
        self.whois_ip = None
        #CIDR retrieved from whois_ip in get_specific_cidr()
        self.cidr = None
        #Reverse domains for each IP in self.ips
        #key - IP | value - list of reverse domains
        self.rev_domains = {}

        #Shodan lookup for self.ip
        self.shodan = None


class Domain(Host):
    '''

    '''

    def __init__(self,domain):

        self.domain = domain

        #MX records - email servers
        #key - domain | value - list of ips
        self.mx = {}
        #NS records - DNS servers
        #key - domain | value - list of ips
        self.ns = {}

        #Whois results for names
        self.whois_domain = None


        #Company LinkedIn page
        self.linkedin_page = None


class Scan(object):
    '''Class that will hold all Host entries, manage scans, threads and output.'''

    def __init__(self,dns_server=None,shodan_key=None,feedback=False):

        self.dns_server = dns_server
        if self.dns_server:
            #Set DNS server - TODO test this to make sure server is really being changed
            dns.resolver.override_system_resolver(self.dns_server)

        #Shodan API key
        self.shodan_key = shodan_key

        #Print stuff or not
        self.feedback = feedback

        #Targets that will be scanned
        self.targets = []
        #Malformed targets, or names that can't be resolved
        self.bad_targets = []
        #Secondary targets, deducted from CIDRs and other relations
        self.secondary_targets = []


    def populate(self, user_supplied_list):
        for user_supplied in user_supplied_list:
            self.add_host(user_supplied)

        if self.feedback:
            if len(self.targets)<1:
                print '# No hosts to scan'
            else:
                print '# Scanning',str(len(self.targets))+'/'+str(len(user_supplied_list)),'hosts'

                if not self.shodan_key:
                    print '# No Shodan key provided'
                else:
                    print'# Shodan key provided -',self.shodan_key


    def add_host(self, user_supplied, from_net=False):

        host = None

        #is it an IP?
        try:
            ip = ipa.ip_address(user_supplied.decode('unicode-escape'))
            if not (ip.is_multicast or ip.is_unspecified or ip.is_reserved or ip.is_loopback):
                self.targets.append(Host(ips=[str(ip)]))
                return
            else:
                self.bad_targets.append(user_supplied)
                return
        except Exception as e:
            #print e
            pass

        #is it a valid network range?
        try:
            net = ipa.ip_network(user_supplied.decode('unicode-escape'),strict=False)
            if net.prefixlen < 16:
                print '# Error: Not a good idea to scan anything bigger than a /16 is it?', user_supplied
            else:
                for ip in net:
                    self.add_host(str(ip), True)
                return
                
        except Exception as e:
            #print e,type(e)
            pass

        #is it a valid DNS?
        try:
            pass
            domain = user_supplied
            ips = dns.resolver.query(user_supplied)
            self.targets.append(Host(domain=domain,ips=[str(ip) for ip in ips]))
            return
        except Exception as e:
            #If here so results from network won't be so verbose
            if not from_net:
                print '# Error: Couldn\'t resolve or understand', user_supplied
            pass

        self.bad_targets.append(user_supplied)


    def scan_targets(self):
        #Consists of DNS and whois lookups on the target hosts
        fb = self.feedback
        if len(self.targets)>0:

            for host in self.targets:
                
                if fb: print '\n____________________ Scanning {} ____________________\n'.format(str(host))
            

            ###DNS and Whois lookups###
                if fb: print '# Doing DNS/Whois lookups'

                host.dns_lookups()
                if fb:
                    if host.domain:
                        print ''
                        print '[*] Domain: '+host.domain
                    
                    #IPs and reverse domains
                    if host.ips: 
                        print ''
                        print '[*] IPs & reverse DNS: '# if len(host.ips)<2 else '[*] IPs/reverse domains: '
                        
                        for ip in host.ips:    
                            ip = str(ip)
                            if host.rev_domains and ip in host.rev_domains:
                                print ip + ' - ' + ', '.join(host.rev_domains[ip])
                            else:
                                print ip
                    
                    
                host.get_ns_records()
                #NS records
                if host.ns and fb:
                    print ''
                    print '[*] NS records:'
                    for ns_name,ns_ips in host.ns.iteritems():
                        if ns_ips: 
                            print ns_name  + ' - ' + ', '.join(ns_ips)
                        else:
                            print ns_name
                    
                host.get_mx_records()
                #MX records
                if host.mx and fb:
                    print ''
                    print '[*] MX records:'
                    for mx_name,mx_ips in host.mx.iteritems():
                        if mx_ips:
                            print mx_name + ' - ' + ', '.join(mx_ips)
                        else:
                            print mx_name


                host.whois_lookups()
                if host.whois_domain and fb:
                    print '' 
                    print '[*] Whois domain:'+'\n'+host.whois_domain

                if host.whois_ip and fb:
                    print ''
                    print '[*] Whois IP:'+'\n'+host.print_whois_ip()


            #Shodan lookup
                if self.shodan_key:
                    print ''
                    if fb: print '# Querying Shodan for open ports'
                    host.get_shodan(self.shodan_key)
                    if fb and host.shodan: print '[*] Shodan:'+'\n'+host.print_shodan()


            #Google subdomains lookup
                if host.domain:
                    if fb:
                        print '' 
                        print '# Querying Google for subdomains and Linkedin pages, this might take a while'
                    host.google_lookups()
                    
                    if fb:
                        if host.linkedin_page:
                            print ''
                            print '[*] Possible LinkedIn page: '+host.linkedin_page

                        if host.subdomains:
                            print ''
                            print '[*] Subdomains:'+'\n'+host.print_subdomains()


    def scan_cidrs(self):
        #DNS lookups on entire CIDRs taken from host.get_whois_ip()
        fb = self.feedback
        
        if len(self.targets)>0:

            for host in self.targets:
        
                if fb:
                    print ''
                    print '# Reverse DNS lookup on range '+str(host.cidr)\
                            +' (taken from '+str(host)+')'
                
                for ip in host.cidr:
                    secondary_target = IP(ip,feedback=False)
                    secondary_target.get_rev_domains()
                                            
                    
                    if secondary_target.rev_domains:

                        self.secondary_targets.append(secondary_target)
                    
                        if fb: print secondary_target.ip,secondary_target.rev_domains

            if fb: print "# Done"


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='InstaRecon')
    parser.add_argument('targets', nargs='+', help='targets')
    parser.add_argument('-d', '--dns_server', metavar='dns_server', required=False, nargs='?',help='DNS server to use')
    parser.add_argument('-s', '--shodan_key', metavar='shodan_key',required=False,nargs='?',help='Shodan key for automated lookups. To get one, simply register on https://www.shodan.io/.')
    args = parser.parse_args()

    targets = list(set(args.targets)) #removes duplicates
    
    #instantiate Scan
    scan = Scan(
        dns_server=args.dns_server,
        shodan_key=args.shodan_key,
        feedback=True
        ) 
    
    scan.populate(targets) #populate Scan with targets

    scan.scan_targets() #whois/dns/shodan lookups on targets

    #scan.scan_cidrs() #dns lookups on entire CIDRs that contain original targets
    


#TODO

    #save google results as Hosts within hosts, create field for pathnames
    
    #dns lookups on google subdomains
    
    #keyboard interrupt in secondary scan
    
    #index whois_ip results so won't have to repeat the same request

    #Output csv?
    
    #What to do with pathname details from google? - too many results sometimes

    #verbosity flag to print all errors

    #granularity in scanning - #recude verbosity when doing only reverse lookups
    
