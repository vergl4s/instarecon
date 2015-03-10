#!/usr/bin/env python
import sys
import socket
import argparse
import requests
from abc import ABCMeta, abstractmethod
import re
import time
from random import randint

import pythonwhois as whois #http://cryto.net/pythonwhois/usage.html https://github.com/joepie91/python-whois
from ipwhois import IPWhois as ipw #https://pypi.python.org/pypi/ipwhois
import ipaddress as ipa #https://docs.python.org/3/library/ipaddress.html
import dns.resolver #http://www.dnspython.org/docs/1.12.0/
import shodan #https://shodan.readthedocs.org/en/latest/index.html

class Host(object):
    '''Abstract class for Host being scanned. IP and Name classes inherit from this.'''
    __metaclass__ = ABCMeta

    def __init__(self, feedback=True):
        #Print errorsr if True
        self.feedback = feedback
        #IP
        self.ip = None
        #Domains
        self.domains = []
        #Reverse DNS lookup for self.ip
        self.rev_domain = None
        #Whois results for names
        self.whois_domain = {}
        #Whois results for self.ip
        self.whois_ip = None
        #CIDR retrieved from whois_ip in get_specific_cidr()
        self.cidr = None 
        #Shodan lookup for self.ip
        self.shodan = None
        #Company LinkedIn page
        self.linkedin_page = None
        #Subdomains, found through google dorks
        #Keys are subdomains
        #values are dicts with protocol keys and pathname values
        self.subdomains = {}

    @abstractmethod
    def resolve(self):
        '''Start scanning process for a Host.'''
        pass

    def ret_host_by_name(self,name):
        try:
            return ipa.ip_address(str(dns.resolver.query(name)[0]).decode('unicode-escape'))
        except Exception as e:
            self.error(e,sys._getframe().f_code.co_name)
            pass

    def ret_host_by_addr_socket(self):
        try:
            return socket.gethostbyaddr(str(self.ip))
        except Exception as e:
            self.error(e,sys._getframe().f_code.co_name)
            pass

    def ret_host_by_addr(self):
        try:
            if self.ip.is_private:
                return self.ret_host_by_addr_socket()
            else:
                return ipw(str(self.ip)).get_host()[0]
        except Exception as e:
            self.error(e,sys._getframe().f_code.co_name)
            pass

    def get_ip(self):
        try:
            self.ip = self.ret_host_by_name(self.domains[0])
        except Exception as e:
            self.error(e,sys._getframe().f_code.co_name)
            pass        

    def get_rev_domain(self):
        try:
            self.rev_domain = self.ret_host_by_addr()
        except Exception as e:
            self.error(e,sys._getframe().f_code.co_name)
            pass

    def get_whois_domain(self,num=0):
        #http://cryto.net/pythonwhois/usage.html for fields

        try:
            result_is_valid = False

            #makes whois query
            query = whois.get_whois(self.domains[num])

            result = {}  
            for key, value in query.iteritems():
                #Lists with strings
                if key in ['id','status','nameservers','emails','registrar','whois_server']:
                    if value != None:
                        result_is_valid = True
                #Dates
                elif key in ['updated_date','expiration_date','creation_date']:
                    date = value[-1].strftime("%Y-%m-%d")
                    result[key] = date
                
                #Dict with registrant, tech, admin and billing
                elif key in ['contacts']:
                    for contact_key, contact_val in value.iteritems():
                        if contact_val != None:
                            result_is_valid = True

                elif key in ['raw']:
                    result[key] = value

            if result_is_valid:
                self.whois_domain[num] = result
                
        except Exception as e:
            self.error(e,sys._getframe().f_code.co_name)
            pass

    def print_whois_domain(self,num=0):
        try:
            if self.whois_domain[num]:
                if 'raw' in self.whois_domain[num] and len(self.whois_domain[num])>1:
                    return self.whois_domain[num]['raw'][0].lstrip().rstrip()
            return ''
        except Exception as e:
            self.error(e,sys._getframe().f_code.co_name)

        
    def get_whois_ip(self):
        try:
            if not self.ip.is_private:
                raw_result = ipw(str(self.ip)).lookup()
                
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
            self.shodan = api.host(self.ip)
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


    def get_linkedin_page(self):
        try:
            r = requests.get('http://ajax.googleapis.com/ajax/services/search/web?v=1.0&q=site:linkedin.com/company%20"'+self.domains[0]+'"').json()
            if 'responseData' in r and 'results' in r['responseData']:
                r = r['responseData']['results']
                if len(r)>0:
                    self.linkedin_page = r[0]['url']
        except Exception as e:
            self.error(e,sys._getframe().f_code.co_name)

    def get_subdomains_from_google(self):
        try:
            def google_lookup(self,num,counter,sleep_before=False):


                #Sleep some time between 0 - 4.999 seconds - maybe fools google?
                if sleep_before: time.sleep(randint(0,4)+randint(0,1000)*0.001)

                subdomains_to_remove = list(self.subdomains.keys())
                request = 'http://google.com/search?hl=en&meta=&num='+str(num)+'&start='+str(counter)+'&q='
                request = ''.join([request,'site%3A',self.domains[0]])

                for subdomain in self.subdomains.keys():
                    #Don't want to remove original name from google query
                    if subdomain != self.domains[0]:
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
                    if self.domains[0] in g_host:

                        if g_host not in self.subdomains:
                            self.subdomains[g_host] = {}
                            self.subdomains[g_host][g_protocol] = set()
                        
                        if g_protocol not in self.subdomains[g_host]:
                            self.subdomains[g_host][g_protocol] = set()
                           
                        if g_pathname: self.subdomains[g_host][g_protocol].add(g_pathname)
            

            #Variable to check if there is any new result in the last iteration
            subdomains_in_last_iteration = 0
            #Google 'start from' parameter
            counter = 0
            #Google number of responses
            num = 100
            
            google_lookup(self,num,counter)

            while len(self.subdomains) > subdomains_in_last_iteration:
                                
                subdomains_in_last_iteration = len(self.subdomains)
            
                google_lookup(self,num,counter,True)

            counter = 100
            google_lookup(self,num,counter,True)


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
        if self.whois_ip:
            cidrs = []
            num_addresses = 0
            specific_cidr = None

            for key in ['asn_cidr','net0_cidr','net1_cidr','net2_cidr','net3_cidr']:
                if key in self.whois_ip:
                    cidrs.append(ipa.ip_network(self.whois_ip[key].decode('unicode-escape'))) 

            for cidr in cidrs:
                if (cidr.num_addresses < num_addresses) or (num_addresses == 0):
                    specific_cidr = cidr
                    num_addresses = cidr.num_addresses

                #for biggest cidr do
                #if (cidr.num_addresses > num_addresses):
            self.cidr = specific_cidr

    def error(self, e, function_name):
        if self.feedback:
            print '# Error:', str(e),'| function name:',function_name

    def requests_header():
        pass

    # def old_get_whois_domain(self,num=0):
    #     '''
    #         Deprecated function. I gave up on trying to catalog the whois results.
    #         There are discrepancies in field names between top-level domains.
    #         As an example, fields names are slightly different between
    #         google.com, google.com.au, and google.co.nz even though values are the same
    #     '''

    #     #http://cryto.net/pythonwhois/usage.html for fields

    #     try:
    #         result_is_valid = False

    #         #makes whois query
    #         query = whois.get_whois(self.domains[num])


    #         result = {}
    #         for key, value in query.iteritems():
    #             #Lists with strings
    #             if key in ['id','status','nameservers','emails','registrar','whois_server']:
    #                 if value != None:
    #                     result[key] = ','.join(value)
    #                     result_is_valid = True

    #             #Dates
    #             elif key in ['updated_date','expiration_date','creation_date']:
    #                 date = value[-1].strftime("%Y-%m-%d")
    #                 result[key] = date
                
    #             #Dict with registrant, tech, admin and billing
    #             elif key in ['contacts']:
                    
    #                 new_dict = {}
                    
    #                 #keys are tech, admin, billing and registrant
    #                 #val are handle,name,organization,street,postalcode,city,state,country,email,phone,fax
    #                 for contact_key, contact_val in value.iteritems():
                        
    #                     if contact_val != None:

    #                         valid_contact_values = []
    #                         #Not saving 'handle'
    #                         for key3 in ['name','organization','street','postalcode','city','state','country','email','phone','fax']:
    #                             if key3 in contact_val:
    #                                 valid_contact_values.append(contact_val[key3])
                            
    #                         new_dict[contact_key] = ','.join(valid_contact_values)

    #                         result_is_valid = True

    #                 result[key]= new_dict

    #             elif key in ['raw']:
    #                 result[key] = value

    #         if result_is_valid:
    #             self.whois_domain[num] = result
    #         else:
    #             #If it is not valid, might be a subdomain
    #             pass
                
    #     except Exception as e:
    #         self.error(e,sys._getframe().f_code.co_name)
    #         pass

    # def old_print_whois_domain(self,num=0):
    #     '''Deprecacted function'''
    #     try:
    #         result = ''
    #         if self.whois_domain[num]:
    #             w = self.whois_domain[num]

    #             #if 'registrar' in 
                
    #             for key,val in self.whois_domain[num].iteritems():
                    
    #                 if key in ['contacts']:

    #                     # result = '\n'.join([result,'{}: '.format(key)])

    #                     for key2,val2 in val.iteritems():
    #                         result = '\n'.join([
    #                             result,
    #                             '{}: {}'.format('contact_'+key2,val2),
    #                             ])
    #                 else:
    #                     result = '\n'.join([
    #                         result,raw
    #                         '{}: {}'.format(key,str(val))
    #                         ])
                
    #             return result.lstrip().rstrip()

    #     except Exception as e:
    #         self.error(e,sys._getframe().f_code.co_name)
    #         pass


class IP(Host):
    '''Host object created from user entry as IP address.'''

    def __init__(self, user_supplied, from_net=False, name=None,feedback=True):
        Host.__init__(self,feedback)

        #If user supplied already converted into IP
        if isinstance(user_supplied,ipa.IPv4Address):
            self.ip = user_supplied
        else:
            #user_supplied must be string in this case
            self.ip = ipa.ip_address(user_supplied.decode('unicode-escape'))


        #will be none if not provided
        self.name = name
        #flag to separate ip derived from netrange - not used for anything so far
        self.from_net = from_net

    def __str__(self):
        return str(self.ip)

    def get_id(self):
        return self.ip

    def resolve(self):
        self.get_rev_domain()
        self.get_whois_ip()
        return self


class Name(Host):
    '''Host object created from user entry as name.'''

    def __init__(self, user_supplied, ip_already_resolved=None,feedback=True):
        #ip_already_resolved is gathered in Scan.add_host() when checking for valid domains
        #is passed to this __init__ because there is no reason to make the same request twice
        Host.__init__(self,feedback)

        self.domains.append(user_supplied)
        self.ip = ip_already_resolved if ip_already_resolved else self.ret_host_by_name(user_supplied)

    def __str__(self):
        return str(self.domains[0])

    def get_id(self):
        return self.domains[0]

    def resolve(self):
        self.get_ip()
        self.get_rev_domain()
        self.get_whois_domain()
        self.get_whois_ip()
        self.get_linkedin_page()
        return self


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

        # #CIDRs that were gathered by each IPWhois lookup, will be used by scan_cidrs()
        # self.cidrs = set()


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

                self.targets.append(IP(ip,from_net))
                return
            else:
                self.bad_targets.append(user_supplied)
                return
        except Exception as e:
            #print e
            pass

        #is it a valid network range?
        try:
            net = ipa.ip_network(user_supplied.decode('unicode-escape'))
            #IP is acceptable as a network, but has num_addresses = 1
            if net.num_addresses != 1:
                for ip in net:
                    scan.add_host(ip, True)
                return
            else:
                self.bad_targets.append(user_supplied)
        except Exception as e:
            #print e
            pass

        #is it a valid DNS?
        try:
            ip = dns.resolver.query(user_supplied)[0]
            self.targets.append(Name(user_supplied,ipa.ip_address(str(ip).decode('unicode-escape'))))
            return
        except Exception as e:
            print '# Error: Couldn\'t resolve', user_supplied
            pass

        self.bad_targets.append(user_supplied)


    def scan_targets(self):
        #Consists of DNS and whois lookups on the target hosts
        fb = self.feedback
        if len(self.targets)>0:

            for host in self.targets:
                
                if fb: print '\n____________________ Scanning {} ____________________\n'.format(host.get_id())
            

            ###DNS and Whois lookups###
                if fb: print '# Doing DNS/Whois lookups'

                host.resolve()

                if fb:  
                    if len(host.domains)>0:print '[-] Domain: '+host.domains[0]
                    if host.ip: print '[-] IP: '+str(host.ip)
                    if host.rev_domain: print '[-] Reverse domain: '+host.rev_domain

                    print ''

                    if len(host.whois_domain)>0:
                        print '[-] Whois domain:'+'\n'+host.print_whois_domain()+''
                    else:
                        print '# No domain whois. Maybe you\'re scanning a subdomain?'

                    if host.whois_ip:
                        print ''
                        print '[-] Whois IP:'+'\n'+host.print_whois_ip()
                    

            #Shodan lookup
                if self.shodan_key:
                    print ''
                    if fb: print '# Querying Shodan for open ports'
                    host.get_shodan(self.shodan_key)
                    if fb and host.shodan: print '[-] Shodan:'+'\n'+host.print_shodan()


            #Google subdomains lookup
                if fb:
                    print '' 
                    print '# Querying Google for subdomains, this might take a while'
                host.get_subdomains_from_google()
                if fb:
                    if host.subdomains:
                        print '[-] Subdomains:'+'\n'+host.print_subdomains()
                    if host.linkedin_page:
                        print ''
                        print '[-] Possible LinkedIn page: '+host.linkedin_page                     


    def scan_cidrs(self):
        #DNS lookups on entire CIDRs taken from host.get_whois_ip()
        fb = self.feedback
        
        if len(self.targets)>0:

            for host in self.targets:
        
                if fb: 
                    print ''
                    print '# Reverse DNS lookup on range ',host.cidr\
                            ,'(taken from '+host.get_id()+')'
                
                #', '.join(str(s) for s in scan.cidrs)

                for ip in host.cidr:
                    try:
                        secondary_target = IP(ip,feedback=False)
                        secondary_target.get_rev_domain()
                                                
                        
                        if secondary_target.rev_domain:
                            #add host to secondary list
                            self.secondary_targets.append(secondary_target)
                        
                            if fb: print secondary_target.ip,secondary_target.rev_domain

                    except Exception as e:
                        pass

            if len(self.secondary_targets) <= 0:
                if fb: print "# Done"


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='IP OSINT scraper')
    parser.add_argument('targets', nargs='+', help='targets')
    parser.add_argument('-d', '--dns_server', metavar='dns_server', required=False, nargs='?',help='DNS server to use')
    parser.add_argument('-a','--aggr',metavar='aggressiveness',required=False,nargs='?',default='1',help='1 - aggressive (default) | 2 - simplified')
    parser.add_argument('-s', '--shodan_key', metavar='shodan_key',required=False,nargs='?',help='Shodan key for automated lookups. To get one, simply register on https://www.shodan.io/.')
    args = parser.parse_args()

    targets = list(set(args.targets)) #removes duplicates

    scan = Scan(dns_server=args.dns_server,shodan_key=args.shodan_key,feedback=True) #instantiate Scan
    
    scan.populate(targets) #populate Scan with targets

    scan.scan_targets() #whois/dns/shodan lookups on targets

    if args.aggr == '1':
        #dns lookups on entire CIDRs that contain original targets
        scan.scan_cidrs()


#TODO
    
    #Other DNS entries eg MX etc
    #keyboard interrupt in secondary scan
    
    #Output csv? xml? excel?
    #dns lookups on subdomains
    #What to do with pathname details from google? - too many results sometimes
    #granularity on scan types
    

#Done

    
    #Fix output line breaks
    #whois for co.nz
    #Only accept subdomains that end in the main domain
    #Secondary scan output - say which target CIDR relates to
    #Style line that says ### Scanning target ###
    #improve printing whois domain results - using raw only
