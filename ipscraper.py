#!/usr/bin/env python
import sys
import socket
import argparse
import requests
from abc import ABCMeta, abstractmethod

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
        #Subdomains, mainly found through google dorks
        self.subdomains = []
        #Reverse DNS lookup for self.ip
        self.rev_name = None
        #Whois results for names
        self.whois_domain = {}
        #Whois results for self.ip
        self.whois_ip = None
        #Shodan lookup for self.ip
        self.shodan = None
        #Company LinkedIn page
        self.linkedin_page = None

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

    def get_rev_name(self):
        try:
            self.rev_name = self.ret_host_by_addr()
        except Exception as e:
            self.error(e,sys._getframe().f_code.co_name)
            pass

    def get_whois_domain(self,name):
        try:
            #TODO do whois with the parent domain, not with subdomain
            if name:
                result_is_valid = False

                #makes whois query
                query = whois.get_whois(name)


                result = {}
                for key, value in query.iteritems():
                    #Lists with strings
                    if key in ['id','status','nameservers','emails','registrar','whois_server']:
                        if value != None:
                            result[key] = ','.join(value)
                            result_is_valid = True

                    #Dates
                    elif key in ['updated_date','expiration_date','creation_date']:
                        date = value[-1].strftime("%Y-%m-%d")
                        result[key] = date
                    
                    #Dict with registrant, tech, admin and billing
                    elif key in ['contacts']:
                        new_dict = {}
                        
                        #keys are tech, admin, billing and registrant
                        #val are handle,name,organization,street,postalcode,city,state,country,email,phone,fax
                        for contact_key, contact_val in value.iteritems():
                            
                            if contact_val != None:

                                valid_contact_values = []
                                for key3 in ['handle','name','organization','street','postalcode','city','state','country','email','phone','fax']:
                                    if key3 in contact_val:
                                        valid_contact_values.append(contact_val[key3])
                                
                                new_dict[contact_key] = ','.join(valid_contact_values)

                                result_is_valid = True

                        result[key]= new_dict

                if result_is_valid:
                    self.whois_domain[name] = result
                else:
                    pass
                
        except Exception as e:
            self.error(e,sys._getframe().f_code.co_name)
            pass

    def print_whois_domain(self,num=0):
        try:
            result = ''
            
            for key,val in self.whois_domain[self.domains[num]].iteritems():
                
                #Improve, should print dicts right
                if type(val) in [dict]:

                    result = '\n\t'.join([result,'{}: '.format(key)])

                    for key2,val2 in val.iteritems():
                        result = '\n\t'.join([
                            result,
                            '\t{}: {}'.format(key2,val2),
                            ])
                else:
                    result = '\n\t'.join([
                        result,
                        '{}: {}'.format(key,str(val))
                        ])
            
            return result

        except Exception as e:
            self.error(e,sys._getframe().f_code.co_name)
            pass


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
                   
                    # #'nets' value in raw_results contains specific value for networks related
                    # #to the scanned IP. goes from less specific to most specific, 
                    # #e.g. parent isp that assigns IPs to clients
                    # valid_net_keys = ['address','description','tech_emails','abuse_emails',\
                    #                 'cidr','country','state','city','created','handle',\
                    #                 'misc_emails','name','postal_code','range']

                    # if raw_result['nets']:
                    #     net = raw_result['nets'][-1]
                    #     #get results from last 'net' - most specific one
                    #     for key,val in net.iteritems():
                    #         if key in valid_net_keys:
                    #             if val:
                    #                 result['net_'+key] = net[key].replace('\n',', ') \
                    #                     if key in net and net[key] else None

                    #     #get results from parent 'nets'
                    #     for index,net in enumerate(raw_result['nets'][0:-1]):
                    #         for key,val in net.iteritems():
                    #             if key in valid_net_keys:
                    #                 if val:
                    #                     result['parent_net_'+str(index)+'_'+key] = net[key].replace('\n',', ') \
                    #                         if key in net and net[key] else None

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
                            result = '\n\t'.join([result,key+': '+str(val)]) #Improve, should print dicts right
                    
                    else:
                        result = '\n\t'.join([result,key+': '+str(val)])
            
            return result

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
                result = ''

                result = '\n\t'.join([
                    
                    result,
                    '{}: {}'.format('Organization',self.shodan.get('org','n/a')),
                    '{}: {}'.format('OS',self.shodan.get('os','n/a')),
                    'Services: '

                        ])

                for item in self.shodan['data']:
                    result = '\n\t\t'.join([
                        
                        result,
                        'Port: {}'.format(item['port']),
                        'Banner: {}'.format(item['data'].replace('\n','\n\t\t\t')), #TODO remove trailing whitespaces

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
            r = requests.get('http://ajax.googleapis.com/ajax/services/search/web?v=1.0&q=site:'+self.domains[0]).json()
            
            if 'responseData' in r and 'results' in r['responseData']:
                r = r['responseData']['results']
                if len(r)>0:
                    for result in r:
                        self.subdomains.append(r[0]['url'])
                    print self.subdomains

        except Exception as e:
            self.error(e,sys._getframe().f_code.co_name)        

    def ret_specific_cidr(self):
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

            return specific_cidr


    def error(self, e, function_name):
        if self.feedback:
            print '[!] Error:', str(e),'| function name:',function_name


class IP(Host):
    '''Host object created from user entry as IP address.'''

    def __init__(self, user_supplied, from_net=False, name=None,feedback=True):
        Host.__init__(self,feedback)

        self.ip = user_supplied
        #will be none if not provided
        self.name = name
        #flag to separate ip derived from netrange - not used for anything so far
        self.from_net = from_net

    def __str__(self):
        return str(self.ip)

    def get_id(self):
        return self.ip

    def resolve(self):
        self.get_rev_name()
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
        self.get_rev_name()
        self.get_whois_domain(self.domains[0])
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

        #CIDRs that were gathered by each IPWhois lookup, will be used by scan_secondary_targets()
        self.cidrs = set()


    def populate(self, user_supplied_list):
        for user_supplied in user_supplied_list:
            self.add_host(user_supplied)

        if self.feedback:
            if len(self.targets)<1:
                print '[+] No hosts to scan'
            else:
                print '[+] Scanning',str(len(self.targets))+'/'+str(len(user_supplied_list)),'hosts'

                if not self.shodan_key:
                    print '[+] No Shodan key provided'
                else:
                    print'[+] Shodan key provided -',self.shodan_key


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
            print '[!] Error: Couldn\'t resolve', user_supplied
            pass

        self.bad_targets.append(user_supplied)


    def scan_targets(self):
        #Consists of DNS and whois lookups on the target hosts
        fb = self.feedback
        if len(self.targets)>0:

            if fb: print '[+] Resolving, please wait'

            #TODO threading
            for host in self.targets:
                
                #DNS and Whois lookups
                host.resolve()
                
                #Shodan lookup
                if self.shodan_key:
                    host.get_shodan(self.shodan_key)

                #If whois_ip is valid, record CIDR in Scan object for future use
                if host.whois_ip:
                    self.cidrs.add(host.ret_specific_cidr())

                ####### Feedback section #######
                if fb:
                    print '\n[+] #### {} ####\n'.format(host.get_id())
                                
                    if len(host.domains)>0:
                        print '[+] Domains:',host.domains[0]
                    
                    print '[+] IP:',host.ip

                    if host.rev_name: print '[+] rev name:',host.rev_name

                    if host.linkedin_page:
                        print '[+] Possible LinkedIn page:',host.linkedin_page

                    if host.whois_domain:
                        if host.whois_domain[host.domains[0]]:
                            print '[+] whois_domain:',host.print_whois_domain()
                    else:
                        print '[!] No domain whois. Maybe you\'re scanning a subdomain?'

                    if host.whois_ip:
                        print '[+] whois_ip:',host.print_whois_ip()



                    if host.shodan:
                        print '[+] shodan:',host.print_shodan()


    def scan_secondary_targets(self):
        #Tries to gather more information and make assumptions based 
        #on information grabbed by scan_targets
        fb = self.feedback

        if self.cidrs:
            if fb: print '\n[+] Doing reverse DNS lookup of related network range(s) -',', '.join(str(s) for s in scan.cidrs),'- please wait'

            #TODO threading
            for cidr in self.cidrs:
                for ip in cidr:
                    try:

                        secondary_target = Name(ipw(ip).get_host()[0],ip,feedback=False)
                        
                        # try:
                        #     if self.shodan_key:
                        #         secondary_target.get_shodan(self.shodan_key)
                        # except Exception as e:
                        #     pass
                        
                        #add host to secondary list
                        self.secondary_targets.append(secondary_target)
                        

                        if fb: print secondary_target.ip,\
                                        secondary_target.names[0]
                                        # 'OS: '+secondary_target.shodan.get('os','n/a'),\
                                        # 'Ports: '+'{} '.format([item['port'] for item in self.shodan['data']])

                    except Exception as e:
                        pass

            if len(self.secondary_targets) <= 0:
                if fb: print "[+} No secondary targets found."


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='IP OSINT scraper')
    parser.add_argument('targets', nargs='+', help='targets')
    parser.add_argument('-d', '--dns_server', metavar='dns_server', required=False, nargs='?',help='DNS server to use')
    parser.add_argument('-a','--aggr',metavar='aggressiveness',required=False,nargs='?',default='1',help='1 - mad (default) | 2 - simplified')
    parser.add_argument('-s', '--shodan_key', metavar='shodan_key',required=False,nargs='?',help='Shodan key for automated lookups. To get one, simply register on https://www.shodan.io/.')
    args = parser.parse_args()

    targets = list(set(args.targets)) #removes duplicates

    scan = Scan(dns_server=args.dns_server,shodan_key=args.shodan_key,feedback=True) #instantiate Scan
    
    scan.populate(targets) #populate Scan with targets

    scan.scan_targets() #whois/dns/shodan lookups on targets

    if args.aggr == '1':

        #dns/shodan lookups on secondary IPs (taken from CIDRs)
        scan.scan_secondary_targets() 

                
#Google dorks to find subdomains? site:pwc.com.au  -www.pwc.com.au -www.digitalinnovation.pwc.com.au -melbournecup.pwc.com.au -www.digitalpulse.pwc.com.au -analyticsmaturity.pwc.com.au -ipower.pwc.com.au -myportal.pwc.com.au
#Output excel? xml? csv?
#Fix output indentation
