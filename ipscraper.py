#!/usr/bin/env python
import sys
import socket
import argparse
import pprint
from abc import ABCMeta, abstractmethod

import pythonwhois as whois #http://cryto.net/pythonwhois/usage.html https://github.com/joepie91/python-whois
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
        self.whois_name = {}
        self.whois_ip = None


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
        try:
            return socket.gethostbyaddr(str(self.ip))
        except Exception as e:
            self.error(e,sys._getframe().f_code.co_name)
            pass

    def get_host_by_addr(self):
        try:
            if self.ip.is_private:
                return self.get_host_by_addr_socket()
            else:
                return ipw(str(self.ip)).get_host()[0]
        except Exception as e:
            self.error(e,sys._getframe().f_code.co_name)
            pass        

    def get_whois_name(self,name):
        try:
            #TODO do whois with the parent domain, not with subdomain
            if name:
                result_is_valid = False

                #makes whois query
                query = whois.get_whois(name)

                #this section treats the results

                result = {}

                for key, value in query.iteritems():
                    #Lists with strings
                    if key in ['id','status','nameservers','emails','registrar','whois_server']:
                        if value != None:
                            result[key] = ','.join(value)
                            result_is_valid = True


                    elif key in ['updated_date','expiration_date','creation_date']:
                        date = value[-1].strftime("%Y-%m-%d")
                        result[key] = date
                    
                    #Dict with registrant, tech, admin and billing
                    elif key in ['contacts']:
                        new_dict = {}
                        
                        for key2, val2 in value.iteritems():
                            if val2 != None:
                                new_dict[key2] = val2
                                result_is_valid = True

                        result[key]= new_dict

                if result_is_valid:
                    return result
                else:
                    #TODO subdomain - if result is not valid, maybe we are trying to query a subdomain?
                    pass
                
        except Exception as e:
            self.error(e,sys._getframe().f_code.co_name)
            pass

    def print_whois_name(self,num=0):
        try:
            result = ''
            for key,val in self.whois_name[self.names[0]].iteritems():
                #Improve, should print dicts right
                if type(val) in [dict]:
                    result = '\n\t'.join([result,key+': '+str(val)])
                else:    
                    result = '\n\t'.join([result,key+': '+val])
            
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

                    result['net'] = raw_result['nets'][-1] if raw_result['nets'] else None
                    result['parent_nets'] = raw_result['nets'][0:-1] if raw_result['nets'] else None

                    for key,val in result['net'].iteritems():
                        if key in ['address','description','tech_emails','abuse_emails',\
                                    'cidr','country','state','city','created','handle',\
                                    'misc_emails','name','postal_code','range']:
                            if val:
                                result['net_'+key] = result['net'][key].replace('\n',', ') if key in result['net'] and result['net'][key] else None


                    for key,val in raw_result.iteritems():
                        if key not in ['nets']:
                            if type(val) in [dict]:

                                new_dict = {}
                                
                                for key2, val2 in value.iteritems():
                                    if val2 != None:
                                        new_dict[key2] = val2
                                        result_is_valid = True

                                result[key] = new_dict

                            elif type(val) in [list]:
                                result[key] = raw_result[key] if raw_result[key] else None

                            else:
                                result[key] = raw_result[key].replace('\n',', ') if raw_result[key] else None

                return result if result else None

        except Exception as e:
            self.error(e,sys._getframe().f_code.co_name)
            pass

    def print_whois_ip(self):
        try:
            result = ''
            for key,val in self.whois_ip.iteritems():
                if key not in ['net', 'query'] and val:
                    if type(val) in [dict,list]:
                        result = '\n\t'.join([result,key+': '+str(val)]) #Improve, should print dicts right
                    else:    
                        result = '\n\t'.join([result,key+': '+val])
            
            return result

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

    def __str__(self):
        return str(self.ip)

    def get_id(self):
        return self.ip

    def resolve(self):
        self.rev_name = self.get_host_by_addr()
        self.whois_rev_name = self.get_whois_name(self.rev_name)
        self.whois_ip = self.get_whois_ip()


class Name(Host):
    '''Host object created from user entry as name.'''

    def __init__(self, user_supplied, ip_already_resolved):
        #ip_already_resolved is gathered in Scan.add_host() when checking for valid domains
        #is passed to this function because there is no reason to make the same request twice
        Host.__init__(self)
        self.names.append(user_supplied)
        self.ip = ip_already_resolved

    def __str__(self):
        return str(self.names[0])

    def get_id(self):
        return self.names[0]

    def resolve(self):
        #self.ip = ipa.ip_address(self.get_host_by_name())

        self.rev_name = self.get_host_by_addr()
        
        #self.whois_rev_name = self.get_whois_name(self.rev_name)
        self.whois_name[self.names[0]] = self.get_whois_name(self.names[0])
        self.whois_ip = self.get_whois_ip()


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

        # #dictionary that'll keep all IPWhois results saved for future use
        # self.whois_ip_results = {}

        #CIDRs that were gathered by each IPWhois lookup, will be used by secondary_scan()
        self.cidrs = set()


        #Will hold all results for secondary scan
        self.secondary_scan_results = {}
        #Will hold all results for reverse lookup done by secondary scan
        self.secondary_scan_results['rev_lookups'] = {}


    def populate(self, user_supplied_list, feedback=False):
        for user_supplied in user_supplied_list:
            self.add_host(user_supplied)

        if feedback:
            if len(scan.hosts)<1:
                print '[+] No hosts to scan'
            else:
                print '[+] Scanning',str(len(self.hosts))+'/'+str(len(user_supplied_list)),'hosts'

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
            print '[!] Error: Couldn\'t resolve', user_supplied
            pass

        self.bad_hosts.append(user_supplied)


    def direct_scan(self, feedback=False):
        #Consists of DNS and whois lookups on the target hosts

        if len(self.hosts)>0:

            if feedback: print '[+] Resolving, please wait'

            #TODO threading
            for host in self.hosts:
                
                host.resolve()

                if host.whois_ip:
                    if host.whois_ip['cidr']:
                        self.cidrs.add(host.whois_ip['cidr'])

                #TODO IO semaphore 
                if feedback:
                    pp =  pprint.PrettyPrinter()
                    print '\n[+] #### {} ####\n'.format(host.get_id())
                                
                    if len(host.names)>0:
                        print '[+] names:',host.names[0]
                    
                    print '[+] rev name:',host.rev_name
                    print '[+] ip:',host.ip
                    
                    if host.whois_name[host.names[0]]:
                        print '[+] whois_name:',host.print_whois_name()

                    if host.whois_ip:
                        print '[+] whois_ip:',host.print_whois_ip()


    def secondary_scan(self, feedback=False):
        #Tries to gather more information and make assumptions based 
        #on information grabbed by direct_scan
        
        if self.cidrs:

            if feedback: print '\n[+] Doing reverse DNS lookup of related network range(s) -',', '.join(s for s in scan.cidrs),'- please wait'

            #TODO threading
            for cidr in self.cidrs:
                net = ipa.ip_network(cidr.decode('unicode-escape'))
                for ip in net:
                    try:

                        rev = ipw(ip).get_host()[0]

                        self.secondary_scan_results['rev_lookups'][str(ip)] = rev
                        
                        #TODO IO semaphore
                        if feedback: print str(ip),rev

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
    
    scan.populate(targets,feedback=True)
    # for host in scan.hosts:
    #     print host, str(host)

    scan.direct_scan(feedback=True)

    if scan_type == 1:
        scan.secondary_scan(feedback=True)

                

