#!/usr/bin/env python
from random import randint
import re
import socket
import sys
import time

import dns.resolver
import dns.reversename
import ipaddress as ipa  # https://docs.python.org/3/library/ipaddress.html
import ipwhois as ipw  # https://pypi.python.org/pypi/ipwhois
import pythonwhois as whois  # http://cryto.net/pythonwhois/usage.html https://github.com/joepie91/python-whois
import requests
import shodan  as shodan_api# https://shodan.readthedocs.org/en/latest/index.html

import log

dns_resolver = dns.resolver.Resolver()
dns_resolver.timeout = 2
dns_resolver.lifetime = 2
dns_maximum_retries = 3
dns_exceptions = (
    dns.resolver.NoAnswer,
    dns.resolver.NXDOMAIN,
    dns.resolver.YXDOMAIN,
    dns.exception.SyntaxError,
)
dns_timeout = (dns.exception.Timeout)

shodan_key = None

def direct_dns(name):
    return dns_lookup_manager(name,'A')

def reverse_dns(ip):
    return dns_lookup_manager(ip,'PTR')

def mx_dns(name):
    return [str(mx.exchange).rstrip('.') for mx in dns_lookup_manager(name,'MX')]

def ns_dns(name):
    return [str(ns).rstrip('.') for ns in dns_lookup_manager(name,'NS')]

def dns_lookup_manager(target, lookup_type):
    tries=0
    while tries < dns_maximum_retries:
        try:

            if lookup_type == 'A':
                return dns_resolver.query(target)
            
            elif lookup_type == 'PTR':
                return dns_resolver.query(dns.reversename.from_address(target), 'PTR')
            
            elif lookup_type == 'MX':
                return  dns_resolver.query(target, 'MX')
            
            elif lookup_type == 'NS':
                return dns_resolver.query(target, 'NS')

        except dns_exceptions as e:
            log.error(lookup_type + ' DNS lookup failed for ' + target, sys._getframe().f_code.co_name)
            break

        except dns_timeout:
            tries += 1
            if tries < dns_maximum_retries:
                log.error('Timeout resolving ' + target + '. Retrying.', sys._getframe().f_code.co_name)
            else:
                log.error(str(dns_maximum_retries)+ ' timeouts resolving ' + target + '. Giving up.', sys._getframe().f_code.co_name)    
                raise log.NoInternetAccess

def whois_domain(name):
    try:
        query = whois.get_whois(name)
        if 'raw' in query:
            return query['raw'][0].split('<<<')[0].lstrip().rstrip()
    except socket.gaierror as e:
        log.error('Whois lookup failed for ' + name, sys._getframe().f_code.co_name)
        raise log.NoInternetAccess

def whois_ip(ip):
    try:
         return ipw.IPWhois(ip).lookup() or None
    except ipw.WhoisLookupError:
        log.error(e, sys._getframe().f_code.co_name)
        raise log.NoInternetAccess

def shodan(ip):
    try:
        api = shodan_api.Shodan(shodan_key)
        return api.host(str(ip))
    except (socket.gaierror, shodan_api.client.APIError) as e:
        log.error(e, sys._getframe().f_code.co_name)
        raise log.NoInternetAccess

def rev_dns_on_cidr(cidr):
    """
    Reverse DNS lookups on each IP within a CIDR. cidrneeds to be ipa.IPv4Networks.
    Yields valid ip, and then reverse_domains. Yields KeyboardInterrupt in case of KeyboardInterrupt.
    """
    if not isinstance(cidr, ipa.IPv4Network):
       raise ValueError
    else:
        for ip in cidr:
            lookup_result = None

            # Used to repeat same scan if user issues KeyboardInterrupt
            scan_completed = False
            while not scan_completed:
                try:

                    lookup_result = reverse_dns(str(ip))
                    if lookup_result:
                        reverse_domains = [str(domain).rstrip('.') for domain in lookup_result]
                        yield ip
                        yield reverse_domains

                    scan_completed = True

                except KeyboardInterrupt as e:
                    yield e

def google_linkedin_page(name):
    """
    Uses a google query to find a possible LinkedIn page related to name (usually self.domain)

    Google query is "site:linkedin.com/company name", and first result is used
    """
    try:
        request = 'http://google.com/search?hl=en&meta=&num=10&q=site:linkedin.com/company%20"' + name + '"'
        google_search = requests.get(request)
        google_results = re.findall('<cite>(.+?)<\/cite>', google_search.text)
        for url in google_results:
            if 'linkedin.com/company/' in url:
                return re.sub('<.*?>', '', url)
    except Exception as e:
        log.error(e, sys._getframe().f_code.co_name)
        raise log.NoInternetAccess

def google_subdomains(name):
    """
    This method uses google dorks to get as many subdomains from google as possible
    It returns a set of Hosts for each subdomain found in google
    Each Host will have dns_lookups() already callled, with possibly ips and rev_domains filled
    """
    def _google_subdomain_lookup(domain, subdomains_to_avoid, num, counter):
        """
        Sub method that reaches out to google using the following query:
        site:*.domain -site:subdomain_to_avoid1 -site:subdomain_to_avoid2 -site:subdomain_to_avoid3...

        Returns list of unique subdomain strings
        """
        request = 'http://google.com/search?hl=en&meta=&num=' + str(num) + '&start=' + str(counter) + '&q=' +\
            'site%3A%2A' + domain

        for subdomain in subdomains_to_avoid[:8]:
            # Don't want to remove original name from google query
            if subdomain != domain:
                request = ''.join([request, '%20%2Dsite%3A', str(subdomain)])

        # Sleep some time between 0 - 4.999 seconds
        time.sleep(randint(0, 4) + randint(0, 1000) * 0.001)
        
        google_search = None
        try:
            google_search = requests.get(request)
        except requests.ConnectionError as e:
            log.error(e, sys._getframe().f_code.co_name)

        new_subdomains = set()
        if google_search:
            google_results = re.findall('<cite>(.+?)<\/cite>', google_search.text)

            for url in set(google_results):
                # Removing html tags from inside url (sometimes they ise <b> or <i> for ads)
                url = re.sub('<.*?>', '', url)

                # Follows Javascript pattern of accessing URLs
                g_host = url
                g_protocol = ''
                g_pathname = ''

                temp = url.split('://')

                # If there is g_protocol e.g. http://, ftp://, etc
                if len(temp) > 1:
                    g_protocol = temp[0]
                    # remove g_protocol from url
                    url = ''.join(temp[1:])

                temp = url.split('/')
                # if there is a pathname after host
                if len(temp) > 1:

                    g_pathname = '/'.join(temp[1:])
                    g_host = temp[0]

                new_subdomains.add(g_host)

            # TODO do something with g_pathname and g_protocol
            # Currently not using protocol or pathname for anything
        return list(new_subdomains)

    # Keeps subdomains found by _google_subdomains_lookup
    subdomains_discovered = []
    # Variable to check if there is any new result in the last iteration
    subdomains_in_last_iteration = -1

    while len(subdomains_discovered) > subdomains_in_last_iteration:

        subdomains_in_last_iteration = len(subdomains_discovered)

        subdomains_discovered += _google_subdomain_lookup(name, subdomains_discovered, 100, 0)
        subdomains_discovered = list(set(subdomains_discovered))

    subdomains_discovered += _google_subdomain_lookup(name, subdomains_discovered, 100, 100)
    subdomains_discovered = list(set(subdomains_discovered))
    return subdomains_discovered

