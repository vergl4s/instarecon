#!/usr/bin/env python

"""
Module wraps all lookups done by InstaRecon and returns only results.

Raises log.NoInternetAccess.

"""

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
                return dns_resolver.query(target, 'MX')
            
            elif lookup_type == 'NS':
                return dns_resolver.query(target, 'NS')

        except dns_exceptions as e:
            log.error(lookup_type + ' DNS lookup failed for ' + target, sys._getframe().f_code.co_name)
            return ()

        except dns_timeout as e:
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

def whois_ip(ip):
    try:
         return ipw.IPWhois(ip).lookup() or None
    except ipw.WhoisLookupError as e:
        log.error(e, sys._getframe().f_code.co_name)

def shodan(ip):
    try:
        api = shodan_api.Shodan(shodan_key)
        return api.host(str(ip))
    except (socket.gaierror, shodan_api.client.APIError) as e:
        log.error(e, sys._getframe().f_code.co_name)

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

            lookup_result = reverse_dns(str(ip))
            if lookup_result:
                reverse_domains = [str(domain).rstrip('.') for domain in lookup_result]
                yield ip, reverse_domains

def google_linkedin_page(name):
    """
    Uses a google query to find a possible LinkedIn page related to name (usually self.domain)

    Google query is "site:linkedin.com/company name", and first result is used
    """
    request = 'http://google.com/search?hl=en&meta=&num=10&q=site:linkedin.com/company%20"' + name + '"'
    
    try:
        google_search = requests.get(request)
    except Exception as e:
        log.error(e, sys._getframe().f_code.co_name)
        raise log.NoInternetAccess
    
    google_results = re.findall('<cite>(.+?)<\/cite>', google_search.text)
    for url in google_results:
        if 'linkedin.com/company/' in url:
            return re.sub('<.*?>', '', url)

def google_subdomains(name):
    """
    This method uses google dorks to get as many subdomains from google as possible
    Returns a dictionary with key=str(subdomain), value=GoogleDomainResult object
    """

    google_results = {}
    results_in_last_iteration = -1

    while len(google_results) > results_in_last_iteration:

        time.sleep(randint(0, 4) + randint(0, 1000) * 0.001)

        # Make this funct keep iterating until there are new results
        results_in_last_iteration = len(google_results)

        #Order google_results by .count, as we want only the top 8 subs with more results
        list_of_sub_ordered_by_count = sorted(google_results, key = lambda sub: google_results[sub].count, reverse=True)

        google_results = _update_google_results(
            _google_subdomain_lookup(
                name,
                [sub for sub in list_of_sub_ordered_by_count if sub != name],
                100,
                0
            ),
            google_results
        )

        print 'len ordered', len(list_of_sub_ordered_by_count), 'len original', len(google_results)

        for sub in google_results:
            print sub,'-',str(google_results[sub].count)

    return google_results

def _update_google_results(new_google_results, results_dictionary):
    """Internal generator that manages multiple _google_subdomain_lookup"""
    for url in new_google_results:
        # Removing html tags from inside url (sometimes they use <b> or <i> for ads)
        url = re.sub('<.*?>', '', url)

        # Follows Javascript pattern of accessing URLs
        g_host = url
        g_protocol = ''
        g_pathname = ''

        temp = url.split('://')

        # If there is g_protocol e.g. http://, ftp://, etc
        if len(temp) > 1:
            g_protocol = temp[0]
            g_host = temp[1:]

        temp = ''.join(g_host).split('/')

        # if there is a pathname after host
        if len(temp) > 1:
            g_pathname = '/'.join(temp[1:])
            g_host = temp[0]

        results_dictionary.setdefault(g_host, GoogleDomainResult()).add_url(url)

    return results_dictionary

def _google_subdomain_lookup(domain, subs_to_avoid=(), num=100, counter=0):
    """
    Reaches out to google using the following query:
    site:*.domain -site:subdomain_to_avoid1 -site:subdomain_to_avoid2 -site:subdomain_to_avoid3...

    Returns list of unique subdomain strings
    """
    request = ''.join([
        'http://google.com/search?hl=en&meta=&num=',
        str(num),
        '&start=',
        str(counter),
        '&q=',
        'site%3A%2A',
        domain
    ])
    
    print 'Avoided subs:',subs_to_avoid[:8]

    if subs_to_avoid:
        for subdomain in subs_to_avoid[:8]:
            request = ''.join([request, '%20%2Dsite%3A', str(subdomain)])

    try:
        return re.findall('<cite>(.+?)<\/cite>', requests.get(request).text)
    except requests.ConnectionError as e:
        log.error(e, sys._getframe().f_code.co_name)
        raise log.NoInternetAccess


class GoogleDomainResult(object):
    """
    Holds Google results for each domain.

    Keyword arguments:
    urls -- Set of urls for this domain
    count -- Integer for how many times this was found in google
    """
    def __init__(self):
        self.urls = set()
        self.count = 0

    def add_url(self, url):
        self.urls.add(url)
        self.count += 1