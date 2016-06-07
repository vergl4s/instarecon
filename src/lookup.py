#!/usr/bin/env python

"""
Module wraps all lookups done by InstaRecon and returns results only.

Raises lookup.NoInternetAccess.

"""
import logging
from random import randint, choice
import re
import socket
import time

import dns.resolver
import dns.reversename
import ipaddress as ipa # https://docs.python.org/3/library/ipaddress.html
import ipwhois as ipw # https://pypi.python.org/pypi/ipwhois
import pythonwhois as whois # http://cryto.net/pythonwhois/usage.html https://github.com/joepie91/python-whois
import requests
import shodan  as shodan_api # https://shodan.readthedocs.org/en/latest/index.html

dns_resolver = dns.resolver.Resolver()
dns_resolver.timeout = 2
dns_resolver.lifetime = 2
dns_maximum_retries = 3
dns_exceptions = (
    dns.resolver.NoAnswer,
    dns.resolver.NXDOMAIN,
    dns.resolver.YXDOMAIN,
    dns.exception.SyntaxError,
    dns.resolver.NoNameservers
)

shodan_key = None

headers = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36',
}


def direct_dns(name):
    return dns_lookup_manager(name,'A') or None

def reverse_dns(ip, suppress_warning=False):
    return dns_lookup_manager(ip, 'PTR', suppress_warning) or None

def mx_dns(name):
    return [str(mx.exchange).rstrip('.') for mx in dns_lookup_manager(name,'MX')] or None

def ns_dns(name):
    return [str(ns).rstrip('.') for ns in dns_lookup_manager(name,'NS')] or None

def dns_lookup_manager(target, lookup_type, suppress_warning=False):
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
            message = lookup_type + ' lookup failed for ' + target + ' - ' + str(e.__class__.__name__)
            if not suppress_warning:
                logging.warning(message)
            else:
                logging.info(message)

            # Needs to be here, as otherwise while will continue trying to scan the same host
            return ()

        except dns.exception.Timeout as e:
            tries += 1
            if tries < dns_maximum_retries:
                logging.info('Timeout resolving ' + target + '. Retrying.')
            else:
                logging.info(str(dns_maximum_retries)+ ' timeouts resolving ' + target + '. Internet connection alright?')
                test_internet_connection()
                logging.warning(lookup_type + ' lookup failed for ' + target + ' - ' + str(e.__class__.__name__))
                return()

def whois_domain(name):
    try:
        query = whois.get_whois(name)
        if 'raw' in query:
            return query['raw'][0].split('<<<')[0].lstrip().rstrip().encode('utf-8')

    except socket.gaierror as e:
        logging.warning('Whois lookup failed for ' + name)

def whois_ip(ip):
    if ip_is_valid(ip):
        try:
            return ipw.IPWhois(ip).lookup_whois()

        except ipw.WhoisLookupError as e:
            raise KeyboardInterrupt

        except ipw.IPDefinedError as e:
            logging.warning(e)
    else:
        logging.warning('No Whois IP for ' + ip + ' as it doesn\'t seem to be an IP on the internet')

def shodan(ip):
    if ip_is_valid(ip):
        try:
            api = shodan_api.Shodan(shodan_key)
            return api.host(str(ip))
        
        except socket.gaierror as e:
            logging.warning('Shodan lookup failed for ' + ip)
        
        except shodan_api.exception.APIError as e:
            if e.value == u'Unable to connect to Shodan':
                raise KeyboardInterrupt
                # Other possible is 'No information available for that IP.' or 'Invalid API key'
            logging.warning(e)
    else:
        logging.warning('No Shodan for ' + ip + ' as it doesn\'t seem to be an IP on the internet')

def ip_is_valid(ip):
    ip = ipa.ip_address(unicode(ip))
    return not (
        ip.is_multicast or 
        ip.is_private or 
        ip.is_reserved or 
        ip.is_loopback or 
        ip.is_link_local or
        ip.is_unspecified
    )

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

            lookup_result = reverse_dns(str(ip), suppress_warning=True)
            if lookup_result:
                reverse_domains = [str(domain).rstrip('.') for domain in lookup_result]
                yield ip, reverse_domains

def google_linkedin_page(name):
    """
    Uses a google query to find a possible LinkedIn page related to name (usually self.domain)

    Google query is "site:linkedin.com/company name", and first result is used
    """
    request = 'http://google.com/search?num=10&q=site:linkedin.com/company%20"' + name + '"'
    
    try:
        google_search = requests.get(request)
        google_results = re.findall('<cite>(.+?)<\/cite>', google_search.text)
        for url in google_results:
            if 'linkedin.com/company/' in url:
                return re.sub('<.*?>', '', url)

    except requests.ConnectionError as e:
        logging.warning(e)
        test_internet_connection()

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

        logging.debug('New subdomain(s) found: ' + str(len(google_results)-len(list_of_sub_ordered_by_count)))
        [logging.debug(sub + ' - ' + str(google_results[sub].count)) for sub in sorted(google_results, key = lambda sub: google_results[sub].count, reverse=True)]

    logging.debug('Finished google lookups with '+str(len(google_results))+' subdomains discovered.')

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
            g_protocol = temp[0] + '://'
            g_host = temp[1:]
        else:
            g_protocol = 'http://'

        temp = ''.join(g_host).split('/')

        # if there is a pathname after host
        if len(temp) > 1:
            g_pathname = ''.join(['/', '/'.join(temp[1:])])
            g_host = temp[0]

        # if there is a port specified
        temp = g_host.split(':')
        if len(temp) > 1:
            g_host = temp[0]
            g_pathname = ''.join([':', temp[1], g_pathname])
            logging.debug('Found host ' + g_host + ' with port ' + temp[1] + '. New pathname is ' + g_pathname)

        results_dictionary.setdefault(g_host, GoogleDomainResult()).add_url(g_protocol, g_pathname)

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
        'site%3A%2A%2E',
        domain,
    ])
    
    logging.info('Subs removed from next query: ' + ', '.join(subs_to_avoid[:8]))

    if subs_to_avoid:
        for subdomain in subs_to_avoid[:8]:
            request = ''.join([request, '%20%2Dsite%3A', str(subdomain)])

    try:
        # Content within cite had url shortening features where '/.../' would appear in the middle of the url
        #return re.findall('<cite>(.+?)<\/cite>', requests.get(request).text)

        return re.findall('<h3 class\=\"r\"><a href=\"/url\?q\=(.+?)\&amp', requests.get(request).text)
        
    except requests.ConnectionError as e:
        logging.warning(e)
        test_internet_connection()

class GoogleDomainResult(object):
    """
    Holds Google results for each domain.

    Keyword arguments:
    urls -- dict with key=protocol value=set of pathnames of urls for this domain
            Example - {'http://':{'/','/home','/test/asd.html'}}
    count -- Integer for how many times this was found in google
    """
    def __init__(self):
        self.urls = {}
        self.count = 0

    def add_url(self, g_protocol, g_pathname):
        self.urls.setdefault(g_protocol, set()).add(g_pathname)
        self.count += 1

def test_internet_connection():
    '''
    Reaches out to public well known DNS servers to check if machine has internet access.
    This exists because sometimes you might get arbitraty timeouts as replies but have internet connection.

    Raises NoInternetAccess if the test fails.
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    possible_targets = [
        '8.8.8.8',
        '8.8.4.4',
        '139.130.4.5',
    ]
    try:
        target = choice(possible_targets)
        logging.info('Testing internet connection by trying to reach out to host ' + target)
        s.connect((target,53))
        s.close()
    except (socket.timeout, socket.error, socket.gaierror) as e:
        raise NoInternetAccess

class NoInternetAccess(Exception):
    pass