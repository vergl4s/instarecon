#!/usr/bin/env python
import re
import sys

import dns.resolver
import dns.resolver
import dns.reversename
from ipwhois import IPWhois as ipw  # https://pypi.python.org/pypi/ipwhois
import pythonwhois as whois  # http://cryto.net/pythonwhois/usage.html https://github.com/joepie91/python-whois
import requests
import shodan  # https://shodan.readthedocs.org/en/latest/index.html

import log

dns_resolver = dns.resolver.Resolver()
dns_resolver.timeout = 5
dns_resolver.lifetime = 5
shodan_key = None

def direct_dns(name):
    try:
        return dns_resolver.query(name)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout) as e:
        log.raise_error('[-] Host lookup failed for ' + name, sys._getframe().f_code.co_name)

def reverse_dns(ip):
    try:
        return dns_resolver.query(dns.reversename.from_address(ip), 'PTR')
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout) as e:
        log.raise_error('[-] Host lookup failed for ' + ip, sys._getframe().f_code.co_name)

def mx_dns(name):
    try:
        # rdata.exchange for domains and rdata.preference for integer
        return [str(mx.exchange).rstrip('.') for mx in dns_resolver.query(name, 'MX')]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout) as e:
        log.raise_error('[-] MX lookup failed for ' + name, sys._getframe().f_code.co_name)

def ns_dns(name):
    try:
        # rdata.exchange for domains and rdata.preference for integer
        return [str(ns).rstrip('.') for ns in dns_resolver.query(name, 'NS')]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout) as e:
        log.raise_error('[-] NS lookup failed for ' + name, sys._getframe().f_code.co_name)

def whois_domain(name):
    try:
        return whois.get_whois(name)
    except Exception, e:
        log.raise_error('[-] NS lookup failed for ' + name, sys._getframe().f_code.co_name)

def whois_ip(ip):
    try:
         return ipw(ip).lookup() or None
    except Exception as e:
        log.raise_error(e, sys._getframe().f_code.co_name)

def shodan(ip):
    try:
        api = shodan.Shodan(shodan_key)
        return api.host(str(self))
    except Exception as e:
        log.raise_error(e, sys._getframe().f_code.co_name)    

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
        log.raise_error(e, sys._getframe().f_code.co_name)

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

        google_search = None
        try:
            google_search = requests.get(request)
        except Exception as e:
            Error.log(e, sys._getframe().f_code.co_name)

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

