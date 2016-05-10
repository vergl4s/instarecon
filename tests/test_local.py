#!/usr/bin/env python
import itertools
import logging
import os
import random
import sys
import unittest

import ipaddress as ipa

from src.host import Host
from src.ip import IP
from src.network import Network
import src.lookup as lookup

lookup.shodan_key = os.getenv('SHODAN_KEY')

class CHostTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):

        possible_hosts = [
            'google.com',
            'amazon.com',
            'reddit.com',
            'seek.com.au',
            'google.cn',
            'sucuri.net',
            'twitter.com',
        ]

        cls.host = Host(random.choice(possible_hosts))
        print '\n# Testing {} {}'.format(cls.host.type, str(cls.host))
        cls.host.lookup_dns()
        cls.host.lookup_whois_domain()
        cls.host.lookup_whois_ip_all()
        cls.host.lookup_shodan_all()

    def test_property_types(self):
        self.assertEquals(self.host.type, 'domain')
        self.assertIsInstance(self.host.domain, str)
        [self.assertIsInstance(ip, IP) for ip in self.host.ips]
        self.assertIsInstance(self.host.ips, list)
        self.assertIsInstance(self.host.whois_domain, unicode)
        self.assertIsInstance(self.host.google_subdomains, set)
        self.assertIsInstance(self.host.subdomains, set)
        self.assertIsInstance(self.host.cidrs, set)
        [self.assertIsInstance(cidr, ipa.IPv4Network) for cidr in self.host.cidrs]
        [self.assertIsInstance(host, Host) for host in self.host.subdomains]
        [self.assertIsInstance(host, Host) for host in self.host.google_subdomains]
        self.assertIsInstance(self.host.urls, dict)

    def test_valid_results(self):
        self.assertTrue(self.host.domain)
        self.assertTrue(self.host.ips)
        self.assertTrue(self.host.whois_domain)
        self.assertTrue(self.host.cidrs)

    def test_cidrs_dont_overlap(self):
        for a,b in itertools.combinations(self.host.cidrs,2):
            self.assertFalse(a.overlaps(b))

    def test_google_lookups(self):
        new_host = Host('google.co')
        new_host.google_lookups()
        self.assertTrue(new_host.linkedin_page)
        self.assertTrue(new_host.subdomains)
        self.assertTrue(Host('www.google.co') in new_host.subdomains)

class AIPTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        possible_ips = [
            '8.8.8.8',
            '8.8.4.4',
            '4.2.2.2',
            '139.130.4.5',
        ]
        cls.host = Host(ips=[(random.choice(possible_ips))])
        cls.host.ips[0].lookup_rev_dns()
        cls.host.ips[0].lookup_whois_ip()
        cls.host.ips[0].lookup_shodan()
        print '\n# Testing {} {}'.format(cls.host.type,str(cls.host))

    def test_property_types(self):
        self.assertEquals(self.host.type, 'ip')
        self.assertIsInstance(self.host.ips[0].ip, str)
        self.assertIsInstance(self.host.ips[0].rev_domains, list)
        self.assertIsInstance(self.host.ips[0].whois_ip, dict)
        self.assertIsInstance(self.host.ips[0].cidrs, set)
        [self.assertIsInstance(cidr, ipa.IPv4Network) for cidr in self.host.ips[0].cidrs]
        self.assertIsInstance(self.host.ips[0].shodan.get('ip_str'), unicode)

    def test_valid_results(self):
        self.assertTrue(self.host.ips[0].ip)
        self.assertTrue(self.host.ips[0].rev_domains)
        self.assertTrue(self.host.ips[0].whois_ip)
        self.assertTrue(self.host.ips[0].cidrs)
        self.assertTrue(self.host.ips[0].shodan)

    def test_ip_remove_overlapping_cidr_function(self):
        """
        Test function that removes overlapping cidrs
        Used in case whois_ip results
        contain cidrs
        """
        cidrs = [
            ipa.ip_network(u'54.192.0.0/12'),
            ipa.ip_network(u'54.206.0.0/16'), # overlaps and is smaller than '54.192.0.0/12'
            ipa.ip_network(u'54.80.0.0/12'),
            ipa.ip_network(u'54.72.0.0/13'),
            ipa.ip_network(u'8.8.8.0/24'),
            ipa.ip_network(u'8.8.8.128/25'), # overlaps and is smaller than '8.8.8.0/24'
        ]
        self.assertEquals(len(IP._remove_overlaping_cidrs(cidrs)),4)

class BNetworkTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.network = Network('8.8.8.0/27')
        print '\n# Testing Network {}'.format(str(cls.network))

    def test_property_types(self):
        self.assertIsInstance(self.network.cidr, ipa.IPv4Network)
        self.assertIsInstance(self.network.related_hosts, set)

    # def test_reverse_dns_lookup(self):
    #     InstaRecon.reverse_dns_on_cidr(self.network)
    #     self.assertTrue(self.network.related_hosts)

if __name__ == '__main__':
    unittest.main()
