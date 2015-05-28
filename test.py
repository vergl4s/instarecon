#!/usr/bin/env python
import itertools
import os
import random
import unittest

import ipaddress

from instarecon import *
import src.lookup

class HostTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        lookup.shodan_key = os.getenv('SHODAN_KEY')

        possible_hosts = [
            'google.com',
            'amazon.com',
            'reddit.com',
            'seek.com.au',
            'google.cn',
            'sucuri.net',
        ]

        cls.host = Host(random.choice(possible_hosts))
        print '\n# Testing {} {}'.format(cls.host.type, str(cls.host))
        cls.host.dns_lookups()
        cls.host.get_whois_domain()
        cls.host.get_whois_ip()

    def test_property_types(self):
        self.assertIsInstance(self.host.domain, str)
        [ self.assertIsInstance(ip, IP) for ip in self.host.ips ]
        self.assertIsInstance(self.host.ips, list)
        self.assertIsInstance(self.host.whois_domain, unicode)
        self.assertIsInstance(self.host.cidrs,set)
        [self.assertIsInstance(cidr, ipaddress.IPv4Network) for cidr in self.host.cidrs]

    def test_whois_domain(self):
        self.assertTrue(self.host.whois_domain)

    def test_cidrs_dont_overlap(self):
        for a,b in itertools.combinations(self.host.cidrs,2):
            self.assertFalse(a.overlaps(b))

class IPTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        possible_ips = [
            '8.8.8.8',
            '8.8.4.4',
            '4.2.2.2',
            '139.130.4.5',
        ]
        cls.ip = IP(random.choice(possible_ips))
        cls.ip.get_rev_domains()
        cls.ip.get_whois_ip()
        print '\n# Testing IP {}'.format(str(cls.ip))

    def test_property_types(self):
        self.assertIsInstance(self.ip.ip, str)
        self.assertIsInstance(self.ip.rev_domains, list)
        self.assertIsInstance(self.ip.whois_ip, dict)
        self.assertIsInstance(self.ip.cidrs, set)
        [self.assertIsInstance(cidr, ipaddress.IPv4Network) for cidr in self.ip.cidrs]

    def test_ip_remove_overlapping_cidr_function(self):
        """
        Test function that removes overlapping cidrs
        Used in case whois_ip results
        contain cidrs
        """
        cidrs = [
            ipa.ip_network(u'54.192.0.0/12'),
            ipa.ip_network(u'54.206.0.0/16'), #overlaps and is smaller than '54.192.0.0/12'
            ipa.ip_network(u'54.80.0.0/12'),
            ipa.ip_network(u'54.72.0.0/13'),
            ipa.ip_network(u'8.8.8.0/24'),
            ipa.ip_network(u'8.8.8.128/25'), #overlaps and is smaller than '8.8.8.0/24'
        ]
        self.assertEquals(len(IP._remove_overlaping_cidrs(cidrs)),4)

class NetworkTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.network = Network('8.8.8.0/27')
        print '\n# Testing Network {}'.format(str(cls.network))

    def test_property_types(self):
        self.assertIsInstance(self.network.cidr, ipaddress.IPv4Network)
        self.assertIsInstance(self.network.related_hosts, set)

    def test_reverse_dns_lookup(self):
        InstaRecon.reverse_dns_on_cidr(self.network)
        self.assertTrue(self.network.related_hosts)

if __name__ == '__main__':
    unittest.main()