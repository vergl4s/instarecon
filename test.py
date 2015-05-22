#!/usr/bin/env python
import unittest
import random
import itertools

from instarecon import *
import ipaddress

class HostTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        possible_hosts = [
            'google.com',
            'amazon.com',
            'reddit.com',
            'seek.com.au',
            'google.cn',
            'sucuri.net',
        ]
        cls.host = Host(random.choice(possible_hosts))
        print '# Testing {}'.format(str(cls.host))
        cls.host.dns_lookups()
        cls.host.get_whois_domain()
        cls.host.get_whois_ip()

    def test_whois_domain(self):
        self.assertTrue(self.host.whois_domain)
        self.assertIsInstance(self.host.whois_domain, unicode)

    def test_cidrs_are_IPv4Network(self):
        self.assertIsInstance(self.host.cidrs,set)
        for cidr in self.host.cidrs:
            self.assertIsInstance(cidr, ipaddress.IPv4Network)

        for ip in self.host.ips:
            self.assertIsInstance(ip.cidrs,set)
            for cidr in ip.cidrs:
                self.assertIsInstance(cidr, ipaddress.IPv4Network)

    def test_cidrs_dont_overlap(self):
        for a,b in itertools.combinations(self.host.cidrs,2):
            self.assertFalse(a.overlaps(b))

class IPTestCase(unittest.TestCase):
    
    def test_ip_remove_overlapping_cidr_func(self):
        cidrs = [
            ipa.ip_network(u'54.192.0.0/12'),
            ipa.ip_network(u'54.206.0.0/16'), #overlaps and is smaller than '54.192.0.0/12'
            ipa.ip_network(u'54.80.0.0/12'),
            ipa.ip_network(u'54.72.0.0/13'),
            ipa.ip_network(u'8.8.8.0/24'),
            ipa.ip_network(u'8.8.8.128/25'), #overlaps and is smaller than '8.8.8.0/24'
        ]
        self.assertEquals(len(IP._remove_overlaping_cidrs(cidrs)),4)

if __name__ == '__main__':
    unittest.main()