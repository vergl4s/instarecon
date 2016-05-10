#!/usr/bin/env python
import itertools
import sys
import time

import ipaddress as ipa  # https://docs.python.org/3/library/ipaddress.html

import lookup

class IP(object):
    """
    IP and information specific to it. Hosts contain multiple IPs,
    as a domain can resolve to multiple IPs.

    Keyword arguments:
    ip -- Str representation of this ip e.g. '8.8.8.8'
    whois_ip -- Dict containing results from IP Whois lookups
    cidrs -- set of ipa.IPv4Network representing networks that contain self.ip (taken from whois_ip)
    rev_domains -- List of str for each reverse domain for self.ip, found through reverse DNS lookups
    shodan -- Dict containing Shodan results
    """

    def __init__(self, ip, rev_domains=()):

        #Will raise an exception in case ip is not a valid address
        ipa.ip_address(unicode(ip))

        self.ip = str(ip)
        self.rev_domains = rev_domains
        self.whois_ip = {}
        self.cidrs = set()
        self.shodan = None

    def __str__(self):
        return str(self.ip)

    def __hash__(self):
        return hash(('ip', self.ip))

    def __eq__(self, other):
        return self.ip == other.ip

    def lookup_rev_dns(self):
        rev_domains = None
        rev_domains = lookup.reverse_dns(self.ip)
        if rev_domains:
            self.rev_domains = [str(domain).rstrip('.') for domain in rev_domains]
        return self

    def lookup_shodan(self):
        self.shodan = lookup.shodan(str(self))

    def lookup_whois_ip(self):
        self.whois_ip = lookup.whois_ip(str(self))

        if self.whois_ip:
            if 'nets' in self.whois_ip:
                if self.whois_ip['nets']:
                    cidrs = []

                    for net in self.whois_ip['nets']:
                        net_cidrs = [ipa.ip_network(unicode(cidr.rstrip().lstrip())) for cidr in net['cidr'].split(',') if cidr]
                        cidrs += net_cidrs

                    self.cidrs = self._remove_overlaping_cidrs(cidrs)
        return self

    @staticmethod
    def _remove_overlaping_cidrs(cidrs):
        """
        Takes list of cidrs and removes duplicates or overlapping networks.
        """
        cidrs = set(cidrs)
        # iter_cidrs won't be changed because it is used for iteration
        iter_cidrs = [i for i in cidrs]
        for a,b in itertools.combinations(iter_cidrs, 2):
            if a.overlaps(b):
                to_be_removed = None
                if a.num_addresses>=b.num_addresses:
                    to_be_removed = b
                else:
                    to_be_removed = a
                try:
                    cidrs.remove(to_be_removed)
                except ValueError:
                    pass
        return cidrs

    def print_ip(self):
        ret = str(self.ip)

        if self.rev_domains:
            if len(self.rev_domains) < 2:
                ret = ''.join([ret, ' - ', self.rev_domains[0]])
            else:
                for rev in self.rev_domains:
                    ret = '\t'.join([ret, '\n', rev])
        return ret

    def print_whois_ip(self):
        if self.whois_ip:
            result = ''
            # Printing all lines except 'nets' annd 'query'
            for key, val in sorted(self.whois_ip.iteritems()):
                if val and key not in ['nets', 'query']:
                    result = '\n'.join([result, key + ': ' + str(val)])
            # Printing each dict within 'nets'
            for key, net in enumerate(self.whois_ip['nets']):
                result = '\n'.join([result, 'net ' + str(key) + ':'])
                if net['cidr']:
                    result = '\n\t'.join([result, 'cidr' + ': ' + net['cidr'].replace('\n', ', ')])
                if net['range']:
                    result = '\n\t'.join([result, 'range' + ': ' + net['range'].replace('\n', ', ')])
                if net['name']:
                    result = '\n\t'.join([result, 'name' + ': ' + net['name'].replace('\n', ', ')])
                if net['description']:
                    result = '\n\t'.join([result, 'description' + ': ' + net['description'].replace('\n', ', ')])
                if net['handle']:
                    result = '\n\t'.join([result, 'handle' + ': ' + net['handle'].replace('\n', ', ')])
                result = '\n\t'.join([result, ''])
                if net['address']:
                    result = '\n\t'.join([result, 'address' + ': ' + net['address'].replace('\n', ', ')])
                if net['city']:
                    result = '\n\t'.join([result, 'city' + ': ' + net['city'].replace('\n', ', ')])
                if net['state']:
                    result = '\n\t'.join([result, 'state' + ': ' + net['state'].replace('\n', ', ')])
                if net['postal_code']:
                    result = '\n\t'.join([result, 'postal_code' + ': ' + net['postal_code'].replace('\n', ', ')])
                if net['country']:
                    result = '\n\t'.join([result, 'country' + ': ' + net['country'].replace('\n', ', ')])
                result = '\n\t'.join([result, ''])
                if 'abuse_emails' in net:
                    result = '\n\t'.join([result, 'abuse_emails' + ': ' + net['abuse_emails'].replace('\n', ', ')])
                if 'tech_emails' in net:
                    result = '\n\t'.join([result, 'tech_emails' + ': ' + net['tech_emails'].replace('\n', ', ')])
                if 'misc_emails' in net:
                    result = '\n\t'.join([result, 'misc_emails' + ': ' + net['misc_emails'].replace('\n', ', ')])
                result = '\n\t'.join([result, ''])
                # if 'created' in net:
                    # result = '\n\t'.join([result, 'created' + ': ' + time.strftime("%Y-%m-%d", time.strptime(net['created'].replace('\n', ', '), '%Y-%m-%d'))])
                # if 'updated' in net:
                    # result = '\n\t'.join([result, 'updated' + ': ' + time.strftime("%Y-%m-%d", time.strptime(net['updated'].replace('\n', ', '), '%Y-%m-%d'))])

                # for key2,val2 in sorted(net.iteritems()):
                #         result = '\n\t'.join([result,key2+': '+str(val2).replace('\n',', ')])
            return result.lstrip().rstrip()

    def print_shodan(self):
        if self.shodan:

            result = ''.join(['IP: ', self.shodan.get('ip_str'), '\n'])

            if self.shodan.get('org', 'n/a'):
                result = ''.join([result, 'Organization: ', self.shodan.get('org', 'n/a'), '\n'])

            if self.shodan.get('os', 'n/a'):
                result = ''.join([result, 'OS: ', self.shodan.get('os', 'n/a'), '\n'])

            if self.shodan.get('isp', 'n/a'):
                result = ''.join([result, 'ISP: ', self.shodan.get('isp', 'n/a'), '\n'])

            if len(self.shodan['data']) > 0:
                for item in self.shodan['data']:
                    result = '\n'.join([
                        result,
                        'Port: {}'.format(item['port']),
                        'Banner: {}'.format(item['data'].replace('\n', '\n\t').rstrip()),
                    ])
            return result.rstrip().lstrip()
