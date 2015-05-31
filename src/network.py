#!/usr/bin/env python
import ipaddress as ipa  # https://docs.python.org/3/library/ipaddress.html

import lookup

class Network(object):
    """
    Subclass of Host that represents an IP network to be scanned.

    Keywork arguments:
    cidr -- ipa.IPv4Network object
    related_hosts -- set of valid Hosts found by scanning each cidr in cidrs
    """

    def __init__(self, cidr):
        """
        cidr parameter should be an ipaddress.IPv4Network
        """
        if not cidr:
            raise ValueError
        # Raises ValueError if cidr is not a valid network
        self.cidr = ipa.ip_network(unicode(cidr), strict=False)
        self.related_hosts = set()
        self.type = 'network'

    def __str__(self):
        return str(self.cidr)

    def __hash__(self):
        return hash(('cidr', self.cidr))

    def __eq__(self, other):
        return self.cidr == other.cidr

    def add_related_host(self, new_host):
        self.related_hosts.add(new_host)

    def print_as_csv_lines(self):
        """Overrides method from Host. Yields each Host in related_hosts as csv line"""
        yield ['Target: ' + str(self.cidr)]

        if self.related_hosts:
            yield ['IP', 'Reverse domains', ]
            for host in self.related_hosts:
                yield [
                    ', '.join([str(ip) for ip in host.ips]),
                    ', '.join([', '.join(ip.rev_domains) for ip in host.ips]),
                ]
        else:
            yield ['No results']