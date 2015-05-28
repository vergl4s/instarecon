#!/usr/bin/env python
import ipaddress as ipa  # https://docs.python.org/3/library/ipaddress.html

from host import Host
import lookup

class Network(object):
    """
    Subclass of Host that represents an IP network to be scanned.

    Keywork arguments:
    cidrs -- set of IPv4Networks to be scanned
    related_hosts -- set of valid Hosts found by scanning each cidr in cidrs
    """

    def __init__(self, cidr):
        """
        cidr parameter should be an ipaddress.IPv4Network
        """
        if not cidr:
            raise ValueError
        # Raises ValueError if cidr is not a valid network
        self.cidr = ipa.ip_network(cidr.decode('unicode-escape'), strict = False)
        self.related_hosts = set()
        self.type = 'network'

    def __str__(self):
        return str(self.cidr)

    def __hash__(self):
        return hash(('cidr', self.cidr))

    def __eq__(self, other):
        return self.cidr == other.cidr

    def reverse_lookup_on_related_cidrs(self, feedback=False):
        """
        Does reverse dns lookups in all cidrs that are related to this host
        Will be used to check for subdomains found through reverse lookup
        """
        generator = lookup.rev_dns_on_cidr(self.cidr)

        while True:
            try:

                # generator may return ip or KeyboardInterrupt
                ip_or_exception = generator.next()
                
                if isinstance(ip_or_exception, KeyboardInterrupt):
                    raise KeyboardInterrupt
                
                else:
                    ip = ip_or_exception
                    reverse_domains = generator.next()

                    new_host = Host(ips=[ip], reverse_domains=reverse_domains)

                    self.related_hosts.add(new_host)

                    if feedback:
                        print new_host.print_all_ips()

            except StopIteration:
                break

        if not self.related_hosts and feedback:
            print '# No results for this range'

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