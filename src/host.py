#!/usr/bin/env python
from random import randint
import sys
import time

import dns.name  # http://www.dnspython.org/docs/1.12.0/
import ipaddress as ipa  # https://docs.python.org/3/library/ipaddress.html

from ip import IP
import log
import lookup

class Host(object):
    """
    Host represents an entity on the internet. Can originate from a domain or from an IP.

    Keyword arguments:
    domain -- DNS/Domain name e.g. google.com
    type -- either 'domain' or 'ip', depending on original information passed to __init__
    ips -- List of instances of IP. Each instance contains:
        ip -- Str representation of IP e.g. 8.8.8.8
        rev_domains -- list of str representing reverse domains related to ip
        whois_ip -- Dict containing results from a Whois lookup on an IP
        shodan -- Dict containing results from Shodan lookups
        cidr -- Str of CIDR that this ip is part of (taken from whois_ip results)
    mx -- Set of Hosts for each DNS MX entry for original self.domain
    ns -- Set of Hosts for each DNS NS entry for original self.domain
    whois_domain -- str representation of the Whois query
    subdomains -- Set of Hosts for each related Host found that is a subdomain of self.domain
    linkedin_page -- Str of LinkedIn url that contains domain in html
    related_hosts -- Set of Hosts that may be related to host, as they're part of the same cidrs
    cidrs -- set of ipa.IPv4Networks for each ip.cidrs
    urls -- set of urls found in google results
    """

    def __init__(self, domain=None, ips=(), reverse_domains=()):
        # Type check - depends on what parameters have been passed
        if domain:
            self.type = 'domain'

            #Check if domain can be resolved and raise ValueError if it can't
            self.domain = lookup.direct_dns(domain)
            if not self.domain:
                raise ValueError

        elif ips:
            self.type = 'ip'
            
            # IP raises ValueError if passed an invalid value
            self.ips = [IP(str(ip), reverse_domains) for ip in ips]
        else:
            raise ValueError

        self.mx = set()
        self.ns = set()
        self.whois_domain = None
        self.subdomains = set()
        self.linkedin_page = None
        self.related_hosts = set()
        self.cidrs = set()
        self.urls = set()

    def __str__(self):
        if self.type == 'domain':
            return str(self.domain)
        elif self.type == 'ip':
            return str(self.ips[0])

    def __hash__(self):
        if self.type == 'domain':
            return hash(('domain', self.domain))
        elif self.type == 'ip':
            return hash(('ip', ','.join([str(ip) for ip in self.ips])))

    def __eq__(self, other):
        if self.type == 'domain':
            return self.domain == other.domain
        elif self.type == 'ip':
            return self.ips == other.ips

    def dns_lookups(self):
        """
        Basic DNS lookups on self. Returns self.

        1) Direct DNS lookup on self.domain
        2) Reverse DNS lookup on each self.ips
        """
        if self.type == 'domain':
            self._get_ips()
        for ip in self.ips:
            ip.get_rev_domains()
        return self

    def mx_dns_lookup(self):
        """
        DNS lookup to find MX entries i.e. mail servers responsible for self.domain
        """
        if self.domain:
            mx_list = lookup.mx_dns(self.domain)
            if mx_list:
                self.mx.update([Host(domain=mx).dns_lookups() for mx in mx_list])
                self._add_to_subdomains_if_valid(subdomains_as_hosts=self.mx)
        return self

    def ns_dns_lookup(self):
        """
        DNS lookup to find NS entries i.e. name/DNS servers responsible for self.domain
        """
        if self.domain:
            ns_list = lookup.ns_dns(self.domain)
            if ns_list:
                self.ns.update([Host(domain=ns).dns_lookups() for ns in ns_list])
                self._add_to_subdomains_if_valid(subdomains_as_hosts=self.ns)
        return self

    def get_rev_domains_for_ips(self):
        """
        Reverse DNS lookup on each IP in self.ips
        """
        if self.ips:
            for ip in self.ips:
                ip.get_rev_domains()
        return self

    def get_whois_domain(self):
        """
        Whois lookup on self.domain. Saved in self.whois_domain as string,
        since each top-level domain has a way of representing data.
        This makes it hard to index it, almost a project on its on.
        """
        try:
            if self.domain:
                query = lookup.whois_domain(self.domain)

                if 'raw' in query:
                    self.whois_domain = query['raw'][0].split('<<<')[0].lstrip().rstrip()

        except Exception as e:
            log.raise_error(e, sys._getframe().f_code.co_name)
            pass
        return self

    def get_whois_ip(self):
        """
        IP Whois lookups on each ip within self.ips
        Saved in each ip.whois_ip as dict, since this is how it is returned by ipwhois library.
        """
        # Keeps track of lookups already made - cidr as key, whois_ip dict as val
        cidrs_found = {}
        for ip in self.ips:
            cidr_found = False
            for cidr, whois_ip in cidrs_found.iteritems():
                if ipa.ip_address(ip.ip.decode('unicode-escape')) in cidr:  # cidr already IPv4.Network obj
                    # If cidr is already in Host, we won't call get_whois_ip again.
                    # Note cidr already found is not saved in new ips, as it isn't really necessary
                    ip.whois_ip = whois_ip
                    cidr_found = True
                    break
            if not cidr_found:
                ip.get_whois_ip()
                for cidr in ip.cidrs:
                    cidrs_found[cidr] = ip.whois_ip

        self.cidrs = set([cidr for cidr in cidrs_found if cidr])
        return self

    def get_all_shodan(self, key):
        """
        Shodan lookups for each ip within self.ips.
        Saved in ip.shodan as dict.
        """
        if key:
            for ip in self.ips:
                ip.get_shodan(key)
        return self

    def _get_ips(self):
        """
        Does direct DNS lookup to get IPs from self.domains.
        Used internally by self.dns_lookups()
        """
        if self.domain and not self.ips:
            ips = lookup.direct_dns(self.domain)
            if ips:
                self.ips = [IP(str(ip)) for ip in ips]

    def google_lookups(self):
        """
        Google queries to find related subdomains and linkedin pages. Testing.
        """
        if self.domain:
            self.linkedin_page = lookup.google_linkedin_page(self.domain)

            self._add_to_subdomains_if_valid(subdomains_as_str=lookup.google_subdomains(self.domain))

            return self

    def _add_to_subdomains_if_valid(self, subdomains_as_str=None, subdomains_as_hosts=None):
        """
        Add Hosts from subdomains_as_str or subdomains_as_hosts to self.subdomains if indeed these hosts are subdomains
        subdomains_as_hosts and subdomains_as_str should be iterable list or set
        """
        if subdomains_as_str:
            self.subdomains.update(
                [Host(domain=subdomain).dns_lookups() for subdomain in subdomains_as_str if self._is_parent_domain_of(subdomain)]
            )

        elif subdomains_as_hosts:
            self.subdomains.update(
                [subdomain for subdomain in subdomains_as_hosts if self._is_parent_domain_of(subdomain)]
            )

    def _is_parent_domain_of(self, subdomain):
        """
        Checks if subdomain is indeed a subdomain of self.domain
        In addition it filters out invalid dns names
        """
        if isinstance(subdomain, Host):
            # If subdomain has .domain
            if subdomain.domain:
                try:
                    return dns.name.from_text(subdomain.domain).is_subdomain(dns.name.from_text(self.domain))
                except Exception as e:
                    pass

            # If subdomain doesn't have .domain, if was found through reverse dns scan on cidr
            # So I must add the rev parameter to subdomain as .domain, so it looks better on the csv
            elif subdomain.ips[0].rev_domains:
                for rev in subdomain.ips[0].rev_domains:
                    try:
                        if dns.name.from_text(rev).is_subdomain(dns.name.from_text(self.domain)):
                            # Adding a .rev_domains str to .domain
                            subdomain.domain = rev
                            return True
                    except Exception as e:
                        pass
        else:
            try:
                return dns.name.from_text(subdomain).is_subdomain(dns.name.from_text(self.domain))
            except dns.name.EmptyLabel:
                # EmptyLabel is an exception raised for bad dns strings
                pass

        return False

    def reverse_lookup_on_related_cidrs(self, feedback=False):
        """
        Does reverse dns lookups in all cidrs that are related to this host
        Will be used to check for subdomains found through reverse lookup
        """
        for cidr in self.cidrs:
            generator = lookup.rev_dns_on_cidr(cidr, feedback=True)
            
            while True:
                try:
                    generator.next()
                except StopIteration:
                    break
                except KeyboardInterrupt:
                    if isinstance(self, Network):
                        raise KeyboardInterrupt
                    else:
                        if raw_input('[-] Sure you want to stop scanning ' + str(cidr) +
                                     '? Program flow will continue normally. (y/N):') in ['Y', 'y']:
                        return

        if not self.related_hosts:
            print '# No results for this range'

    def print_all_ips(self):
        if self.ips:
            return '\n'.join([ip.print_ip() for ip in self.ips]).rstrip()

    def print_subdomains(self):
        return self._print_domains(sorted(self.subdomains, key=lambda x: x.domain))

    @staticmethod
    def _print_domains(hosts):
        # Static method that prints a list of domains with its respective ips and rev_domains
        # domains should be a list of Hosts
        if hosts:
            ret = ''
            for host in hosts:

                ret = ''.join([ret, host.domain])

                p = host.print_all_ips()
                if p:
                    ret = ''.join([ret, '\n\t', p.replace('\n', '\n\t')])

                ret = ''.join([ret, '\n'])

            return ret.rstrip().lstrip()

    def print_all_ns(self):
        # Print all NS records
        return self._print_domains(self.ns)

    def print_all_mx(self):
        # Print all MS records
        return self._print_domains(self.mx)

    def print_dns_only(self):
        return self._print_domains([self])

    def print_all_whois_ip(self):
        # Prints whois_ip records related to all self.ips
        ret = set([ip.print_whois_ip() for ip in self.ips if ip.whois_ip])
        return '\n'.join(ret).lstrip().rstrip()

    def print_all_shodan(self):
        # Print all Shodan entries (one for each IP in self.ips)

        ret = [ip.print_shodan() for ip in self.ips if ip.shodan]
        return '\n'.join(ret).lstrip().rstrip()

    def print_as_csv_lines(self):
        """Generator that yields each IP within self.ips as a csv line."""

        yield ['Target:', str(self)]

        if self.ips:
            yield [
                'Domain',
                'IP',
                'Reverse domains',
                'NS',
                'MX',
                # 'Subdomains',
                'Domain whois',
                'IP whois',
                'Shodan',
                'LinkedIn page',
                'CIDRs'
            ]

            for ip in self.ips:
                yield [
                    self.domain,
                    str(ip),
                    '\n'.join(ip.rev_domains),
                    self.print_all_ns(),
                    self.print_all_mx(),
                    # self.print_subdomains(),
                    self.whois_domain,
                    ip.print_whois_ip(),
                    ip.print_shodan(),
                    self.linkedin_page,
                    ', '.join([str(cidr) for cidr in self.cidrs])
                ]

        if self.subdomains:
            yield ['\n']
            yield ['Subdomains for ' + str(self.domain)]
            yield ['Domain', 'IP', 'Reverse domains']

            for sub in sorted(self.subdomains, key=lambda x: x.domain):
                for ip in sub.ips:
                    if sub.domain:
                        yield [sub.domain, ip.ip, ','.join(ip.rev_domains)]
                    else:
                        yield [ip.rev_domains[0], ip.ip, ','.join(ip.rev_domains)]

        if self.related_hosts:
            yield ['\n']
            yield ['Hosts in same CIDR as', str(self), '(all results found, including subdomains)']
            yield ['IP', 'Reverse domains']

            for sub in sorted(self.related_hosts, key=lambda x: x.ips[0]):
                yield [
                    ','.join([str(ip) for ip in sub.ips]),
                    ','.join([','.join(ip.rev_domains) for ip in sub.ips]),
                ]

    def do_all_lookups(self, shodan_key=None):
        """
        This method does all possible direct lookups for a Host.
        Not called by any Host or Scan function, only here for testing purposes.
        """
        self.dns_lookups()
        self.ns_dns_lookup()
        self.mx_dns_lookup()
        self.get_whois_domain()
        self.get_whois_ip()
        if shodan_key:
            self.get_all_shodan(shodan_key)
        self.google_lookups()

class Network(Host):
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

    def __str__(self):
        return ','.join([str(cidr) for cidr in self.cidrs])

    def __hash__(self):
        return hash(('cidrs', ','.join([str(cidr) for cidr in self.cidrs])))

    def __eq__(self, other):
        return self.cidrs == other.cidrs

    def print_as_csv_lines(self):
        """Overrides method from Host. Yields each Host in related_hosts as csv line"""
        yield ['Target: ' + ', '.join([str(cidr) for cidr in self.cidrs])]

        if self.related_hosts:
            yield ['IP', 'Reverse domains', ]
            for host in self.related_hosts:
                yield [
                    ', '.join([str(ip) for ip in host.ips]),
                    ', '.join([', '.join(ip.rev_domains) for ip in host.ips]),
                ]
        else:
            yield ['No results']