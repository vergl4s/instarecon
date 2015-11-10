#!/usr/bin/env python
import dns.name  # http://www.dnspython.org/docs/1.12.0/
import ipaddress as ipa  # https://docs.python.org/3/library/ipaddress.html
import logging

from ip import IP
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
    linkedin_page -- Str of LinkedIn url that contains domain in html
    urls -- dict of protocol:pathnames found in google results for this domain
    related_hosts -- Set of Hosts that may be related to host, as they're part of the same cidrs
    subdomains -- Set of Hosts for each related Host found that is a subdomain of self.domain
    google_subdomains -- set of Hosts found through google dorks
    cidrs -- set of ipa.IPv4Network objects related to each ip.cidrs
    """

    def __init__(self, domain=None, ips=(), reverse_domains=(), strict=False):
        self.domain = None
        self.ips = []

        # Type check - depends on what parameters have been passed
        if domain:
            self.type = 'domain'

            self.domain = domain
            self._get_ips()

            # Check if domain can be resolved only if strict flag is True
            if strict and not self.ips:
                # Couldn't resolve domain
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
        self.linkedin_page = None
        self.urls = {}

        self.related_hosts = set()
        self.subdomains = set()
        self.google_subdomains = set()
        self.cidrs = set()

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

    def lookup_dns(self):
        """
        Basic DNS lookups on self. Returns self.

        1) Direct DNS lookup on self.domain
        2) Reverse DNS lookup on each self.ips
        """
        if self.type == 'domain':
            self._get_ips()
        self.lookup_dns_rev_all()
        return self

    def _get_ips(self):
        """
        Does direct DNS lookup to get IPs from self.domains.
        Used internally by self.lookup_dns()
        """
        if self.domain and not self.ips:
            ips = lookup.direct_dns(self.domain)
            if ips:
                self.ips = [IP(str(ip)) for ip in ips]

    def lookup_dns_mx(self):
        """
        DNS lookup to find MX entries i.e. mail servers responsible for self.domain
        """
        if self.domain:
            mx_list = lookup.mx_dns(self.domain)
            if mx_list:
                self.mx.update([Host(domain=mx).lookup_dns() for mx in mx_list])
                self._add_to_subdomains_if_valid(self.mx)
        return self

    def lookup_dns_ns(self):
        """
        DNS lookup to find NS entries i.e. name/DNS servers responsible for self.domain
        """
        if self.domain:
            ns_list = lookup.ns_dns(self.domain)
            if ns_list:
                self.ns.update([Host(domain=ns).lookup_dns() for ns in ns_list])
                self._add_to_subdomains_if_valid(self.ns)
        return self

    def lookup_dns_rev_all(self):
        """
        Reverse DNS lookup on each IP in self.ips
        """
        if self.ips:
            for ip in self.ips:
                ip.lookup_rev_dns()
        return self

    def lookup_whois_domain(self):
        """
        Whois lookup on self.domain. Saved in self.whois_domain as string,
        since each top-level domain has a way of representing data.
        This makes it hard to index it, almost a project on its on.
        """
        if self.domain:
            self.whois_domain = lookup.whois_domain(self.domain)
        return self

    def lookup_whois_ip_all(self):
        """
        IP Whois lookups on each ip within self.ips
        Saved in each ip.whois_ip as dict, since this is how it is returned by ipwhois library.
        """
        for ip1 in self.ips:
            cidr_found = False

            for ip2 in self.ips:
                if cidr_found:
                    break
                if ip1!=ip2:
                    for cidr in ip2.cidrs:
                        if ipa.ip_address(unicode(ip1.ip)) in cidr:  # cidr already IPv4.Network obj
                            # If cidr is already in Host, we won't call whois_ip again.
                            # Note cidr already found is not saved in new ips, as it isn't really necessary
                            ip1.whois_ip = ip2.whois_ip
                            ip1.cidrs = ip2.cidrs
                            cidr_found = True
                            logging.info('Results for ' + str(ip1) + ' already found in ip ' + str(ip2) + '. CIDR is ' + str(cidr))
                            break

            if not cidr_found:
                logging.debug('Performing Whois IP lookup for ' + str(ip1))
                ip1.lookup_whois_ip()

        for ip in self.ips:
            [self.cidrs.add(cidr) for cidr in ip.cidrs]
        return self

    def lookup_shodan_all(self):
        """
        Shodan lookups for each ip within self.ips.
        Saved in ip.shodan as dict.
        """
        for ip in self.ips:
            ip.lookup_shodan()
        return self

    def add_related_host(self, new_host):
        self.related_hosts.add(new_host)
        self._add_to_subdomains_if_valid([new_host])

    def google_lookups(self):
        """Does all Google queries"""

        self.google_linkedin_page()

        self.lookup_google_subdomains()

        return self

    def google_linkedin_page(self):
        """Finds the most likely linkedin page for self"""

        if self.type == 'domain':
            self.linkedin_page = lookup.google_linkedin_page(self.domain)

    def lookup_google_subdomains(self):
        """Find as many subdomains from google as possible"""
        # Dict of subdomain_str:GoogleDomainResult for each subdomain found
        subdomains = lookup.google_subdomains(self.domain)

        subdomains_as_hosts = set([])

        for sub_str, google_results in subdomains.iteritems():
                if sub_str == self.domain:
                    self.urls = sorted(google_results.urls)
                else:
                    try:
                        sub = Host(domain=sub_str).lookup_dns()
                        sub.urls = google_results.urls
                        subdomains_as_hosts.add(sub)
                    except ValueError as e: # in case it can't be resolved
                        pass

        # Hold subdomains in self.google_subdomains
        self.google_subdomains.update(subdomains_as_hosts)

        # Pass subdomains to set in self.subdomains as well
        self._add_to_subdomains_if_valid(subdomains_as_hosts)

    def _add_to_subdomains_if_valid(self, subdomains_as_hosts):
        """
        Add Hosts from subdomains_as_hosts to self.subdomains if indeed these hosts are subdomains
        """
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

    def do_all_lookups(self, shodan_key=None):
        """
        This method does all possible direct lookups for a Host.
        Not called by any Host or Scan function, only here for testing purposes.
        """
        self.lookup_dns()
        self.lookup_dns_ns()
        self.lookup_dns_mx()
        self.lookup_whois_domain()
        self.lookup_whois_ip_all()
        if shodan_key:
            self.lookup_shodan_all(shodan_key)
        self.google_lookups()

    @staticmethod
    def _print_domains(hosts):
        # Static method that prints a list of domains with its respective ips and rev_domains
        # domains should be a list of Hosts
        if hosts:
            ret = ''
            for host in hosts:

                ret = ''.join([ret, host.domain])

                ips = host.print_all_ips()
                if ips:
                    ret = ''.join([ret, '\n\t', ips.replace('\n', '\n\t')])

                urls = host.print_all_urls()
                if urls:
                    ret = ''.join([ret, '\n\t', urls.replace('\n','\n\t')])

                ret = ''.join([ret, '\n'])

            return ret.rstrip().lstrip()

    def print_all_ips(self):
        if self.ips:
            return '\n'.join([ip.print_ip() for ip in self.ips]).rstrip()

    def print_all_cidrs(self):
        if self.cidrs:
            return '\n'.join([str(cidr) for cidr in self.cidrs])

    def print_all_urls(self):
        if self.urls:
            ret = ''
            for proto, paths in self.urls.iteritems():
                for path in sorted(paths):
                    ret = ''.join([ret, '\n', proto, self.domain, path])
            return ret.rstrip().lstrip()

    def print_subdomains(self):
        return self._print_domains(sorted(self.subdomains, key=lambda x: x.domain))

    def print_google_subdomains(self):
        return self._print_domains(sorted(self.google_subdomains, key=lambda x: x.domain))

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
        # kind of a hack, since it returns a list instead of strings
        results = {}
        ret = []
        for ip in self.ips:
            whois_ip = ip.print_whois_ip()
            if whois_ip:
                results.setdefault(whois_ip, set()).add(str(ip))
        for whois_ip, set_of_ips in results.iteritems():
            ret.append(''.join([', '.join(set_of_ips), ':\n', whois_ip]))
        return ret

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
                'CIDRs',
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
                    ', '.join([str(cidr) for cidr in ip.cidrs])
                ]

        if self.subdomains:
            yield ['\n']
            yield ['Subdomains for ' + str(self.domain)]
            yield ['Domain', 'IP', 'Reverse domains', 'URLs']

            for sub in sorted(self.subdomains, key=lambda x: x.domain):
                for ip in sub.ips:
                    line = []
                    if sub.domain:
                        line.append(sub.domain)
                    else:
                        line.append('')
                    line += [ip.ip, ','.join(ip.rev_domains)]
                    if sub.urls:
                        line += [sub.print_all_urls()]
                    yield line


        if self.related_hosts:
            yield ['\n']
            yield ['Hosts in same CIDR as ' + str(self) + ' (' + ', '.join([str(cidr) for cidr in self.cidrs]) + ')']
            yield ['IP', 'Reverse domains']

            for host in sorted(self.related_hosts, key=lambda x: x.ips[0]):
                yield [
                    ','.join([str(ip) for ip in host.ips]),
                    ','.join([','.join(ip.rev_domains) for ip in host.ips]),
                ]
