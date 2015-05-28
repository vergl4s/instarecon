#!/usr/bin/env python
import argparse
import csv
import os
import sys

import ipaddress as ipa  # https://docs.python.org/3/library/ipaddress.html
import dns.resolver

from src.ip import IP
from src.host import Host
from src.network import Network
from src import lookup
from src import log

class InstaRecon(object):
    """
    Holds all Host entries and manages scans, interpret user input, threads and outputs.

    Keyword arguments:
    nameserver -- Str DNS server to be used for lookups (consumed by dns.resolver module).
    targets -- Set of Hosts or Networks that will be scanned.
    bad_targets -- Set of user inputs that could not be understood or resolved.
    versobe -- Bool flag for verbose output printing. Passed to logs.
    shodan_key -- Str key used for Shodan lookups. Passed to lookups.
    """
    __version__ = '0.1'
    entry_banner = '# InstaRecon v' + __version__ + ' - by Luis Teixeira (teix.co)'
    exit_banner = '# Done'

    def __init__(self, nameserver=None, timeout=None, shodan_key=None, verbose=False, dns_only=False):

        if nameserver:
            lookup.dns_resolver.nameservers = [nameserver]
        if timeout:
            lookup.dns_resolver.timeout = timeout
            lookup.dns_resolver.lifetime = timeout
        self.dns_only = dns_only
        self.targets = set()
        self.bad_targets = set()

        log.feedback = True
        log.verbose = verbose

        lookup.shodan_key = shodan_key

    def populate(self, user_supplied_list):
        for user_supplied in user_supplied_list:
            self.add_host(user_supplied)

        if not self.targets:
            print '# No hosts to scan'
        else:
            print '# Scanning', str(len(self.targets)) + '/' + str(len(user_supplied_list)), 'hosts'

            if not self.dns_only:
                if not lookup.shodan_key:
                    print '# No Shodan key provided'
                else:
                    print'# Shodan key provided -', lookup.shodan_key

    def add_host(self, user_supplied):
        """
        Add string passed by user to self.targets as proper Host/Network objects
        For this, it attempts to create these objects and moves on if got a ValueError.
        """
        # Test if user_supplied is an IP?
        try:
            self.targets.add(Host(ips=[user_supplied]))
            return
        except ValueError as e:
            pass

        try:
            self.targets.add(Network(user_supplied))
            return
        except ValueError as e:
            pass

        # Test if user_supplied is a valid DNS?
        try:
            self.targets.add(Host(domain=user_supplied))
            return
        except ValueError as e:
            print '[-] Couldn\'t resolve or understand -', user_supplied
            pass

        self.bad_targets.add(user_supplied)

    def scan_targets(self):
        for target in self.targets:
            if type(target) is Host:
                if self.dns_only:
                    self.scan_host_dns_only(target)
                else:
                    self.scan_host(target)
            elif type(target) is Network:
                self.scan_network(target)

    @staticmethod
    def scan_host(host):
        """Does all possible scans for host"""

        print ''
        print '# ____________________ Scanning {} ____________________ #'.format(str(host))

        # DNS and Whois lookups
        print ''
        print '# DNS lookups'

        host.dns_lookups()
        if host.domain:
            print '[*] Domain: ' + host.domain

        # IPs and reverse domains
        if host.ips:
            print ''
            print '[*] IPs & reverse DNS: '
            print host.print_all_ips()

        host.ns_dns_lookup()
        # NS records
        if host.ns:
            print ''
            print '[*] NS records:'
            print host.print_all_ns()

        host.mx_dns_lookup()
        # MX records
        if host.mx:
            print ''
            print '[*] MX records:'
            print host.print_all_mx()

        print ''
        print '# Whois lookups'

        host.get_whois_domain()
        if host.whois_domain:
            print ''
            print '[*] Whois domain:'
            print host.whois_domain

        host.get_whois_ip()
        for ip in host.ips:
            m = ip.print_whois_ip()
            if m:
                print ''
                print '[*] Whois IP for '+str(ip)+':'
                print m

        # Shodan lookup
        if lookup.shodan_key:

            print ''
            print '# Querying Shodan for open ports'

            host.get_all_shodan()

            m = host.print_all_shodan()
            if m:
                print '[*] Shodan:'
                print m

        # Google subdomains lookup
        if host.domain:
            print ''
            print '# Querying Google for subdomains and Linkedin pages, this might take a while'

            host.google_lookups()

            if host.linkedin_page:
                print '[*] Possible LinkedIn page: ' + host.linkedin_page

            if host.subdomains:
                print '[*] Subdomains:' + '\n' + host.print_subdomains()
            else:
                print '[-] Error: No subdomains found in Google. If you are scanning a lot, Google might be blocking your requests.'

        # DNS lookups on entire CIDRs taken from host.get_whois_ip()
        if host.cidrs:
            print ''
            print '# Reverse DNS lookup on range {}'.format(', '.join([str(cidr) for cidr in host.cidrs]))
            host.reverse_lookup_on_related_cidrs(feedback=True)
    
    @staticmethod
    def scan_host_dns_only(host):
        """Does only direct and reverse DNS lookups for host"""

        print ''
        print '# _________________ DNS lookups on {} _________________ #'.format(str(host))

        host.dns_lookups()
        if host.domain:
            print ''
            print host.print_dns_only()

    @staticmethod
    def scan_network(network):
        """Does reverse dns lookups on a network object"""
        print ''
        print '# _____________ Reverse DNS lookups on {} _____________ #'.format(str(network))

        network.reverse_lookup_on_related_cidrs(True)

    def write_output_csv(self, filename=None):
        """Writes output for each target as csv in filename"""
        if filename:
            filename = os.path.expanduser(filename)

            print '# Saving output csv file'

            output_as_lines = []

            for host in self.targets:
                try:
                    # Using generator to get one csv line at a time (one Host can yield multiple lines)
                    generator = host.print_as_csv_lines()
                    while True:
                        output_as_lines.append(generator.next())

                except StopIteration:
                    # Space between targets
                    output_as_lines.append(['\n'])

            output_written = False
            while not output_written:

                try:
                    with open(filename, 'wb') as f:
                        writer = csv.writer(f)

                        for line in output_as_lines:
                            writer.writerow(line)

                        output_written = True

                except Exception as e:
                    error = '[-] Something went wrong, can\'t open output file. Press anything to try again.'
                    error = ''.join([error, '\nError: ', str(e)])
                    raw_input(error)

                except KeyboardInterrupt:
                    if raw_input('[-] Sure you want to exit without saving your file (Y/n)?') in ['y', 'Y', '']:
                        sys.exit('# Scan interrupted')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=InstaRecon.entry_banner,
        usage='%(prog)s [options] target1 [target2 ... targetN]',
        epilog=argparse.SUPPRESS,
    )
    parser.add_argument('targets', nargs='+', help='targets to be scanned - can be in the format of a domain (google.com), an IP (8.8.8.8) or a network range (8.8.8.0/24)')
    parser.add_argument('-o', '--output', required=False, nargs='?', help='output filename as csv')
    parser.add_argument('-n', '--nameserver', required=False, nargs='?', help='alternative DNS server to query')
    parser.add_argument('-s', '--shodan_key', required=False, nargs='?', help='shodan key for automated port/service information')
    parser.add_argument('-v', '--verbose', action='store_true', help='verbose errors')
    parser.add_argument('-d', '--dns_only', action='store_true', help='direct and reverse DNS lookups only')
    args = parser.parse_args()

    targets = sorted(set(args.targets))

    if args.shodan_key:
        shodan_key = args.shodan_key
    else:
        shodan_key = os.getenv('SHODAN_KEY')

    scan = InstaRecon(
        nameserver=args.nameserver,
        shodan_key=shodan_key,
        verbose=args.verbose,
        dns_only=args.dns_only,
    )

    try:
        print scan.entry_banner
        scan.populate(targets)
        scan.scan_targets()
        scan.write_output_csv(args.output)
        print scan.exit_banner
    except KeyboardInterrupt:
        sys.exit('# Scan interrupted')
    except (dns.resolver.NoNameservers):
        sys.exit('# Something went wrong. Sure you got internet connection?')
