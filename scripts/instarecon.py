#!/usr/bin/env python
import argparse
import csv
import logging
import os
import sys

import ipaddress as ipa # https://docs.python.org/3/library/ipaddress.html
import dns.resolver

from src.ip import IP
from src.host import Host
from src.network import Network
from src import lookup
from src._version import __version__

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
    entry_banner = '# InstaRecon v' + __version__ + ' - by Luis Teixeira (teix.co)'
    exit_banner = '# Done'

    def __init__(self, nameserver=None, timeout=None,
                shodan_key=None, verbose=0):

        self.targets = set()
        self.bad_targets = set()

        if nameserver:
            lookup.dns_resolver.nameservers = [nameserver]
        if timeout:
            lookup.dns_resolver.timeout = timeout
            lookup.dns_resolver.lifetime = timeout
        if shodan_key:
            lookup.shodan_key = shodan_key

        # https://docs.python.org/2/library/logging.html#logging-levels
        logging_level = 40 # ERROR
        log_format = '[-] %(levelname)s: %(message)s'
        if verbose == 1:
            logging_level = 30 # WARNING
        elif verbose == 2:
            logging_level = 20 # INFO
        elif verbose > 2:
            logging_level = 10 # DEBUG
            log_format = '[-] %(levelname)s:%(module)s:%(funcName)s:%(lineno)d: %(message)s'

        logging.basicConfig(format=log_format, level=logging_level)

    def populate(self, user_supplied_list):
        for user_supplied in user_supplied_list:
            self.add_host(user_supplied)

        if not self.targets:
            print '# No hosts to scan'
        else:
            print '# Scanning', str(len(self.targets)) + '/' + str(len(user_supplied_list)), 'hosts'

            if not lookup.shodan_key:
                print '# No Shodan key provided'

    def add_host(self, user_supplied):
        """
        Add string passed by user to self.targets as proper Host/Network objects
        For this, it attempts to create these objects and moves on if got a ValueError.
        """
        # Test if user_supplied is an IP?
        try:
            self.targets.add(Host(ips=[user_supplied]))
            return
        except ValueError:
            pass

        try:
            self.targets.add(Network(user_supplied))
            return
        except ValueError:
            pass

        # Test if user_supplied is a valid DNS? Needs strict flag, otherwise no ValueError will be raise by Host
        try:
            self.targets.add(Host(domain=user_supplied, strict=False))
            return
        except ValueError:
            logging.critical('Couldn\'t resolve or understand ' + user_supplied)
            pass

        self.bad_targets.add(user_supplied)

    def scan_targets(self):
        for target in self.targets:
            if isinstance(target, Host):
                self.scan_host(target)
            elif isinstance(target, Network):
                self.scan_network(target)

    def scan_host(self, host):
        print ''
        print '# ____________________ Scanning {} ____________________ #'.format(str(host))
        print ''

        # flags_default = not (args.dns or args.whois or args.shodan or args.google)

        # if self.scan_flags['dns'] or flags_default:
        #     self.scan_host_dns(host)
        # if self.scan_flags['whois'] or flags_default:
        #     self.scan_host_whois(host)
        # if self.scan_flags['shodan'] or flags_default:
        #     self.scan_host_shodan(host)
        # if self.scan_flags['google'] or flags_default:
        #     self.scan_host_google(host)

        self.scan_host_dns(host)
        self.scan_host_whois(host)
        self.scan_host_shodan(host)
        self.scan_host_google(host)

    def scan_host_dns(self, host):
        # DNS and Whois lookups
        host.lookup_dns()
        if host.domain:
            print '[*] Domain: ' + host.domain

        # IPs and reverse domains
        if host.ips:
            print ''
            print '[*] IPs & reverse DNS:'
            print host.print_all_ips()

        host.lookup_dns_ns()
        # NS records
        if host.ns:
            print ''
            print '[*] NS records:'
            print host.print_all_ns()

        host.lookup_dns_mx()
        # MX records
        if host.mx:
            print ''
            print '[*] MX records:'
            print host.print_all_mx()
        print ''


    def scan_host_whois(self, host):
        # Domain whois
        host.lookup_whois_domain()
        if host.whois_domain:
            print '[*] Whois domain:'
            print host.whois_domain

        # IP whois
        host.lookup_whois_ip_all()
        m = host.print_all_whois_ip()
        if m:
            for result in m:
                print ''
                print '[*] Whois IP for ' + result

        # CIDRs
        if host.cidrs:
            print ''
            print '[*] Related CIDR:\n{}'.format(host.print_all_cidrs())

        print ''

    def scan_host_shodan(self, host):
        # Shodan
        if lookup.shodan_key:

            print '# Querying Shodan for open ports'

            host.lookup_shodan_all()

            m = host.print_all_shodan()
            if m:
                print '[*] Shodan:'
                print m
            else:
                logging.error('No Shodan entries found')

        else:
            print "# Can't do Shodan lookups without a key (pass one with -s or with unix environment variable SHODAN_KEY)"
        print ''

    def scan_host_google(self, host):
        # Google subdomains lookup
        if host.domain:
            print '# Querying Google for subdomains and Linkedin pages, this might take a while'

            host.google_lookups()

            if host.linkedin_page:
                print '[*] Possible LinkedIn page: ' + host.linkedin_page

            if host.google_subdomains:
                print '[*] Subdomains:' + '\n' + host.print_google_subdomains()
            else:
                logging.error('No subdomains found in Google. If you are scanning a lot, Google might be blocking your requests.')
            print ''

    def scan_network(self, network):
        """Scan a network object"""
        print ''
        print '# _____________ Reverse DNS lookups on {} _____________ #'.format(str(network))
        self.reverse_dns_on_cidr(network)

    @staticmethod
    def reverse_dns_on_cidr(target):
        """Does reverse dns lookups on a target, and saves results to target using target.add_related_host"""
        if not isinstance(target, Network):
            raise ValueError

        cidr = target.cidr

        for ip, reverse_domains in lookup.rev_dns_on_cidr(cidr):

                new_host = Host(ips=[ip], reverse_domains=reverse_domains)
                target.add_related_host(new_host)
                print new_host.print_all_ips()

        if not target.related_hosts:
            print '# No results for this range'

    def test_output_csv(self, filename=None):
        """Test if file is writable before running any scan"""
        if filename:
            with open(filename, 'wb') as f:
                # If file isn't writable this raises an IOError, which is caught in main
                pass

    def write_output_csv(self, filename=None):
        """Writes output for each target as csv in filename"""
        if filename:
            filename = os.path.expanduser(filename)

            print '# Saving output csv file'

            output_as_lines = []

            for host in self.targets:
                for line in host.print_as_csv_lines():
                    output_as_lines.append(line)
                output_as_lines.append(['\n'])

                with open(filename, 'wb') as f:
                    writer = csv.writer(f)

                    for line in output_as_lines:
                        writer.writerow(line)

                    output_written = True

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=InstaRecon.entry_banner,
        usage='%(prog)s [options] target1 [target2 ... targetN]',
        epilog=argparse.SUPPRESS,
    )

    parser.add_argument('targets', nargs='+', help='targets to be scanned - can be a domain (google.com), an IP (8.8.8.8) or a network range (8.8.8.0/24)')
    parser.add_argument('-o', '--output', required=False, nargs='?', help='output filename as csv')
    parser.add_argument('-n', '--nameserver', required=False, nargs='?', help='alternative DNS server to query')
    parser.add_argument('-s', '--shodan_key', required=False, nargs='?', help='shodan key for automated port/service information (SHODAN_KEY environment variable also works for this)')
    parser.add_argument('-t', '--timeout', required=False, nargs='?', type=float, help='timeout for DNS lookups (default is 2s)')
    parser.add_argument('-v', '--verbose', action='count', default=0, help='verbose errors (-vv or -vvv for extra verbosity)')
    # parser.add_argument('--dns', action='store_true', help='DNS lookups')
    # parser.add_argument('--whois', action='store_true', help='whois lookups')
    # parser.add_argument('--shodan', action='store_true', help='shodan lookups')
    # parser.add_argument('--google', action='store_true', help='google lookups')

    args = parser.parse_args()

    targets = sorted(set(args.targets))

    if args.shodan_key:
        shodan_key = args.shodan_key
    else:
        shodan_key = os.getenv('SHODAN_KEY')

    # scan_flags = {
    #     'dns':args.dns,
    #     'whois':args.whois,
    #     'shodan':args.shodan,
    #     'google':args.google,
    # }

    scan = InstaRecon(
        nameserver=args.nameserver,
        shodan_key=shodan_key,
        timeout=args.timeout,
        verbose=args.verbose,
    )

    try:
        print scan.entry_banner
        scan.test_output_csv(args.output)
        scan.populate(targets)
        scan.scan_targets()

    except KeyboardInterrupt:
        logging.warning('Scan interrupted')

    except lookup.NoInternetAccess:
        logging.critical('Something went wrong. Sure you got internet connection?')
        sys.exit()

    except IOError:
        logging.critical('Can\'t write to file.. Better not start scanning anything, right?')
        sys.exit()

    scan.write_output_csv(args.output)
    print scan.exit_banner
