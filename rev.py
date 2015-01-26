#!/usr/bin/env python3
import sys, socket, argparse
import whois #https://pypi.python.org/pypi/whois
from ipwhois import IPWhois #https://pypi.python.org/pypi/ipwhois
import ipaddress as ipa #https://docs.python.org/3/library/ipaddress.html
import dns as d #http://www.dnspython.org/docs/1.12.0/


class Host(object):
	'''
	Object that basically represents 1 IP address and all DNS, reverse DNS, Whois, and geo information associated with it.
		category - 'ip', 'dns', 'net'
		ip = IP address of the entry (unique identifier)
		dns = any DNS that points to the IP address (can have multiple entries)
		rev_dns = reverse DNS got from the IP (only one entry)
		self.geo = geo information
	'''
	
	def __init__(self, user_supplied, server=None):

		self.category = None
		self.ip = None
		self.dns = []
		self.rev_dns = None
		self.geo = None

		#Is it an IP?
		try:
			
			query = ipa.ip_address(user_supplied)
			
			self.category = 'ip'
			self.ip = user_supplied
		except Exception as e:
			#print(e)
			pass
		else:
			#Check if it is not multicast IP
			pass

		if not self.category:
			#Is it a valid network range?
			try:
				
				query = ipa.ip_network(user_supplied)
				
				self.category = 'net'
			except Exception as e:
				#print(e)
				pass

		if not self.category:
			#is it a valid DNS? Need to check against valid DNS characters
			try:
				#Set DNS server - TODO test this to make sure server is really being changed
				d.resolver.override_system_resolver(server)
				
				query = d.resolver.query(user_supplied)
				
				self.category = 'dns'
				self.dns = user_supplied
				
				#TODO maybe multiple results?
				self.ip = self.get_host_by_name()
			except Exception as e:
				#print(e)
				pass

		#if it is still not set, then couldn't read value, kill instance
		if not self.category:
			self.category = 'bad'

	def get_info(self):
		if self.category == 'dns':
			return self.dns
		elif self.category == 'ip':
			return self.ip
		elif self.category == 'net':
			return 'This is a subnet'

	def resolve(self):
		if self.category == 'dns':
			pass
		elif self.category == 'ip':
			pass 

	def resolve_dns(self):
		pass

	def resolve_ip(self):
		pass

	def get_host_by_name(self, name=None):
		'''Return a triple (hostname, aliaslist, ipaddrlist) - https://docs.python.org/2/library/socket.html#socket.gethostbyname_ex'''
		q = name if name else self.dns
		if q: #in case self.dns is not set
			return d.resolver.query(q)[0].to_text

	def get_host_by_addr(self):
		'''Return a triple (hostname, aliaslist, ipaddrlist) - https://docs.python.org/2/library/socket.html#socket.gethostbyaddr'''
		return socket.gethostbyaddr(self.ip)

	def whois_by_hostname(self):
		return whois.query(self.dns).__dict__

	def whois_by_ip(self):
		return IPWhois(str(self.ip)).lookup()


class Scan(object):
	'''
	Class that will hold all Host entries and organise scanning macro
	'''

	def __init__(self):
		self.hosts = []
		pass

	def add(self, host):
		if host.category == 'bad':
			print(host.get_info(), 'bad entry')
		else:
			scan.hosts.append(host)
			print(host.get_info())





if __name__ == '__main__':

	parser = argparse.ArgumentParser(description='Reverse DNS lookup.')
	parser.add_argument('IP', nargs='+', help='IP ranges')
	parser.add_argument('-o', '--output', metavar='output', required=False, nargs='?', help='Output filename')
	parser.add_argument('-s', '--server', metavar='server', required=False, nargs=1, help='Server to resolve')
	args = parser.parse_args()


	scan = Scan()
	
	for entry in args.IP:
		scan.add(Host(entry))

	# scan_count = 0
	# result_count = 0

	# #If result is to go to a file, reset the file (could implement check on the file that resumes tests)
	# if args.o:
	# 	with open(args.o, 'w') as f:
	# 		f.write('Reverse DNS lookup -- ' + (' ').join(sys.argv) + ' --\n\n')


	# for target in args.IP:
	# 	print 'Scanning ' + target
	# 	target = IPNetwork(target)
	# 	for ip in target:
	# 		IPt += 1

	# 		name, alias, addresslist = socket.gethostbyaddr(str(ip))

	# 		if len(name) > 1:
	# 			result_count += 1
	# 			name = str(ip) + ',' + name.rstrip('.\n')
	# 			print name
	# 			if args.o:
	# 				with open(args.o,'a') as f:
	# 					f.write(name + '\n')

	# print 'Finished scanning', str(scan_count), 'targets. Got', str(result_count)+'/'+str(scan_count),'results.'


