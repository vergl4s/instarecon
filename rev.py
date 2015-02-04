#!/usr/bin/env python3
import sys, socket, argparse
from abc import ABCMeta, abstractmethod
import pythonwhois as whois #https://github.com/joepie91/python-whois
from ipwhois import IPWhois #https://pypi.python.org/pypi/ipwhois
import ipaddress as ipa #https://docs.python.org/3/library/ipaddress.html
import dns.resolver #http://www.dnspython.org/docs/1.12.0/



class Host(object):
	'''Abstract class for Host being scannedns. IP and Name classes inherit from this.'''
	__metaclass__ = ABCMeta


	def __init__(self):

		self.ip = None
		self.names = []
		self.rev_name = None
		self.geo = None
		self.whois_name = None
		self.whois_ip = None


	@abstractmethod
	def get_results(self):
		""""Return basic information about a Host."""
		return self.names,self.rev_name,self.ip,self.whois_name,self.whois_ip
		pass

	@abstractmethod
	def resolve(self):
		""""Start scanning process for a Host."""
		pass

	def get_host_by_name(self):
		try:
			return str(dns.resolver.query(self.names[0])[0])
		except Exception as e:
			raise e
	
	#TODO - use dns library instead of socket
	def get_host_by_addr(self):
		'''Return a triple (hostname, aliaslist, ipaddrlist) - https://docs.python.org/2/library/socket.html#socket.gethostbyaddr'''
		try:
			return socket.gethostbyaddr(str(self.ip))
		except Exception as e:
			raise e
		

	def get_whois_by_name(self):
		try:
			if self.names[0]:
				return whois.get_whois(self.names[0])
		except Exception as e:
			raise e

	def get_whois_by_rev_name(self):
		try:
			return whois.get_whois(self.rev_name)
		except Exception as e:
			raise e


	def get_whois_by_ip(self):
		if not self.ip.is_private:
			try:
				return IPWhois(str(self.ip)).lookup()
			except Exception as e:
				raise e
				pass


class IP(Host):
	'''Host object created from user entry as IP address.'''

	def __init__(self, user_supplied, from_net=False):
		Host.__init__(self)
		self.ip = user_supplied
		self.from_net = from_net
		print(type(self.ip))

	def get_id(self):
		return self.ip

	def resolve(self):
		self.rev_name = self.get_host_by_addr()[0]
		self.whois_name = self.get_whois_by_rev_name()
		self.whois_ip = self.get_whois_by_ip()
		pass

class Name(Host):
	'''Host object created from user entry as name.'''

	def __init__(self, user_supplied):
		Host.__init__(self)
		self.names.append(user_supplied)

	def get_id(self):
		return self.names[0]

	def resolve(self):
		self.ip = ipa.ip_address(self.get_host_by_name())
		self.rev_name = self.get_host_by_addr()[0]
		self.whois_name = self.get_whois_by_ip()
		self.whois_ip = self.get_whois_by_name()
		pass


class Scan(object):
	'''Class that will hold all Host entries, manage threads and scanning pipeline.'''

	def __init__(self,server=None):

		self.dns_server = server
		self.hosts = []
		self.bad_hosts = []
		
		if self.dns_server:
			#Set DNS server - TODO test this to make sure server is really being changed
			dns.resolver.override_system_resolver(args.dns_server)


	def add_host(self, user_supplied, from_net=False):

		host = None

		try:
			#Is it an IP?
			ip = ipa.ip_address(user_supplied)
			if not (ip.is_multicast or ip.is_unspecified or ip.is_reserved or ip.is_loopback):
				print(type(ip))
				self.hosts.append(IP(ip,from_net))
				return
			else:
				self.bad_hosts.append(user_supplied)
				return
		except Exception as e:
			#print(e)
			pass

		try:
			#Is it a valid network range?
			net = ipa.ip_network(user_supplied)
			#IP is acceptable as a network, but has num_addresses = 1
			if net.num_addresses != 1:
				for ip in net:
					scan.add_host(ip, True)
				return
			else:
				self.bad_hosts.append(user_supplied)
		except Exception as e:
			#print(e)
			pass


		#TODO change this to, instead of resolving, verify characters
		try:
			#is it a valid DNS? Need to check against valid DNS characters
			name = dns.resolver.query(user_supplied)
			self.hosts.append(Name(user_supplied))
			return
		except Exception as e:
			#print('Error with dns resolution') #seems like this library doesn't raise exceptions?
			pass

		self.bad_hosts.append(user_supplied)

	def get_hosts(self):
		return self.hosts

	def get_bad_hosts(self):
		return self.bad_hosts

	def start_full_scan(self):
		for host in self.hosts:
			host.resolve()



if __name__ == '__main__':

	parser = argparse.ArgumentParser(description='Reverse DNS lookup.')
	parser.add_argument('IP', nargs='+', help='IP ranges')
	parser.add_argument('-o', '--output', metavar='output', required=False, nargs='?', help='Output filename')
	parser.add_argument('-s', '--server', metavar='server', required=False, nargs=1, help='Server to resolve')
	args = parser.parse_args()


	scan = Scan(args.server)
	
	for user_supplied in args.IP:
		scan.add_host(user_supplied)

	print('Not scanning', len(scan.get_bad_hosts()), 'hosts')
	print('Scanning',len(scan.get_hosts()),'hosts')
	print('Resolving, please wait')

	scan.start_full_scan()
	
	for host in scan.hosts:
		print('\n#### {} ####\n'.format(host.get_id()))
		results = []
		results = (host.get_results())
		print('names:',results[0])
		print('rev name:',results[1])
		print('ip:',results[2])
		print('whois_name:',results[3])
		print('whois_ip:',results[4])


