from netaddr import *
import argparse
import sys
import socket
import whois #https://pypi.python.org/pypi/whois
#for ipwhois https://pypi.python.org/pypi/ipwhois


parser = argparse.ArgumentParser(description='Reverse DNS lookup.')
parser.add_argument('IP', nargs='+', help='IP ranges')
parser.add_argument('-o', '--o', metavar='output', required=False, nargs='?', help='output filename')
args = parser.parse_args()



class Entry:
	def __init__(self, ip, host="", rev_host=""):
		self.ip = ip
		self.host = host
		self.revHost = rev_host

def get_host_by_name(name):
	'''Return a triple (hostname, aliaslist, ipaddrlist) 
			hostname is the primary host name responding to the given ip_address
			aliaslist is a (possibly empty) list of alternative host names for the same address
			ipaddrlist is a list of IPv4 addresses for the same interface on the same host (often but not always a single address). 
		gethostbyname_ex() does not support IPv6 name resolution, and getaddrinfo() should be used instead for IPv4/v6 dual stack support.'''
	return socket.gethostbyname_ex(name)

def get_host_by_addr(ip):
	'''Return a triple (hostname, aliaslist, ipaddrlist) 
			hostname is the primary host name responding to the given ip_address
			aliaslist is a (possibly empty) list of alternative host names for the same address
			ipaddrlist is a list of IPv4/v6 addresses for the same interface on the same host (most likely containing only a single address).
	To find the fully qualified domain name, use the function getfqdn(). gethostbyaddr() supports both IPv4 and IPv6.'''
	return socket.gethostbyaddr(ip)

def main(args):
	scanCount = 0
	resultCount = 0
	#If result is to go to a file, reset the file (could implement check on the file that resumes tests)
	if args.o:
		with open(args.o, 'w') as f:
			f.write('Reverse DNS lookup -- ' + (' ').join(sys.argv) + ' --\n\n')


	for target in args.IP:
		print "Scanning " + target
		target = IPNetwork(target)
		for ip in target:
			scanCount += 1

			name, alias, addresslist = socket.gethostbyaddr(str(ip))

			if len(name) > 1:
				resultCount += 1
				name = str(ip) + ',' + name.rstrip('.\n')
				print name
				if args.o:
					with open(args.o,'a') as f:
						f.write(name + '\n')

	print "Finished scanning", str(scanCount), "targets. Got", str(resultCount)+"/"+str(scanCount),"results."


# if __name__ == '__main__':
#     main()

a = whois.query('8.8.8.8')
print a.__dict__

