from netaddr import *
import os
import argparse
import sys


parser = argparse.ArgumentParser(description='Reverse DNS lookup.')
parser.add_argument('IPs', nargs='+', help='IP ranges')
parser.add_argument('-o', '--o', metavar='output', required=False, nargs='?', help='output filename')
args = parser.parse_args()

scanCount = 0
resultCount = 0


#If result is to go to a file, reset the file (could implement check on the file that resumes tests)
if args.o:
	with open(args.o, 'w') as f:
		f.write('Reverse DNS lookup -- ' + (' ').join(sys.argv) + ' --\n\n')


for target in args.IPs:
	print "Scanning " + target
	target = IPNetwork(target)
	for ip in target:
		scanCount += 1
		com = 'host ' + str(ip)
		r = os.popen(com).read().split('pointer ')
		if len(r) > 1:
			resultCount += 1
			r = str(ip) + ',' + r[1].rstrip('.\n')
			print r
			if args.o:
				with open(args.o,'a') as f:
					f.write(r + '\n')

print "Finished scanning", str(scanCount), "targets. Got", str(resultCount)+"/"+str(scanCount),"results."
