from netaddr import *
import os
import argparse
import sys


parser = argparse.ArgumentParser(description='Reverse dns lookup.')
parser.add_argument('strings', nargs='+', help='IP ranges.')
parser.add_argument('-o', required=True, help='Output filename.')
args = parser.parse_args()



print("###########################################################")
print("#                Simple reverse DNS lookup                #")
print("#                     by Luis Teixeira                    #")
print("###########################################################")



#If result is to go to a file, reset the file (could implement check on the file that resumes tests)
if args.o:
	with open(args.o, 'w') as f:
		f.write('Reverse DNS lookup -- ' + (' ').join(sys.argv) + ' --\n\n')


for target in args.strings:
	target = IPNetwork(target)
	for ip in target:
		com = 'host ' + str(ip)
		r = os.popen(com).read().split('pointer ')
		if len(r) > 1:
			
			r = str(ip) + ',' + r[1].rstrip('.\n')
			print r
			with open(args.o,'a') as f:
				f.write(r + '\n')


