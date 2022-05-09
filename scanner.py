#!/usr/bin/python
import getopt
from sys import argv
from scapy.all import *

welcome_message = 'Opening TCP port scanner '

usage_string = '''
usage: klscng [-s start_port] [-e end_port] [-d destination_ip] [-t timeout]

defaults:

    start_port = 0
    end_port = 1024
    destination_ip = www.google.com
    timeout = 10 seconds
'''


quiet = False
target = 'www.google.com'
start_port = 78
end_port = 82
tout = 10

def usage():
    print(usage_string)

try:
    opts, args = getopt.getopt(sys.argv[1:], 'd:s:e:qt:')
except getopt.GetoptError as err:
    print(err)
    usage()
    sys.exit(2)

for o, a in opts:
    if o == '-d':
        target = a
    elif o == '-s':
        start_port = int(a)
    elif o == '-e':
        end_port = int(a)
    elif o == '-t':
        timeout = int(a)
    elif o == '-q':
        quiet = True
    else:
        assert False, f"Unhandled option: {o}"

if end_port == -1:
    end_port = start_port + 1

if not quiet:
    print(welcome_message)
    usage()

ip = IP(dst=target)

for port in range(start_port, end_port):
    syn = TCP(dport=port, flags='S', seq=1000)
    ans, unans = sr(ip/syn, timeout=tout)

    if not ans:
        print(f'No service running on host {target} on port {port}')
    else:
        print(f'{len(ans)} answered.')
