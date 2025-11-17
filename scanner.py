import argparse
import ipaddress


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--address", action='store', dest='address', required=True,help="you can use CIDR notation or a something like 1.1.1.1-100. or specify single host")
    parser.add_argument('--mode', choices=['common', 'range', 'all'], required=False, default='common',help='common is 1-1024, range you specify --startport and --endport and all is 1-65535')
    parser.add_argument('--start-port', type=int, action='store', dest='start', required=False, default=1,help='start port of range')
    parser.add_argument('--end-port', type=int, action='store', dest='end', required=False, default=1024,help='end port of range')
    parser.add_argument('-t', '--threads', type=int, action='store', dest='threads', required=False, default=1,help='number of threads')
    parser.add_argument('-d', '--delay', type=float, action='store', dest='delay', required=False, default=1,help='delay in seconds')
    parser.add_argument('--display-only-open', action='store_true', dest='display_only_open', required=False, default=False, help='display only open port')
    parser.add_argument('--output-to-file', action='store_true', dest='output_to_file', required=False, default=False,help='output to file')
    parser.add_argument('--servicescan', action='store_true', dest='servicescan', required=False, default=False, help='service scan')
    parser.add_argument('--show-vulns', action='store_true', dest='show_vulns', required=False, default=False,help='show vulnerabilities')
    return parser.parse_args()

def getIpaddresses(address):
    hosts = []
    if '\\' in address:
        try:
            network = ipaddress.ip_network(address).hosts()
            hosts = [str(network) for ip in network]
            return hosts
        except:
            print("Invalid Cidr range")
    elif '-' in address:
        try:
            segments = address.split('.')
            hostRange = address.split('-')
            for i in range(int(hostRange[1]), int(hostRange[0]) + 1 ):
                hosts.append(f"{segments[0]}.{segments[1]}.{segments[2]}.{i}")
            return hosts
        except:
            print("Invalid host range")
    else:
        try:
            hosts.append(ipaddress.ip_address(address))
            return hosts
        except:
            print("Invalid Host")

    def main():
        args = parse_arguments()
