import argparse
import ipaddress
import socket
import sys
import threading
import time

#list of common ports to check against
common_ports_dict = {
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    119: "NNTP",
    123: "NTP",
    135: "Microsoft RPC",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
    139: "NetBIOS Session Service",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP Trap",
    179: "BGP",
    443: "HTTPS",
    445: "Microsoft-DS (SMB)",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP (Submission)",
    631: "IPP",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS Proxy",
    1433: "Microsoft SQL Server",
    1521: "Oracle DB",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    6667: "IRC",
    8000: "HTTP Alternate",
    8080: "HTTP Proxy",
    8443: "HTTPS Alternate",
    8888: "Web Proxy",
    9000: "SonarQube / PHP-FPM",
    9090: "Prometheus / Web Admin",
    9200: "Elasticsearch",
    10000: "Webmin",
    27017: "MongoDB"
}


def parse_arguments():
    '''
    :return: arguments
    '''
    #allows for nice CLI argument parsing
    parser = argparse.ArgumentParser(description='network scanner',usage='scans a given network for open ports')
    parser.add_argument("-a", "--address", action='store', dest='address', required=True,help="you can use CIDR notation or a something like 1.1.1.1-100. or specify single host")
    parser.add_argument('--mode', action='store',dest='portMode',choices=['common', 'range', 'all'], required=False, default='common',help='common is 1-1024, range you specify --startport and --endport and all is 1-65535')
    parser.add_argument('--start-port', type=int, action='store', dest='start', required=False, default=1,help='start port of range')
    parser.add_argument('--end-port', type=int, action='store', dest='end', required=False, default=1024,help='end port of range')
    parser.add_argument('-t', '--threads', type=int, action='store', dest='threads', required=False, default=1,help='number of threads')
    parser.add_argument('-d', '--delay', type=float, action='store', dest='delay', required=False, default=0.3,help='delay in seconds')
    parser.add_argument('--display-only-open', action='store_true', dest='display_only_open', required=False, default=False, help='display only open port')
    parser.add_argument('--output-to-file', action='store_true', dest='output_to_file', required=False, default=False,help='output to file')
    parser.add_argument('--servicescan', action='store_true', dest='servicescan', required=False, default=False, help='service scan')
    parser.add_argument('--show-vulns', action='store_true', dest='show_vulns', required=False, default=False,help='show vulnerabilities')
    return parser.parse_args()

def getIPaddresses(address, threads):
    '''
    :param address: the entered ip address from user
    :return: list of hosts to scan
    '''
    #allows for a range or cidr notation of ip addresses
    hosts = []
    if '/' in address:
        try:
            network = ipaddress.ip_network(address).hosts()
            hosts = [str(ip) for ip in network]
            temp = [[] for i in range(threads)]
            for i in range(len(hosts)):
                temp[i % threads].append(hosts[i])
            return temp
        except:
            sys.exit('invalid CIDR notation')
    elif '-' in address:
        try:
            segments = address.split('.')
            hostRange = address.split('-')
            for i in range(int(hostRange[0]), int(hostRange[1]) + 1 ):
               if i < 255:
                   sys.exit("invalid Octet")
               hosts.append(f"{segments[0]}.{segments[1]}.{segments[2]}.{i}")
            temp = [[] for i in range(threads)]
            for i in range(len(hosts)):
                temp[i % threads].append(hosts[i])
            return temp
        except:
            sys.exit("Invalid host range")
    else:
        try:
            hosts.append(str(ipaddress.ip_address(address)))
            return hosts
        except:
            sys.exit("Invalid Host")
#JL Edit V1
def scan_port(target, port):
    '''
    :param target: target ip address
    :param port: port to scan
    :return: state of port
    '''
    """Simple port scanner -- checks if the port is actually open"""
    try:
        print(f"Scanning {target}... Port {port}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        sock.settimeout(.5)
        result = sock.connect_ex((target, port))

        sock.close()

        if result == 0:
            return "OPEN"
        else:
            return "CLOSED"
    except:
        return "ERROR"
# takes in the info and runs the scan then it outputs to a group of all the threads results for post processing
def busybeeIFMultipleHosts(hosts, ports, delay, groupedResults, index):
    '''
    :param delay: delay between scans
    :param ports: ports to scan
    :param hosts: hosts to scan
    :param groupedResults: the final results of all threads
    :param index: id of thread
    '''
    # multiplies threads and delays to allow the user to have a precise delay so threads are staggered so the packet only gets sent so often
    local = []
    for host in hosts:
        for port in ports:
            if port in common_ports_dict:
                # checks if port is one of the common ones
                state = scan_port(host, port)
                local.append([host,port,common_ports_dict[port],state])

            else:
                state = scan_port(host, port)
                local.append([host,port,'UNKNOWN',state])
            time.sleep(delay)
    groupedResults[index] = local


# only do one host. so only split ports and not hosts
def busyBeeIFOneHost(hosts, ports, delay, groupedResults, index):
    '''
    :param hosts: list of hosts to scan
    :param delay: delay between scanning
    :param ports: list of ports
    :param groupedResults: grouped results
    :param index: id of thread
    '''
    local = []
    for port in ports:
        if port in common_ports_dict:
            # checks if port is one of the common ones
            state = scan_port(hosts[0], port)
            local.append([hosts[0], port, common_ports_dict[port],state])
        else:
            state = scan_port(hosts[0], port)
            local.append([hosts[0], port, 'UNKNOWN'], state)
        time.sleep(delay)
    groupedResults[index] = local

# start of the post-processing function, takes in the results and deals with it
def outPut(time,ifOnlyOpen,ifOutFile,groupedResults):
    fileName = "connectScan_"+str(time)+".txt"




def getPorts(portMode, numberOfHosts, start, end, threads):
    '''
    :param portMode: common, range, all
    :param numberOfHosts: number of hosts to scan
    :param start: start port
    :param end: end port
    :param threads: number of threads
    :return: list of ports to scan or lists of ports to scan
    '''
    listOfPorts = []
    if portMode == "common":
       listOfPorts = list(common_ports_dict.keys())
    elif portMode == "all":
        listOfPorts = list(range(1,65536))
    elif portMode == "range":
        listOfPorts = list(range(start, end+1))
    else:
        raise sys.exit("Invalid portMode")

    if numberOfHosts == 1:
        temp = [[] for i in range(threads)]
        for i in range(len(listOfPorts)):
            temp[i % threads].append(listOfPorts[i])
        return temp

    else:
        return listOfPorts

#UnFinishedFUNC
def main():
    args = parse_arguments()
    scanStart = time.time()
    try: float(args.delay)
    except ValueError: sys.exit('wrong value for delay: needs to be float')

    try: int(args.threads)
    except ValueError: sys.exit('wrong value for threads: needs to be int')

    try: int(args.start)
    except ValueError: sys.exit('wrong value for startport: needs to be int')

    try: int(args.end)
    except ValueError: sys.exit('wrong value for endport: needs to be int')



    hosts = getIPaddresses(args.address, args.threads)
    ports = getPorts(args.portMode, len(hosts), args.start, args.end, args.threads)
    groupedResults = [[] for i in range(args.threads)]
    threads = []


    #create worker threads to then scan all ports. if 1 host is present splits up ports and if multiple hosts then splits up hosts
    for t in range (args.threads):
        if len(hosts) == 1:
            thread = threading.Thread(target=busyBeeIFOneHost,args=(hosts, ports[t],args.delay, groupedResults, t))
            time.sleep(args.delay)
            threads.append(thread)

        else:
            thread = threading.Thread(target=busybeeIFMultipleHosts, args=(hosts[t], ports, args.delay, groupedResults, t))
            threads.append(thread)



    if args.threads != 1:
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    for group in groupedResults:
        for host, port, service, state in group:
            if state == 'OPEN':
                print(f"{host}:{port} ({service}) -> {state}")



main()


