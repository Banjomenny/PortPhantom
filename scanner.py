
import ipaddress
import sys
from concurrent.futures import ProcessPoolExecutor

import pyfiglet
from rich.align import Align
from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.panel import Panel
from rich.progress import Progress, TextColumn, BarColumn, TimeRemainingColumn
from rich.table import Table
from rich.text import Text
from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP

threadLock = threading.Lock()
portScanned = 0



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

wellKnownPorts = {
    0: "Reserved",
    1: "TCPMUX",
    5: "RJE",
    7: "ECHO",
    9: "DISCARD",
    11: "SYSTAT",
    13: "DAYTIME",
    17: "QOTD",
    18: "Message Send Protocol",
    19: "CHARGEN",
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    26: "RSFTP",
    35: "QMS Magicolor Printer",
    37: "TIME",
    38: "Route Access Protocol",
    39: "Resource Location Protocol",
    41: "Graphics",
    42: "Host Name Server/WINS",
    43: "WHOIS",
    49: "TACACS",
    53: "DNS",
    57: "MTP",
    67: "BOOTP/DHCP Server",
    68: "BOOTP/DHCP Client",
    69: "TFTP",
    70: "Gopher",
    79: "Finger",
    80: "HTTP",
    81: "Torpark ORPort",
    82: "Torpark Control Port",
    88: "Kerberos",
    101: "HOSTNAME",
    102: "ISO-TSAP / MS Exchange",
    107: "Remote Telnet",
    109: "POP2",
    110: "POP3",
    111: "SUNRPC",
    113: "Ident",
    115: "SFTP",
    117: "UUCP-PATH",
    118: "SQL Services",
    119: "NNTP",
    123: "NTP",
    135: "Microsoft RPC Locator",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
    139: "NetBIOS Session Service",
    143: "IMAP4",
    152: "BFTP",
    153: "SGMP",
    156: "SQL Service",
    157: "KNET VM Command",
    158: "DMSP",
    159: "NSS-Routing",
    160: "SGMP-TRAPS",
    161: "SNMP",
    162: "SNMPTRAP",
    170: "Print-srv",
    179: "BGP",
    190: "GACP",
    191: "Prospero Directory",
    192: "OSU Network Monitoring / SRMP",
    194: "IRC",
    201: "AppleTalk Routing",
    209: "Quick Mail Transfer",
    213: "IPX",
    218: "MPP",
    220: "IMAP v3",
    259: "ESRO",
    264: "BGMP",
    311: "Apple Server Admin",
    318: "TSP",
    323: "IMMP",
    366: "ODMR SMTP",
    369: "Rpc2portmap",
    371: "ClearCase albd",
    384: "Remote Network Server",
    387: "AURP",
    389: "LDAP",
    401: "UPS",
    411: "Direct Connect Hub",
    427: "SLP",
    443: "HTTPS",
    444: "SNPP",
    445: "Microsoft-DS / SMB",
    464: "Kerberos Password Change",
    465: "SMTPS",
    500: "ISAKMP/IKE",
    512: "exec/comsat",
    513: "Login/Who",
    514: "rsh/syslog",
    515: "LPD",
    517: "Talk",
    518: "NTalk",
    520: "efs/RIP",
    524: "NCP",
    525: "Timed",
    530: "RPC",
    531: "AOL IM / IRC",
    532: "netnews",
    533: "netwall",
    540: "UUCP",
    542: "commerce",
    543: "klogin",
    544: "kshell",
    546: "DHCPv6 Client",
    547: "DHCPv6 Server",
    548: "AFP",
    550: "new-who",
    554: "RTSP",
    556: "Remotefs",
    560: "rmonitor",
    561: "monitor/chcmd",
    563: "NNTPS",
    587: "SMTP Submission",
    591: "FileMaker Web Sharing",
    593: "HTTP RPC Ep Map/DCOM",
    604: "TUNNEL",
    631: "IPP",
    636: "LDAPS",
    639: "MSDP",
    646: "LDP",
    647: "DHCP Failover",
    648: "RRP",
    652: "DTCP",
    654: "AODV",
    665: "sun-dr",
    666: "Doom",
    674: "ACAP",
    691: "MS Exchange Routing",
    692: "Hyperwave-ISP",
    695: "IEEE-MMS-SSL",
    698: "OLSR",
    699: "Access Network",
    700: "EPP",
    701: "LMP",
    702: "IRIS over BEEP",
    706: "SILC",
    711: "TDP",
    712: "TBRPF",
    720: "SMQP",
    749: "Kerberos Admin",
    750: "Kerberos IV",
    782: "Conserver",
    829: "CMP",
    860: "iSCSI",
    873: "rsync",
    901: "SWAT",
    902: "VMware Server",
    911: "NCA Console",
    981: "SofaWare HTTPS Mgmt",
    989: "FTPS Data",
    990: "FTPS Control",
    991: "NAS",
    992: "Telnet over SSL",
    993: "IMAPS",
    995: "POP3S",
}




class Color(Enum):
    BLACK = 0
    RED = 1
    GREEN = 2
    YELLOW = 3
    BLUE = 4
    PURPLE = 5
    CYAN = 6
    WHITE = 7
    BOLDGREEN = 8
    BOLDRED = 9
    BOLDWHITE = 10
def stringInColor(color,text ):
    '''
    :param color:  Color enum class value of the color you want
    :param text: the selected text you wanna make colorful
    :return: the string that makes the text colorful
    '''
    os.system("color")
    RESET = '\033[0m'
    COLORS = {
     0: "\033[0;30m",
     1: "\033[0;31m",
     2: "\033[0;32m",
     3: "\033[0;33m",
     4: "\033[0;34m",
     5: "\033[0;35m",
     6: "\033[0;36m",
     7: "\0333[0;37m",
     8: "\033[1;32m",
     9: "\033[1;31m",
     10: "\033[1;37m",
    }
    return COLORS[color.value] + text + RESET

def checkHostStatus(hostname):
    platform = os.name
    response = ""
    match platform:
        case 'posix':
            ping_command = f"ping -c 1 {hostname}"
            response = os.system(f"{ping_command} > /dev/null 2>&1")
        case 'nt':
            ping_command = f"ping -n 1 {hostname}"
            response = os.system(f"{ping_command} > NUL")
        case _:
            return 1
    return response

def textual_interface():
    parser = parse_arguments()
    args = parser.parse_args([])
    args.start = 1
    args.end = 1024
    console = Console()
    console.rule("[bold blue]Network Scanner Setup[/bold blue]")

    args.address = Prompt.ask(
        "[cyan]Target address[/cyan] (CIDR, range, or single host)",
        default="127.0.0.1"
    )

    port_table = Table(title="Port Modes")
    port_table.add_column("Option", style="magenta")
    port_table.add_column("Description", style="green")
    port_table.add_row("wellknown", "Ports 1-1024")
    port_table.add_row("range", "Custom start/end")
    port_table.add_row("web", "common web ports")
    port_table.add_row("database", "common database ports")
    port_table.add_row("fileShare", "common filesharing ports")
    port_table.add_row("mail", "common ports used for mail")
    port_table.add_row("remoteAccess", "ports assoicated with remote access")
    port_table.add_row("common", "most common ports")
    port_table.add_row("single", "Specify one port or list")
    console.print(port_table)


    args.portMode = Prompt.ask(
        "[cyan]Choose port mode[/cyan]",
        choices=['common', 'range', 'all', 'single','wellKnown', 'web', 'database', 'remoteAccess', 'fileShare', 'mail'],
        default="common"
    )

    if args.portMode == "range":
        args.start = IntPrompt.ask("[yellow]Enter start port[/yellow]", default=1)
        args.end = IntPrompt.ask("[yellow]Enter end port[/yellow]", default=1024)
    elif args.portMode == "single":
        args.port = Prompt.ask("[yellow]Enter port(s)[/yellow] (comma separated)")

    scan_map = {
        "syn": "SYN Scan (-sS)",
        "ack": "ACK Scan (-sA)",
        "rst": "RST Scan (-sR)",
        "fin": "FIN Scan (-sF)",
        "connect": "Connect Scan (-sC)",
        "arpping": "ARP Ping (-aP)"
    }

    scan_table = Table(title="Scan Types")
    scan_table.add_column("Type", style="magenta")
    scan_table.add_column("Description", style="green")
    for key, desc in scan_map.items():
        scan_table.add_row(key, desc)
    console.print(scan_table)

    args.scanType = Prompt.ask(
        "[cyan]Choose scan type[/cyan]",
        choices=list(scan_map.keys()),
        default="connect"
    )

    args.threads = IntPrompt.ask("[cyan]Number of threads[/cyan]", default=1)
    args.delay = float(Prompt.ask("[cyan]Delay between probes[/cyan]", default='0.1'))

    args.display = Prompt.ask(
        "[cyan]Display mode[/cyan]",
        choices=["all", "open", "closed"],
        default="all"
    )

    args.output_file = Prompt.ask("[cyan]Output filename[/cyan] (optional)", default="")
    args.output_format = Prompt.ask(
        "[cyan]Output format[/cyan]",
        choices=["txt", "csv"],
        default="txt"
    )

    if args.scanType is 'connect':
        args.servicescan = Confirm.ask("[cyan]Enable service scan?[/cyan]", default=False)
    args.show_vulns = Confirm.ask("[cyan]Show vulnerabilities?[/cyan]", default=False)
    args.do_pings = Confirm.ask("[cyan]Do ping sweep?[/cyan]", default=False)

    console.rule("[bold green]Final Configuration[/bold green]")

    return args


def parse_arguments():
    '''
    :return: arguments
    '''




    #allows for nice CLI argument parsing


    parser = argparse.ArgumentParser(description='network scanner',usage='scans a given network for open ports')
    groupPort = parser.add_mutually_exclusive_group(required=False)
    groupPort.add_argument('--portList', action='store',dest='portMode',choices=['common', 'range', 'all', 'single','wellKnown', 'web', 'database', 'remoteAccess', 'fileShare', 'mail'], required=False, default='common',help='common is 1-1024, range you specify --startport and --endport and all is 1-65535')
    groupPort.add_argument('-p','--port', action='store', dest='port', required=False, default=None,help='choose the port you want or a list like 1,2,3,4,5,6,7')

    groupScan = parser.add_mutually_exclusive_group(required=False)
    groupScan.add_argument('-sS', action='store_const',dest='scanType',const='syn',help='synscan')
    groupScan.add_argument('-sA', action='store_const',dest='scanType',const='ack',help='ack scan')
    groupScan.add_argument('-sR', action='store_const',dest='scanType',const='rst',help='rst scan')
    groupScan.add_argument('-sF', action='store_const',dest='scanType',const='fin',help='fin scan')
    groupScan.add_argument('-sC', action='store_const',dest='scanType',const='connect',help='connect scan \\ vannila scan')
    groupScan.add_argument('-aP', action='store_const',dest='scanType',const='arpping',help='arp ping')


    parser.add_argument("-a", "--address", action='store', dest='address', required=False,help="you can use CIDR notation or a something like 1.1.1.1-100. or specify single host")
    parser.add_argument('-t', '--threads', type=int, action='store', dest='threads', required=False, default=1,help='number of threads')
    parser.add_argument('-d', '--delay', type=float, action='store', dest='delay', required=False, default=0.1,help='delay in seconds')
    parser.add_argument('--display', action='store',choices=['all','open','closed'], dest='display', required=False, default='all', help='chose what ports to be diplayed, all, open, closed')
    parser.add_argument('-out','--output-to-file', type=str, dest='output_file', required=False, default=None, help='output filename (e.g., results.txt or results.csv)') #JL output
    parser.add_argument('-f','--output-format', choices=['txt', 'csv'], default='txt', help='output format: txt or csv') #JL output
    parser.add_argument('-sv','--servicescan', action='store_true', dest='servicescan', required=False, default=False, help='service scan')
    parser.add_argument('--show-vulns', action='store_true', dest='show_vulns', required=False, default=False,help='show vulnerabilities')
    parser.add_argument('-ps','--pingsweep', action='store_true', dest='do_pings', required=False, default=False,help='do a ping sweep to only scan up hosts')


    return parser

def parsePort(input):
    portsstr = None
    ports = []
    if input:
        portsstr = input.split(',')
    for port in portsstr:
        try:
            ports.append(int(port))
        except ValueError:
            raise argparse.ArgumentTypeError("Invalid port number")
    return ports

def getIPaddresses(address, threads):
    '''
    :param address: the entered ip address from user
    :return: list of hosts to scan
    '''
    #allows for a range or cidr notation of ip addresses
    hosts = []
    address = address.strip()

    if '/' in address:
        try:
            network = ipaddress.ip_network(address).hosts()
            hosts = [str(ip) for ip in network]
            return hosts
        except:
            sys.exit('invalid CIDR notation')
    elif '-' in address:
        try:
            segments = address.split('.')
            hostRange = segments[3].split('-')
            for i in range(int(hostRange[0]), int(hostRange[1]) + 1 ):
               if i > 255:
                   sys.exit("invalid Octet")
               hosts.append(f"{segments[0]}.{segments[1]}.{segments[2]}.{i}")
            return hosts

        except Exception as e:
            print(e)
            sys.exit("Invalid host range")
    else:
        try:
            hosts.append(address)
            return hosts
        except:
            print("you get an error")
            sys.exit("Invalid Host")
#JL Edit V1


def scan_port_with_progress(target, port, ifServiceScan, progress, taskID):
    result = scan_port_connect(target, port, ifServiceScan)
    global portScanned
    with threadLock:
        portScanned += 1
        progress.update(taskID, completed=portScanned)

    return result


def scan_port_connect(target, port, ifServiceScan):
    '''
    :param target: target ip address
    :param port: port to scan
    :return: state of port
    '''
    """Simple port scanner -- checks if the port is actually open"""
    global portScanned

    try:

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((target, port))

        banner = ""

        if ifServiceScan:
                if port in [21, 22, 23, 25, 110, 143, 3306, 5432, 6379, 6667]:
                    try:
                        banner = sock.recv(4096).decode(errors='ignore')
                    except:
                        banner = "NO BANNER"
                elif port in [80, 8080, 8888, 9000, 9200, 10000]:
                    probe = f"GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
                    try:
                        sock.sendall(probe.encode())
                        sock.settimeout(4)
                        response = []
                        while True:
                            try:
                                data = sock.recv(4096)
                                if not data:
                                    break
                                response.append(data.decode(errors='ignore'))
                            except socket.timeout:
                                break
                        raw = ''.join(response) if response else None

                        headers, _, body = raw.partition("\r\n\r\n")


                        # Grab the Server line
                        for line in headers.splitlines():
                            line = line.strip()
                            if line.lower().startswith("server:"):

                                banner = line
                                break
                        else:
                            banner = headers.splitlines()[0]

                    except Exception:
                        banner = "NO BANNER"
        service = 'UNKNOWN'
        banner = banner.strip()

        if port in common_ports_dict.keys():
            service = common_ports_dict[port]
        elif port in wellKnownPorts.keys():
            service = wellKnownPorts[port]
        else:
            service = 'TCP/UDP'

        if ifServiceScan:
            return {
                'host': target,
                'port': port,
                'service': service,
                'banner': banner,
                'state': 'OPEN' if result == 0 else 'CLOSED'
            }
        else:
            return {
                'host': target,
                'port': port,
                'service': service,
                'state': 'OPEN' if result == 0 else 'CLOSED'
            }
    except:
        if ifServiceScan:
               return {
                'host': target,
                'port': port,
                'service': 'ERROR',
                'banner': None,
                'state': 'ERROR'
                }
        else:
            return {
                'host': target,
                'port': port,
                'service': 'ERROR',
                'state': 'ERROR'
            }
# takes in the info and runs the scan then it outputs to a group of all the threads results for post processing
def busybeeIFMultipleHosts(hosts, ports, delay, groupedResults, index, ifServiceScan, progress, taskID):
    '''
    :param delay: delay between scans
    :param ports: ports to scan
    :param hosts: hosts to scan
    :param groupedResults: the final results of all threads
    :param index: id of thread
    '''
    # multiplies threads and delays to allow the user to have a precise delay so threads are staggered so the packet only gets sent so often


    for host in hosts:
        local = []
        target = host
        if isinstance(ports, list):
            for port in ports:
                local.append(scan_port_with_progress(target, port, ifServiceScan, progress,taskID))

        else:
            local.append(scan_port_with_progress(target, ports, ifServiceScan, progress, taskID))
        groupedResults[index] = local


# only do one host. so only split ports and not hosts
def busyBeeIFOneHost(hosts, ports, delay, groupedResults, index, ifServiceScan, progress,taskID):
    '''
    :param hosts:
    :param ports:
    :param delay:
    :param groupedResults:
    :param index:
    :return:
    '''

    local = []
    target = hosts[0]
    if isinstance(ports, list):
        for port in ports:
            local.append(scan_port_with_progress(target, port, ifServiceScan, progress, taskID))

    else:
        local.append(scan_port_with_progress(target, ports, ifServiceScan, progress, taskID))
    groupedResults[index] = local

def save_as_csv(fileName, finalOutput, args):
    """Save results in CSV format"""
    import csv
    
    with open(fileName, 'w', newline='') as f:
        if args.servicescan:
            writer = csv.writer(f)
            writer.writerow(['Host', 'Port', 'Service', 'State', 'Banner'])
            
            for host in finalOutput.keys():
                for result in finalOutput[host]:
                    port, service, state, banner = result
                    
                    if args.display == 'all' or \
                       (args.display == 'open' and state == 'OPEN') or \
                       (args.display == 'closed' and state == 'CLOSED'):
                        banner_text = banner if banner else ""
                        writer.writerow([host, port, service, state, banner_text])
        else:
            writer = csv.writer(f)
            writer.writerow(['Host', 'Port', 'Service', 'State'])
            
            for host in finalOutput.keys():
                for result in finalOutput[host]:
                    port, service, state = result
                
                    if args.display == 'all' or \
                       (args.display == 'open' and state == 'OPEN') or \
                       (args.display == 'closed' and state == 'CLOSED'):
                        writer.writerow([host, port, service, state])

def save_as_txt(fileName, finalOutput, args):
    """Save results in TXT format"""
    with open(fileName, 'w') as f:
        f.write("="*70 + "\n")
        f.write(f"PORT SCAN REPORT\n")
        f.write(f"Timestamp: {time.ctime()}\n")
        f.write(f"Target(s): {args.address}\n")
        f.write(f"Port Mode: {args.portMode}\n")
        f.write(f"Threads: {args.threads}\n")
        f.write("="*70 + "\n\n")
        
        for host in finalOutput.keys():
            f.write(f"\n{'='*70}\n")
            f.write(f"Host: {host}\n")
            f.write(f"{'-'*70}\n")
            f.write(f"{'Port':<10} {'Service':<25} {'State':<10}\n")
            f.write(f"{'-'*70}\n")
            
            for result in finalOutput[host]:
                if args.servicescan:
                    port, service, state, banner = result
                    # ✅ NEW: Respect --display filter
                    if args.display == 'all' or \
                       (args.display == 'open' and state == 'OPEN') or \
                       (args.display == 'closed' and state == 'CLOSED'):
                        f.write(f"{port:<10} {service:<25} {state:<10}")
                        if banner and banner != "NO BANNER":
                            f.write(f" | {banner[:50]}")
                        f.write("\n")
                else:
                    port, service, state = result
                    # ✅ NEW: Respect --display filter
                    if args.display == 'all' or \
                       (args.display == 'open' and state == 'OPEN') or \
                       (args.display == 'closed' and state == 'CLOSED'):
                        f.write(f"{port:<10} {service:<25} {state:<10}\n")
        
        f.write("\n" + "="*70 + "\n")
        f.write("END OF REPORT\n")

# start of the post-processing function, takes in the results and deals with it #JL OUTPUT
def outputFile(timestamp, finalOutput, args):
    """Save scan results to file in txt or csv format"""
    
    # Determine filename
    if args.output_file:
        fileName = args.output_file
    else:
        extension = 'csv' if args.output_format == 'csv' else 'txt'
        fileName = f"connectScan_{int(timestamp)}.{extension}"
    
    # Save based on format
    if args.output_format == 'csv':
        save_as_csv(fileName, finalOutput, args)
    else:
        save_as_txt(fileName, finalOutput, args)
    
    print(f"\n[+] Results saved to: {fileName}")

def osDetection(hostOutput, host):
    linux_distros = ["Ubuntu", "Debian", "Red Hat", "CentOS", "FreeBSD", "Raspbian"]
    microsoft_keywords = ['Microsoft', 'Windows']
    apple_keywords = ['Darwin', 'Apple']
    OS = ''

    try:
        for port, service, state, banner in hostOutput:

            for distro in linux_distros:
                if distro.lower() in banner.lower():
                    return f"Linux ({distro})"

            for keyword in microsoft_keywords:
                if keyword.lower() in banner.lower():
                    return "Windows"

            for keyword in apple_keywords:
                if keyword.lower() in banner.lower():
                    return "MacOS"
    except Exception as e:
        OS = ''

    packet = IP(dst=host)/ICMP()
    reply = sr1(packet, timeout=2, verbose=0)
    if reply is None:
        return OS if OS else "No response"

    ttl = reply.ttl
    if OS == '':
        if ttl <= 64:
            OS = 'likely Linux/macOS/Unix'
        elif ttl <= 128:
            OS = 'likely Windows'
        elif ttl <= 255:
            OS = 'likely Cisco/network device'
        else:
            OS = f'Unknown OS'
    return OS

def scanPort(host, scanningPort, flag, scanType):
        state = 'UNKNOWN'
        service = common_ports_dict.get(scanningPort, wellKnownPorts.get(scanningPort, 'TCP/UDP'))

        try:
            ans, unans = sr(IP(dst=host) / TCP(dport=scanningPort, flags=flag), timeout=2, verbose=0)
        except Exception:
            return [scanningPort, service, state]

        if ans:
            for snd, rcv in ans:
                tcp = rcv.getlayer(TCP)
                if tcp:
                    if scanType == 'syn':
                        if tcp.flags == 0x12:
                            state = 'OPEN'
                            sr(IP(dst=host) / TCP(dport=scanningPort, flags="R"), timeout=1, verbose=0)
                        elif tcp.flags == 0x14:
                            state = 'CLOSED'
                    elif scanType == 'ack':
                        if tcp.flags == 0x14:
                            state = "UNFILTERED"
                    elif scanType == 'rst':
                        state = "CLOSED" if tcp.flags == 0x14 else "OPEN|FILTERED"
                    elif scanType == 'fin':
                        state = "CLOSED" if tcp.flags == 0x14 else "OPEN|FILTERED"
        else:
            match scanType:
                case 'syn' | 'ack':
                    state = 'FILTERED'
                case 'rst' | 'fin':
                    state = 'OPEN|FILTERED'

        return [scanningPort, service, state]


def scapyScan(host, ports, scanType, progress, taskID):
    results = []
    flag = {'syn':'S','ack':'A','rst':'R','fin':'F'}.get(scanType, '')

    with ProcessPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(scanPort, host, p, flag, scanType) for p in ports]
        for fut in futures:
            result = fut.result()
            results.append(result)
            # update progress here in parent
            progress.update(taskID, advance=1)

    return results



def getPorts(portMode, numberOfHosts, start, end, threads,scanType, inputPorts = None):
    '''
    :param inputPorts:
    :param portMode: common, range, all
    :param numberOfHosts: number of hosts to scan
    :param start: start port
    :param end: end port
    :param threads: number of threads
    :return: list of ports to scan or lists of ports to scan
    '''
    if inputPorts:
        return parsePort(inputPorts)
    else:
        listOfPorts = []
        match portMode:
            case 'common':
                listOfPorts = list(common_ports_dict.keys())
            case 'wellKnown':
                listOfPorts = list(range(1, 1025))
            case 'range':
                listOfPorts = list(range(start, end + 1))
            case 'all':
                listOfPorts = list(range(1, 65536))
            case 'web':
                listOfPorts = [80,443,8080,8443,8888,9000,9200,10000]
            case 'database':
                listOfPorts = [1433,1521,3306,5432,27017,6479]
            case 'mail':
                listOfPorts = [25,465,587,110,995,143,993]
            case 'remoteAccess':
                listOfPorts = [22,23,3389,5900]
            case 'fileShare':
                listOfPorts = [20,21,445,137,138,139,69]
            case _:
                listOfPorts =list(range(1, 1025))

        if numberOfHosts == 1 and scanType == 'connect':
            temp = [[] for i in range(threads)]
            for i in range(len(listOfPorts)):
                temp[i % threads].append(listOfPorts[i])
            return temp

        else:
            return listOfPorts

def validate_ports(ports, args):
    """
    Task 8: Port Range Validation - Check for commonly used ports and display warnings
    """
    if ports and isinstance(ports[0], list):
        flat_ports = []
        for sublist in ports:
            flat_ports.extend(sublist)
        ports = flat_ports
    
    well_known = [p for p in ports if p < 1024]
    
    if well_known:
        print("\n" + "="*70)
        print(stringInColor(Color.YELLOW, "⚠  PORT RANGE VALIDATION WARNING"))
        print("="*70)
        print(stringInColor(Color.YELLOW, 
              f"[!] You are scanning {len(well_known)} well-known ports."))
        print(stringInColor(Color.YELLOW, 
              f"[!] Total ports to scan: {len(ports)}"))
        print(stringInColor(Color.YELLOW, 
              "[!] This may trigger IDS/IPS alerts or security monitoring!"))
        input(stringInColor(Color.YELLOW,
                    "Press any key to continue SCANNING"))


        # Check for particularly sensitive ports
        sensitive_ports = {
            21: {
                'name': 'FTP',
                'risk': 'Often targeted, logs access attempts',
                'recommendation': 'Use SFTP (port 22) or FTPS instead'
            },
            22: {
                'name': 'SSH',
                'risk': 'Failed attempts trigger security alerts',
                'recommendation': 'Ensure you have authorization before scanning'
            },
            23: {
                'name': 'Telnet',
                'risk': 'Insecure protocol, Not Encrypted, heavily monitored',
                'recommendation': 'Use SSH (port 22) instead of Telnet'
            },
            25: {
                'name': 'SMTP',
                'risk': 'Mail server scanning may trigger alerts',
                'recommendation': 'Only scan with explicit permission'
            },
            135: {
                'name': 'Microsoft RPC',
                'risk': 'Common ransomware target, heavily monitored',
                'recommendation': 'Avoid scanning unless absolutely necessary'
            },
            139: {
                'name': 'NetBIOS',
                'risk': 'Can leak system information',
                'recommendation': 'Should not be exposed to internet'
            },
            445: {
                'name': 'SMB',
                'risk': 'EternalBlue exploit vector, heavily monitored',
                'recommendation': 'Avoid scanning SMB ports without authorization'
            },
            3306: {
                'name': 'MySQL',
                'risk': 'Database should not be internet facing',
                'recommendation': 'Use VPN or SSH tunnel or Proxy Server instead'
            },
            3389: {
                'name': 'RDP',
                'risk': 'Prime target for ransomware attacks',
                'recommendation': 'Use VPN or disable RDP internet access'
            },
            5432: {
                'name': 'PostgreSQL',
                'risk': 'Database should not be internet-facing',
                'recommendation': 'Use VPN or SSH tunnel instead'
            },
            6379: {
                'name': 'Redis',
                'risk': 'Often left with no authentication',
                'recommendation': 'Should never be exposed to internet'
            },
            27017: {
                'name': 'MongoDB',
                'risk': 'Frequently targeted for data theft',
                'recommendation': 'Enable authentication and use VPN'
            }
        }
        
        # Display warnings for sensitive ports being scanned
        found_sensitive = False
        for port in ports:
            if port in sensitive_ports:
                if not found_sensitive:
                    print(stringInColor(Color.BOLDRED, "SENSITIVE PORTS DETECTED:"))
                    print("-"*70)
                found_sensitive = True
                
                info = sensitive_ports[port]
                print(f"\n{stringInColor(Color.BOLDRED, f'Port {port}')} ({info['name']})")
                print(f"  Risk: {info['risk']}")
                print(f"  {stringInColor(Color.GREEN, '✓ Recommendation:')} {info['recommendation']}")
        
        print("\n" + "="*70 + "\n")
        input(stringInColor(Color.YELLOW,
                            "Are you still sure you wanna continue SCANNING?"))
        print('\n\n')

def validate_open_ports(finalOutput, args):
    """
    Task 8: Port Validation - Warn about OPEN sensitive ports AFTER scan completes
    """
    # Collect all OPEN ports from scan results
    open_ports = set()
    for host in finalOutput.keys():
        for result in finalOutput[host]:
            if args.servicescan:
                port, service, state, banner = result
            else:
                port, service, state = result
            
            if state == 'OPEN':
                open_ports.add(port)
    
    if not open_ports:
        return  # No open ports, nothing to warn about
    
    # Check for well-known ports
    well_known = [p for p in open_ports if p < 1024]
    
    if well_known:
        print("\n" + "="*70)
        print(stringInColor(Color.YELLOW, "⚠  OPEN PORT SECURITY WARNING"))
        print("="*70)
        print(stringInColor(Color.YELLOW, 
              f"[!] Found {len(well_known)} open well-known ports."))
        print(stringInColor(Color.YELLOW, 
              f"[!] Total open ports: {len(open_ports)}"))
        print(stringInColor(Color.YELLOW, 
              "[!] These ports may be vulnerable to attacks!"))
        print()

        # Check for particularly sensitive ports
        sensitive_ports = {
            21: {
                'name': 'FTP',
                'risk': 'Often targeted, logs access attempts',
                'recommendation': 'Use SFTP (port 22) or FTPS instead'
            },
            22: {
                'name': 'SSH',
                'risk': 'Failed attempts trigger security alerts',
                'recommendation': 'Ensure you have authorization and strong passwords'
            },
            23: {
                'name': 'Telnet',
                'risk': 'Insecure protocol, Not Encrypted, heavily monitored',
                'recommendation': 'DISABLE IMMEDIATELY - Use SSH (port 22) instead'
            },
            25: {
                'name': 'SMTP',
                'risk': 'Mail server may be exploited for spam',
                'recommendation': 'Ensure authentication is required'
            },
            135: {
                'name': 'Microsoft RPC',
                'risk': 'Common ransomware target, heavily monitored',
                'recommendation': 'Block at firewall, disable if not needed'
            },
            139: {
                'name': 'NetBIOS',
                'risk': 'Can leak system information',
                'recommendation': 'Should not be exposed to internet'
            },
            445: {
                'name': 'SMB',
                'risk': 'EternalBlue exploit vector, heavily monitored',
                'recommendation': 'CRITICAL: Never expose SMB to internet!'
            },
            3306: {
                'name': 'MySQL',
                'risk': 'Database should not be internet facing',
                'recommendation': 'Bind to localhost, use VPN or SSH tunnel'
            },
            3389: {
                'name': 'RDP',
                'risk': 'Prime target for ransomware attacks',
                'recommendation': 'Use VPN, enable NLA, implement lockout policies'
            },
            5432: {
                'name': 'PostgreSQL',
                'risk': 'Database should not be internet-facing',
                'recommendation': 'Bind to localhost, use VPN or SSH tunnel'
            },
            6379: {
                'name': 'Redis',
                'risk': 'Often left with no authentication',
                'recommendation': 'Should NEVER be exposed to internet'
            },
            27017: {
                'name': 'MongoDB',
                'risk': 'Frequently targeted for data theft',
                'recommendation': 'Enable authentication and use VPN'
            }
        }
        
        # Display warnings for OPEN sensitive ports only
        found_sensitive = False
        for port in open_ports:
            if port in sensitive_ports:
                if not found_sensitive:
                    print(stringInColor(Color.BOLDRED, "⚠️  CRITICAL: SENSITIVE PORTS ARE OPEN!"))
                    print("-"*70)
                found_sensitive = True
                
                info = sensitive_ports[port]
                print(f"\n{stringInColor(Color.BOLDRED, f'Port {port}')} ({info['name']}) - OPEN")
                print(f"  Risk: {info['risk']}")
                print(f"  {stringInColor(Color.GREEN, '✓ Recommendation:')} {info['recommendation']}")
        
        print("\n" + "="*70 + "\n")

def output(hosts, results, ifServicescan):
    finalOutput = {host: [] for host in hosts}
    for host in hosts:
        seen = set()
        for group in results:
            for result in group:
                host = result.get('host')
                if ifServicescan:
                    finalOutput[host].append([result.get('port'), result.get('service'), result.get('state'), result.get('banner')])
                else:
                    finalOutput[host].append(
                        [result.get('port'), result.get('service'), result.get('state')])
    return finalOutput


def security_scan_report(finalOutput, args):
    """
    Task 11: Security Scanning - Check for vulnerabilities in open ports
    """
    if not args.show_vulns:
        return
    
    # Define vulnerability database
    VULNERABILITY_DB = {
        21: {
            'severity': 'HIGH',
            'service': 'FTP',
            'issue': 'FTP transmits credentials in plaintext',
            'impact': 'Credentials can be intercepted by attackers',
            'recommendation': 'Disable FTP and use SFTP (port 22) or FTPS instead'
        },
        23: {
            'severity': 'CRITICAL',
            'service': 'Telnet',
            'issue': 'Telnet is completely unencrypted',
            'impact': 'All traffic including passwords sent in plaintext',
            'recommendation': 'Disable Telnet immediately, use SSH (port 22) instead'
        },
        69: {
            'severity': 'MEDIUM',
            'service': 'TFTP',
            'issue': 'TFTP has no authentication mechanism',
            'impact': 'Anyone can read/write files',
            'recommendation': 'Disable TFTP or restrict access with firewall rules'
        },
        80: {
            'severity': 'LOW',
            'service': 'HTTP',
            'issue': 'HTTP traffic is unencrypted',
            'impact': 'Data can be intercepted in transit',
            'recommendation': 'Use HTTPS (port 443) with valid SSL/TLS certificates'
        },
        135: {
            'severity': 'HIGH',
            'service': 'Microsoft RPC',
            'issue': 'RPC exposed to network',
            'impact': 'Target for WannaCry-style ransomware attacks',
            'recommendation': 'Block port 135 at firewall, disable if not needed'
        },
        139: {
            'severity': 'HIGH',
            'service': 'NetBIOS',
            'issue': 'NetBIOS can leak system information',
            'impact': 'Attackers can enumerate users, shares, and services',
            'recommendation': 'Disable NetBIOS or restrict to local network only'
        },
        445: {
            'severity': 'CRITICAL',
            'service': 'SMB',
            'issue': 'SMB is prime ransomware attack vector (EternalBlue)',
            'impact': 'Remote code execution, lateral movement, data theft',
            'recommendation': 'Never expose SMB to internet, use VPN for remote access'
        },
        3306: {
            'severity': 'CRITICAL',
            'service': 'MySQL',
            'issue': 'Database exposed to network',
            'impact': 'Data breach, unauthorized access, data manipulation',
            'recommendation': 'Bind to localhost only, use VPN or SSH tunnel for remote access'
        },
        3389: {
            'severity': 'CRITICAL',
            'service': 'RDP',
            'issue': 'RDP is frequent ransomware entry point',
            'impact': 'Brute force attacks, remote takeover, ransomware deployment',
            'recommendation': 'Use VPN, enable NLA, implement account lockout policies'
        },
        5432: {
            'severity': 'CRITICAL',
            'service': 'PostgreSQL',
            'issue': 'Database exposed to network',
            'impact': 'Data breach, unauthorized access, data manipulation',
            'recommendation': 'Bind to localhost only, use VPN or SSH tunnel for remote access'
        },
        6379: {
            'severity': 'CRITICAL',
            'service': 'Redis',
            'issue': 'Redis often has no authentication by default',
            'impact': 'Complete data access, code execution via Lua scripts',
            'recommendation': 'Enable authentication, bind to localhost, use firewall'
        },
        27017: {
            'severity': 'CRITICAL',
            'service': 'MongoDB',
            'issue': 'MongoDB frequently misconfigured without auth',
            'impact': 'Data theft, ransomware, database deletion',
            'recommendation': 'Enable authentication, bind to localhost, use VPN'
        },
        1433: {
            'severity': 'HIGH',
            'service': 'MS SQL Server',
            'issue': 'SQL Server exposed to network',
            'impact': 'Data breach, SQL injection attacks',
            'recommendation': 'Restrict access, use Windows auth, enable encryption'
        },
        5900: {
            'severity': 'HIGH',
            'service': 'VNC',
            'issue': 'VNC often has weak or no password',
            'impact': 'Remote desktop access, full system control',
            'recommendation': 'Use strong passwords, enable encryption, use SSH tunnel'
        }
    }
    
    # Collect vulnerabilities from scan results
    vulnerabilities = {
        'CRITICAL': [],
        'HIGH': [],
        'MEDIUM': [],
        'LOW': []
    }
    
    for host in finalOutput.keys():
        for result in finalOutput[host]:
            if args.servicescan:
                port, service, state, banner = result
            else:
                port, service, state = result
            
            # Only report on OPEN ports with known vulnerabilities
            if state == 'OPEN' and port in VULNERABILITY_DB:
                vuln = VULNERABILITY_DB[port].copy()
                vuln['host'] = host
                vuln['port'] = port
                vulnerabilities[vuln['severity']].append(vuln)
    
    # Check if any vulnerabilities found
    total_vulns = sum(len(v) for v in vulnerabilities.values())
    
    if total_vulns == 0:
        print("\n" + "="*70)
        print(stringInColor(Color.GREEN, "✓ SECURITY SCAN: NO CRITICAL VULNERABILITIES DETECTED"))
        print("="*70)
        print(stringInColor(Color.GREEN, "[✓] No high-risk open ports found"))
        print(stringInColor(Color.CYAN, "[i] This does not guarantee complete security"))
        print(stringInColor(Color.CYAN, "[i] Always follow security best practices"))
        print("="*70 + "\n")
        return
    
    # Display vulnerability report
    print("\n" + "="*70)
    print(stringInColor(Color.BOLDRED, "⚠️  SECURITY VULNERABILITY REPORT"))
    print("="*70)
    print(stringInColor(Color.YELLOW, f"[!] {total_vulns} security issue(s) detected"))
    print("="*70 + "\n")
    
    # Display CRITICAL vulnerabilities
    if vulnerabilities['CRITICAL']:
        print(stringInColor(Color.BOLDRED, f"🔴 CRITICAL SEVERITY ({len(vulnerabilities['CRITICAL'])} issues):"))
        print("-"*70)
        for vuln in vulnerabilities['CRITICAL']:
            vuln_text = f"Host: {vuln['host']} | Port {vuln['port']} ({vuln['service']})"
            print(f"\n{stringInColor(Color.BOLDRED, vuln_text)}")
            print(f"  Issue: {vuln['issue']}")
            print(f"  Impact: {vuln['impact']}")
            print(f"  {stringInColor(Color.GREEN, '→ Fix:')} {vuln['recommendation']}")
    
    # Display HIGH vulnerabilities
    if vulnerabilities['HIGH']:
        print(stringInColor(Color.RED, f"🟠 HIGH SEVERITY ({len(vulnerabilities['HIGH'])} issues):"))
        print("-"*70)
        for vuln in vulnerabilities['HIGH']:
            vuln_text = f"Host: {vuln['host']} | Port {vuln['port']} ({vuln['service']})"
            print(f"\n{stringInColor(Color.RED, vuln_text)}")
            print(f"  Issue: {vuln['issue']}")
            print(f"  Impact: {vuln['impact']}")
            print(f"  {stringInColor(Color.GREEN, '→ Fix:')} {vuln['recommendation']}")
    
    # Display MEDIUM vulnerabilities
    if vulnerabilities['MEDIUM']:
        print(stringInColor(Color.YELLOW, f"🟡 MEDIUM SEVERITY ({len(vulnerabilities['MEDIUM'])} issues):"))
        print("-"*70)
        for vuln in vulnerabilities['MEDIUM']:
            vuln_text = f"Host: {vuln['host']} | Port {vuln['port']} ({vuln['service']})"
            print(f"\n{stringInColor(Color.YELLOW, vuln_text)}")
            print(f"  Issue: {vuln['issue']}")
            print(f"  {stringInColor(Color.GREEN, '→ Fix:')} {vuln['recommendation']}")
    
    # Display LOW vulnerabilities
    if vulnerabilities['LOW']:
        print(stringInColor(Color.CYAN, f"🔵 LOW SEVERITY ({len(vulnerabilities['LOW'])} issues):"))
        print("-"*70)
        for vuln in vulnerabilities['LOW']:
            vuln_text = f"Host: {vuln['host']} | Port {vuln['port']} ({vuln['service']})"
            print(f"\n{stringInColor(Color.CYAN, vuln_text)}")
            print(f"  Issue: {vuln['issue']}")
            print(f"  {stringInColor(Color.GREEN, '→ Fix:')} {vuln['recommendation']}")
    
    print("="*70)
    print(stringInColor(Color.BOLDRED, f"[!] TOTAL: {total_vulns} security vulnerabilities require attention"))
    print("="*70 + "\n")

#UnFinishedFUNC
def main():
    if len(sys.argv) == 1:
        args = textual_interface()
    else:
        args = parser.parse_args()
        if args.portMode == 'range':
            try:
                if args.start is None:
                    args.start = int(input("Enter start port: "))
                    if args.start < 1 or args.start > 65535:
                        raise ValueError
                if args.end is None:
                    args.end = int(input("Enter end port: "))
                    if args.start < 1 or args.start > 65535:
                        raise ValueError
            except ValueError:
                print("Please enter a valid port number")


    scanStart = time.time()


    try: int(args.threads)
    except ValueError: sys.exit('wrong value for threads: needs to be int')

    try: int(args.start)
    except ValueError: sys.exit('wrong value for startport: needs to be int')

    try: int(args.end)
    except ValueError: sys.exit('wrong value for endport: needs to be int')

    Title = pyfiglet.figlet_format("Scanner", font="bloody")
    console = Console(force_terminal=True)
    console.print(f"[bold red]{Title}[/bold red]", justify="center")
    info = Text()
    info.append("Coded By : Benjamin and Josh\n", style="bold cyan")
    info.append("Version   : 1.0.0\n", style="bold cyan")
    info.append("Team      : BenNjosh\n", style="bold cyan")
    info.append("GitHub    : coming soon\n", style="bold cyan")
    info = Align.center(info)
    panel = Panel(info, title="[bold green]Scanner Info", border_style="bright_white")
    console.print(panel)

    prehosts = getIPaddresses(args.address, args.threads)
    flatHosts = []

    for host in prehosts:
        if isinstance(host, list):
            flatHosts.extend(host)
        else:
            flatHosts.append(host)

    if args.do_pings:
        hosts = []
        for host in flatHosts:
            if checkHostStatus(host) == 0:
                hosts.append(host)
    else:
        hosts = flatHosts
    ports = getPorts(args.portMode, len(hosts), args.start, args.end, args.threads,args.scanType, args.port)
    validate_ports(ports if isinstance(ports, list) else ports[0], args)

    groupedResults = [[] for i in range(args.threads)]
    threads = []
    threadCount = args.threads
    if (len(hosts) > 1):
        if len(hosts) < args.threads:
            threadCount = len(hosts)

    if (len(ports) > 1):
        if len(ports) < args.threads:
            threadCount = len(ports)
    hostChunks = []

    if len(hosts) == 0:
        sys.exit('no hosts to scan')

    if len(hosts) > 1:

        hostChunks = [[] for i in range(threadCount)]
        for i in range(len(hosts)):
            hostChunks[i % threadCount].append(hosts[i])

    total_ports = len(hosts) * len(ports)
    final = {host: [] for host in hosts}
    with Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TimeRemainingColumn(),
    ) as progress:

        # Create one task for the whole scan
        taskID = progress.add_task("Scanning all hosts", total=total_ports)



        if args.scanType == 'connect':
            for t in range(threadCount):
                if len(hosts) == 1:
                    thread = threading.Thread(target=busyBeeIFOneHost, args=(
                    hosts, ports[t], args.delay, groupedResults, t, args.servicescan, progress, taskID))
                    threads.append(thread)

                else:
                    thread = threading.Thread(target=busybeeIFMultipleHosts, args=(
                    hostChunks[t], ports, args.delay, groupedResults, t, args.servicescan, progress, taskID))
                    threads.append(thread)

            for t in threads:
                t.start()
            for t in threads:
                t.join()
        elif args.scanType in ['syn','ack','fin','rst']:
            if isinstance(hosts, list):
                for host in hosts:
                    final[host] = scapyScan(host, ports, args.scanType, progress, taskID)
            elif isinstance(hosts, str):
                final[hosts] = scapyScan(hosts, ports, args.scanType, progress, taskID)

    scannedHosts = set()
    for group in groupedResults:
        for result in group:
            scannedHosts.add(result.get('host'))
    if args.scanType == 'connect':
        final = output(scannedHosts, groupedResults, args.servicescan)

    for host in final.keys():
        sorted_results = sorted(final[host], key=lambda x: x[0])
        os = osDetection(sorted_results, host)
        console.print(f"\n [bold purple]Host:[/bold purple] [bold blue]{host} -> OS: {os}[/bold blue]")

        if not sorted_results:
            continue
        num_cols = len(sorted_results[0])
        headers = ["Port", "Service", "State"]
        if num_cols > 3:
            headers.extend([f"Col{i}" for i in range(4, num_cols + 1)])
            headers[3] = "Banner"

        table = Table(show_header=True, header_style="bold blue")
        for h in headers:
            table.add_column(h, justify="right" if h in ["Port", "State"] else "left")

        seen = set()
        for row in sorted_results:
            port = row[0]
            if port in seen:
                continue
            seen.add(port)

            # Format state with colors
            state = row[2]
            if state == 'OPEN' and (args.display in ['all', 'open']):
                row[2] = f"[bold green]{state}[/bold green]"
                table.add_row(*[str(item) if item is not None else "" for item in row])
            elif state == 'CLOSED' and (args.display in ['all', 'closed']):
                row[2] = f"[bold red]{state}[/bold red]"
                table.add_row(*[str(item) if item is not None else "" for item in row])
            elif state == 'FILTERED' and (args.display in ['all']):
                row[2] = f"[bold yellow]{state}[/bold yellow]"
                table.add_row(*[str(item) if item is not None else "" for item in row])
            elif state == 'UNFILTERED' and (args.display in ['all']):
                row[2] = f"[bold green]{state}[/bold green]"
                table.add_row(*[str(item) if item is not None else "" for item in row])
            elif state == 'OPEN|FILTERED' and (args.display in ['all']):
                row[2] = f"[bold green]{state}[/bold green]"
                table.add_row(*[str(item) if item is not None else "" for item in row])




        console.print(table)

    validate_open_ports(final, args)

    security_scan_report(final, args)

    if args.output_file or args.output_format != 'txt':
        outputFile(scanStart, final, args)

if __name__ == "__main__":
    main()

