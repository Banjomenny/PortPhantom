import argparse
import ipaddress
import socket
import sys
import threading
import time
import os
from enum import Enum


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


def parse_arguments():
    '''
    :return: arguments
    '''
    #allows for nice CLI argument parsing
    parser = argparse.ArgumentParser(description='network scanner',usage='scans a given network for open ports')
    parser.add_argument("-a", "--address", action='store', dest='address', required=True,help="you can use CIDR notation or a something like 1.1.1.1-100. or specify single host")
    parser.add_argument('--mode', action='store',dest='portMode',choices=['common', 'range', 'all', 'single','wellKnown', 'web', 'database', 'remoteAccesss', 'fileShare', 'mail'], required=False, default='common',help='common is 1-1024, range you specify --startport and --endport and all is 1-65535')
    parser.add_argument('--start-port', type=int, action='store', dest='start', required=False, default=1,help='start port of range')
    parser.add_argument('--end-port', type=int, action='store', dest='end', required=False, default=1024,help='end port of range')
    parser.add_argument('-t', '--threads', type=int, action='store', dest='threads', required=False, default=1,help='number of threads')
    parser.add_argument('-d', '--delay', type=float, action='store', dest='delay', required=False, default=0.1,help='delay in seconds')
    parser.add_argument('--display', action='store',choices=['all','open','closed'], dest='display', required=False, default='all', help='chose what ports to be diplayed, all, open, closed')
    parser.add_argument('-p','--port', action='store', dest='port', required=False, default=None,help='choose the port you want or a list like 1,2,3,4,5,6,7')
    parser.add_argument('--output-to-file', type=str, dest='output_file', required=False, default=None, help='output filename (e.g., results.txt or results.csv)') #JL output
    parser.add_argument('--output-format', choices=['txt', 'csv'], default='txt', help='output format: txt or csv') #JL output
    parser.add_argument('--servicescan', action='store_true', dest='servicescan', required=False, default=False, help='service scan')
    parser.add_argument('--show-vulns', action='store_true', dest='show_vulns', required=False, default=False,help='show vulnerabilities')
    parser.add_argument('--do-pings', action='store_true', dest='do_pings', required=False, default=False,help='ping service')
    return parser.parse_args()

def parsePort(input):
    ports = None
    if input:
        ports = input.split(',')
    return ports

def getIPaddresses(address, threads):
    '''
    :param address: the entered ip address from user
    :return: list of hosts to scan
    '''
    #allows for a range or cidr notation of ip addresses
    hosts = []
    address = address.strip()

    print(f"DEBUG: raw address string = {repr(address)}")

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
            print(hosts)
            return hosts
        except:
            print("you get an error")
            sys.exit("Invalid Host")
#JL Edit V1
def scan_port(target, port, ifServiceScan):
    '''
    :param target: target ip address
    :param port: port to scan
    :return: state of port
    '''
    """Simple port scanner -- checks if the port is actually open"""
    try:
        print(f"Scanning {target}... Port {port}")
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
                        raw = ''.join(response) if response else "NO BANNER"

                        headers, _, body = raw.partition("\r\n\r\n")
                        print(f"DEBUG HEADERS:\n{headers}")

                        # Grab the Server line
                        for line in headers.splitlines():
                            line = line.strip()
                            if line.lower().startswith("server:"):
                                print(f"DEBUG SERVER:\n{line}")
                                banner = line
                                break
                        else:
                            banner = headers.splitlines()[0]
                        print(f"DEBUG HEADERS:\n{banner}")
                    except Exception:
                        banner = "NO BANNER"
        service = 'UNKNOWN'
        banner = banner.strip()

        try:
            service = common_ports_dict[port]
        except:
            service = 'UNKNOWN'

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
def busybeeIFMultipleHosts(hosts, ports, delay, groupedResults, index, ifServiceScan):
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
        for port in ports:
            local.append(scan_port(target, port, ifServiceScan))
        groupedResults[index] = local


# only do one host. so only split ports and not hosts
def busyBeeIFOneHost(hosts, ports, delay, groupedResults, index, ifServiceScan):
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
    for port in ports:
        local.append(scan_port(target, port, ifServiceScan))
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
                    if not args.display_only_open or state == 'OPEN':
                        banner_text = banner if banner and banner != "NO BANNER" else ""
                        writer.writerow([host, port, service, state, banner_text])
        else:
            writer = csv.writer(f)
            writer.writerow(['Host', 'Port', 'Service', 'State'])
            
            for host in finalOutput.keys():
                for result in finalOutput[host]:
                    port, service, state = result
                    if not args.display_only_open or state == 'OPEN':
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
                    if not args.display_only_open or state == 'OPEN':
                        f.write(f"{port:<10} {service:<25} {state:<10}")
                        if banner and banner != "NO BANNER":
                            f.write(f" | {banner[:50]}")
                        f.write("\n")
                else:
                    port, service, state = result
                    if not args.display_only_open or state == 'OPEN':
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

def getPorts(portMode, numberOfHosts, start, end, threads, inputPorts = None):
    '''
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

        if numberOfHosts == 1:
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
    ports = getPorts(args.portMode, len(hosts), args.start, args.end, args.threads)
    
    
    validate_ports(ports if isinstance(ports, list) else ports[0], args)
    


    groupedResults = [[] for i in range(args.threads)]
    threads = []
    threadCount = args.threads
    if(len(hosts) > 1):
        if len(hosts) < args.threads:
            threadCount = len(hosts)

    hostChunks = []

    if len(hosts) == 0:
        sys.exit('no hosts to scan')

    if len(hosts) > 1:

        hostChunks = [[] for i in range(threadCount)]
        for i in range(len(hosts)):
            hostChunks[i % threadCount].append(hosts[i])
    print(hostChunks)
    #create worker threads to then scan all ports. if 1 host is present splits up ports and if multiple hosts then splits up hosts
    print(len(hostChunks))
    print()
    for t in range (threadCount):
        if len(hosts) == 1:
            thread = threading.Thread(target=busyBeeIFOneHost,args=(hosts, ports[t],args.delay, groupedResults, t, args.servicescan))
            threads.append(thread)

        else:
            if threadCount == len(hosts):
                print(t)
                thread = threading.Thread(target=busyBeeIFOneHost,args=(hostChunks[t], ports, args.delay, groupedResults, t, args.servicescan))

            thread = threading.Thread(target=busybeeIFMultipleHosts, args=(hostChunks[t], ports, args.delay, groupedResults, t, args.servicescan))
            threads.append(thread)


    for t in threads:
         t.start()
    for t in threads:
        t.join()

    scanEnd = time.time()
    elapsedTime = scanEnd - scanStart
    print("Elapsed time: " + str(elapsedTime))

    scannedHosts = set()
    for group in groupedResults:
        for result in group:
            scannedHosts.add(result.get('host'))

    final = output(scannedHosts, groupedResults, args.servicescan)

    target = stringInColor(Color.BOLDWHITE, 'port')
    serviceName = stringInColor(Color.BOLDWHITE, "service")
    stateName = stringInColor(Color.BOLDWHITE, "state")
    if not args.servicescan:

        for host in final.keys():
            print("\nHost: " + stringInColor(Color.PURPLE,host))
            print(f"{target:>15}  {serviceName:>25}{stateName:>30}")
            sorted_results = sorted(final[host], key=lambda x: x[0])
            for port, service, state in sorted_results:
                if state == 'OPEN' and (args.display == 'all' or args.display == 'open'):
                    state = stringInColor(Color.GREEN, state)
                    print(f"{port:<5} : {service:<25} | {state:>10}")
                elif state == 'CLOSED' and (args.display == 'all' or args.display == 'closed'):
                    state = stringInColor(Color.RED, state)
                    print(f"{port:<5} : {service:<25} | {state:<10}")
    else:
        for host in final.keys():
            print("\nHost: " + stringInColor(Color.PURPLE,host))
            print(f"{target:>15}  {serviceName:>25}{stateName:>30}")
            seen = set()
            sorted_results = sorted(final[host], key=lambda x: x[0])
            for port, service, state, banner in sorted_results:
                if port not in seen:
                    if state == 'OPEN':
                        state = stringInColor(Color.GREEN, state)
                        print(f"{port:<5} : {service:<25} | {state:>10} {str(banner):<20}")
                    else:
                        if not args.display_only_open:
                            state = stringInColor(Color.RED, state)
                            print(f"{port:<5} : {service:<25} | {state:<10} {str(banner):<20}")
                    seen.add(port)
    
    security_scan_report(final, args)
    
    if args.output_file or args.output_format != 'txt':
        outputFile(scanStart, final, args)

main()
