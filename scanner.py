import argparse
import ipaddress
import ipaddress
import socket

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
        parser = argparse.ArgumentParser()