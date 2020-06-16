#!/usr/bin/python

"""
By: d4rk6h05t [ Michani. M. De La Calleja E. ]

We point out that the hacking related material found in the github account (d4rk6h05t) is for educational and demonstration purposes only.
We are not responsible for any damages. You are responsible for your own actions.

DarkSniffer [ small DarkSniffer only TCP incoming package ]
Sniffers are programs that can capture/sniff/detect package of network traffic per packet and analyze
additional note to successfully run the script you must be root or prepend the sudo command at the time of executing the script, for example: 
 
 $ sudo python darksniffer.py

The following script is a bit slow and not currently optimized, so don't despair if it doesn't run fast, you have to wait a few seconds.
"""
from struct import *
import socket, sys

class DarkSniffer:
    
    def __init__(self):
        pass
    
    def banner(self):
        print(f' _       __   _  __    ____ _  _ _ ________________   \n'
              f'|++\ /\ |**\ |(|/;/___| ___| \| | | .__| .__| -_|**\  \n'
              f'|+.&/&_\|@#/ |+_./|___|___ |  \ | | |__| |__| -_|$%/  \n'
              f'|__/_/\_\|\_\|+|\_\   |____|_|\_|_|_|  |_|  |___|_^_\ \n')
        print(':: By: d4rk6h05t :: An small  5n1ff3r v1.0 ')
    
    def display_headers_package(self,version,ip_header_length,ttl,protocol,source_address,target_address):
        print(f'Version: {str(version)}\n'
                f'IP Header Length: {str(ip_header_length)}\n'
                f'TTL: {str(ttl)}\n'
                f'Protocol :{str(protocol)}\n'
                f'Source Address: {str(source_address)}\n'
                f'Target Address :{str(target_address)}\n')
    
    def display_info_package(self,source_port,target_port,sequence,recognition,tcp_header_length):
        print(f'Source Port: {str(source_port)}\n'
                f'Target Port : {str(target_port)}\n'
                f'Sequence Number : {str(sequence)}\n'
                f'Recognition :{str(recognition)}\n'
                f'TCP header length :{str(tcp_header_length)}\n')
    
    def display_data_package(self,data):
        print(f'Data : {data}')
        print('')
        
    def intercept_package(self):
        try:
            # Create an INET, STREAMing socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except socket.error as message:
            # Some socket exceptions
            print('Problem in the socket cant create.  : SocketExeption' + str(message[0]) + ' Message ' + message[1])
            sys.exit()

        # Receive a package tcp
        while True:
            tcp_packet = server_socket.recvfrom(65565)
            # TCP packet of strings from tuple, Take the first 20 characters for the IP header.
            tcp_packet = tcp_packet[0] 
            ip_header = tcp_packet[0:20] 
            ip_header_unpacked = unpack('!BBHHHBBH4s4s', ip_header) # Now unpack them IP header
            
            # TCP IP package metadata collection
            version_ip_header_length = ip_header_unpacked[0]
            version = version_ip_header_length >> 4
            ip_header_length = version_ip_header_length & 0xF
            ip_header_unpacked_length = ip_header_length * 4
            ttl, protocol = ip_header_unpacked[5], ip_header_unpacked[6]
            source_address,target_address = socket.inet_ntoa(ip_header_unpacked[8]), socket.inet_ntoa(ip_header_unpacked[9])

            tcp_header = tcp_packet[ip_header_unpacked_length:ip_header_unpacked_length + 20]
            tcp_header = unpack('!HHLLBBHHH' , tcp_header) # Now unpack them TCP header
            
            # Package metadata collection TCP header
            source_port, target_port, sequence, recognition, data_reserved = tcp_header[0], tcp_header[1], tcp_header[2], tcp_header[3], tcp_header[4]
            tcp_header_length = data_reserved >> 4
            header_size = ip_header_unpacked_length + tcp_header_length * 4
            # Retrieve packet data TCP
            data = tcp_packet[header_size:]
            
            # Display information on intercepted package (network traffic)
            self.display_headers_package(version,ip_header_length,ttl,protocol,source_address,target_address)
            self.display_info_package(source_port,target_port,sequence,recognition,tcp_header_length)    
            self.display_data_package(data)

def main(argv):
    darksniffer = DarkSniffer()
    darksniffer.banner()
    darksniffer.intercept_package()
    
if __name__ == '__main__':
    main(sys.argv[1:])
