#!/usr/bin/python

"""
By: d4rk6h05t [ Michani. M. De La Calleja E. ]

We point out that the hacking related material found in the github account (d4rk6h05t) is for educational and demonstration purposes only.
We are not responsible for any damages. You are responsible for your own actions.

DarkSniffer [ small DarkSniffer only TCP incoming package ]
Sniffers are programs that can capture/sniff/detect package of network traffic per package and analyze
additional note to successfully run the script you must be root or prepend the sudo command at the time of executing the script, for example: 
 
 $ sudo python darksniffer.py

The following script is a bit slow and not currently optimized, so don't despair if it doesn't run fast, you have to wait a few seconds.
"""
from struct import *
import socket, sys

class DarkSniffer:
    
    def banner(self):
        print(f' _       __   _  __    ____ _  _ _ ________________   \n'
              f'|++\ /\ |**\ |(|/;/___| ___| \| | | .__| .__| -_|**\  \n'
              f'|+.&/&_\|@#/ |+_./|___|___ |  \ | | |__| |__| -_|$%/  \n'
              f'|__/_/\_\|\_\|+|\_\   |____|_|\_|_|_|  |_|  |___|_^_\ \n')
        print(f':: By: d4rk6h05t  :: An small  5n1ff3r V1.0.0 ')
    
    def check_protocol(self,number_protocol):
        # based in IP Protocol numbers found in the Protocol field of the IPv4 header
        # for more info: https://en.wikipedia.org/wiki/List_of_IP_Protocol_numbers
        protocols = { 
            0: ':: [ HOPOPT ] :: IPv6 Hop-by-Hop Option ............:: RFC 8200', 
            1: ':: [  ICMP  ] :: Internet Control Message Protocol .:: RFC 792', 
            2: ':: [  IGMP  ] :: Internet Group Management Protocol :: RFC 1112',
            3: ':: [  GGP   ] :: Gateway-to-Gateway Protocol .......:: RFC 823', 
            4: ':: [IP-in-IP] :: IP in IP (encapsulation) ..........:: RFC 2003 ', 
            5: ':: [   ST   ] :: Internet Stream Protocol ..........:: RFC 1190, RFC 1819',
            6: ':: [   TCP  ] :: Transmission Control Protocol .....:: RFC 793',
            7: ':: [   CBT  ] :: Core-based trees ..................:: RFC 2189 ',
            8: ':: [   EGP  ] :: Exterior Gateway Protocol......... :: RFC 888 ',
            9: ':: [   IGP  ] :: Interior Gateway Protocol......... :: OK ',
        } 
        return protocols.get(number_protocol, 'number_protocol')
    
    def display_headers_package(self,ip_header_version,ip_header_length,time_to_live,tcp_protocol,source_address,target_address):
        print(f'Version: {str(ip_header_version)}\n'
                f'IP Header Length: {str(ip_header_length)}\n'
                f'Time To Live: {str(time_to_live)}\n'
                f'Protocol :{ self.check_protocol(tcp_protocol) }\n'
                f'Source Address: {str(source_address)}\n'
                f'Target Address :{str(target_address)}\n')
    
    def display_info_package(self,source_port,target_port,sequence,recognition,tcp_header_length):
        print(f'Source Port: {str(source_port)}\n'
                f'Target Port : {str(target_port)}\n'
                f'Sequence Number : {str(sequence)}\n'
                f'Recognition :{str(recognition)}\n'
                f'TCP header length :{str(tcp_header_length)}\n')
    
    def display_data_package(self,data):
        print(f'Data : {data}\n')
    
    def intercept_package(self):
        try:
            # AF_INET and AF_INET6 correspond to the protocol classification PF_INET and PF_INET6.
            # Which include standard IP and TCP and UDP port numbers. 
            # Create a raw socket and bind it to the public interface
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except socket.error as message:
            print('Problem in the socket cant create.  : SocketExeption' + str(message[0]) + ' Message ' + message[1])
            sys.exit()
        
        while True:
            # Receive data from the socket. 
            tcp_package = server_socket.recvfrom(65565)
            # TCP package, Take the first 20 characters for the IP header.
            tcp_package = tcp_package[0] 
            ip_header = tcp_package[0:20] 
            # At the moment, unpack them IP header
            ip_header_unpacked = unpack('!BBHHHBBH4s4s', ip_header) 
            
            # TCP IP package metadata collection
            ip_header_length_version = ip_header_unpacked[0]
            ip_header_version = ip_header_length_version >> 4
            ip_header_length = ip_header_length_version & 0xF
            ip_header_unpacked_length = ip_header_length * 4
            # TTL [ Time to Live ]
            time_to_live, tcp_protocol = ip_header_unpacked[5], ip_header_unpacked[6]
            source_address,target_address = socket.inet_ntoa(ip_header_unpacked[8]), socket.inet_ntoa(ip_header_unpacked[9])

            tcp_header = tcp_package[ip_header_unpacked_length:ip_header_unpacked_length + 20]
            # At the moment, unpack them TCP header
            tcp_header = unpack('!HHLLBBHHH' , tcp_header) 
            
            # Package metadata collection TCP header
            source_port, target_port, sequence, recognition, data_reserved = tcp_header[0], tcp_header[1], tcp_header[2], tcp_header[3], tcp_header[4]
            tcp_header_length = data_reserved >> 4
            header_size = ip_header_unpacked_length + tcp_header_length * 4
            # Retrieve package data TCP
            data = tcp_package[header_size:]
            
            # Display information on intercepted package (network traffic)
            self.display_headers_package(ip_header_version,ip_header_length,time_to_live,tcp_protocol,source_address,target_address)
            self.display_info_package(source_port,target_port,sequence,recognition,tcp_header_length)    
            self.display_data_package(data)

def main(argv):
    darksniffer = DarkSniffer()
    darksniffer.banner()
    darksniffer.intercept_package()
    
if __name__ == '__main__':
    main(sys.argv[1:])
