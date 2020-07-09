#!/usr/bin/python
# -*- coding: utf-8 -*-
__author__  = 'd4rk6h05t [Michani. M. De La Calleja E.]'
__version__ = 'v1.0.0'
__github__  = 'https://github.com/d4rk6h05t/dark-sniffer'
__email__   = 'd4rk6h05t_0d4y5@protonmail.ch'
"""
We point out that the hacking related material found in the github account (d4rk6h05t) is for educational and demonstration purposes only.
We are not responsible for any damages. You are responsible for your own actions.

DarkSniffer [ small DarkSniffer only TCP incoming package ]
Sniffers are programs that can capture/sniff/detect package of network traffic per package and analyze
additional note to successfully run the script you must be root or prepend the sudo command at the time of executing the script, for example: 
 
 $ sudo python darksniffer.py
 or 
 $ sudo ./darksniffer.py
 
Author: d4rk6h05t [ Michani. M. De La Calleja E. / d4rk6h05t_0d4y5@protonmail.ch ]

"""
import time
import binascii
from struct import *
import socket, sys
from prettytable import PrettyTable

class DarkSniffer:
    
    def __init__(self,version):
        self._version = version
    
    def __repr__(self):
        return 'DarkSniffer({})'.format(self._version)
    
    @property
    def version(self):
        return self._version

    @version.setter
    def version(self, version):
        self._version = version
    
    def banner(self):
        print(f'███████╗ █████╗ ██████╗ ██╗  ██╗     ███████╗███╗  ██╗██████╗██████╗██████╗███████╗██████╗ \n' 
              f'██╔═══█║██╔══██╗██╔══██╗██║ ██╔╝     ██╔════╝████╗ ██║╚═██╔═╝██╔═══╝██╔═══╝██╔════╝██╔══██╗\n'
              f'██║   █║███████║██████╔╝█████╔╝█████╗███████╗██╔██╗██║  ██║  ██████╗██████╗█████╗  ██████╔╝\n'
              f'██║   █║█ ╔══██║██╔══██╗██╔═██╗╚════╝╚════██║██║╚████║  ██║  ██╔═══╝██╔═══╝██╔══╝  ██╔══██╗\n'
              f'███████║█ ║  ██║██║  ██║██║  ██╗     ███████║██║ ╚═██║██████╗██║    ██║    ███████╗██║  ██║\n'
              f' ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝     ╚══════╝╚═╝   ╚═╝╚═════╝╚═╝    ╚═╝    ╚══════╝╚═╝  ╚═╝\n')
        print(f'[+]\t:: By: {__author__} \n[+]\t:: An small  5n1ff3r {self._version} ')
    
    def get_protocol(self,number_protocol):
        # based in IP Protocol numbers found in the Protocol field of the IPv4 header
        # for more info: https://en.wikipedia.org/wiki/List_of_IP_Protocol_numbers
        # Currently the most commonly used protocol is TCP but there may be exceptions 
        # return a list with protocol, small description and rfc
        protocols = { 
            0: ['HOPOPT','IPv6 Hop-by-Hop Option','8200'], 
            1: ['ICMP', 'Internet Control Message Protocol','792'], 
            2: ['IGMP', 'Internet Group Management Protocol','1112'],
            3: ['GGP', 'Gateway-to-Gateway Protocol', '823'], 
            4: ['IP-in-IP', 'IP in IP (encapsulation)', '2003'], 
            5: ['ST', 'Internet Stream Protocol', '1190,1819'],
            6: ['TCP', 'Transmission Control Protocol', '793'],
            7: ['CBT', 'Core-based trees', '2189'],
            8: ['EGP', 'Exterior Gateway Protocol', '888'],
            9: ['IGP', 'Interior Gateway Protocol', ''],
        } 
        return protocols.get(number_protocol, 'number_protocol')
    
    def load_progress_bar(self,package_number, total_collect_packages):
        prefix, suffix  = 'Loading...:', 'Progress:'
        percent = ('{0:.' + str(0) + 'f}').format( (100 * package_number) / float(total_collect_packages)  )
        filled_space = int( (50 * package_number) // total_collect_packages )
        bar = '█' * filled_space + '-' * (50 - filled_space)
        print(f'\r[+]\t:: {prefix} |{bar}|  {suffix:}{percent}% ({package_number}/{total_collect_packages} collected packages)', end = '\r')
        if package_number == total_collect_packages: 
            prefix, suffix  = 'Ready ...:', 'Completed:'
            print()
   
    def intercept_package(self):
        try:
            # AF_INET and AF_INET6 correspond to the protocol classification PF_INET and PF_INET6.
            # Which include standard IP and TCP and UDP port numbers. 
            # Create a raw socket and bind it to the public interface
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            table = PrettyTable()
            table.field_names = [
                '#',
                'Source',
                'Destination',
                'Protocol',
                'IP Head. V',
                'IP Head. L.',
                'TTL',
                'src p.',
                'des p.',
                'sequence',
                'identification',
                'TCP H L',
                'data',
            ]
            total_collect_packages = 50
            self.load_progress_bar(0, total_collect_packages)
            
        except socket.error as message:
            print('Problem in the socket cant create.  : SocketExeption' + str(message[0]) + ' Message ' + message[1])
            sys.exit()
        package_number = 1
        while True:
            time.sleep(0.1)
            self.load_progress_bar(package_number, total_collect_packages)
            if package_number == total_collect_packages:
                break
            # Receive data from the socket packaged. 
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
            
            # TTL [ Time to Live ] & TCP Protocol
            time_to_live, tcp_protocol = ip_header_unpacked[5], ip_header_unpacked[6]
            source_address,destination_address = socket.inet_ntoa(ip_header_unpacked[8]), socket.inet_ntoa(ip_header_unpacked[9])

            tcp_header = tcp_package[ip_header_unpacked_length:ip_header_unpacked_length + 20]
            # At the moment, unpack them TCP header
            tcp_header = unpack('!HHLLBBHHH' , tcp_header) 
            
            # Package metadata collection TCP header
            source_port, destination_port, sequence, identification, data_reserved = tcp_header[0], tcp_header[1], tcp_header[2], tcp_header[3], tcp_header[4]
            tcp_header_length = data_reserved >> 4
            header_size = ip_header_unpacked_length + tcp_header_length * 4
            
            # Retrieve package data TCP
            # If the target you're analyzing is using the https protocol, the information will obviously be encrypted. 
            # On the other hand, if the target you are scanning only uses http, the information will appear in plain text.
            data = tcp_package[header_size:]
            data_b2a_hex = binascii.b2a_hex(data)
            if data != b'':
                data_saved = str(data)[0:190] 
                package_info = [
                    package_number,
                    source_address,
                    destination_address,
                    (self.get_protocol(tcp_protocol))[0],
                    ip_header_version,
                    ip_header_length,
                    time_to_live,
                    source_port,
                    destination_port,
                    sequence,
                    identification,
                    tcp_header_length,
                    data_saved,
                ]
                table.add_row(package_info)
                package_number += 1
        print(f'[+]\t:: Protocol : {(self.get_protocol(tcp_protocol))[0]}'
              f' :: Destination addr : {destination_address}'
              f' :: TCP Header Length : {tcp_header_length}'
              f' :: IP Headader Version : {ip_header_version}' 
              f' :: IP Header Length.: {ip_header_length}')
        print(table.get_string(fields=[
                '#',
                'Source',
                'TTL',
                'src p.',
                'des p.',
                'sequence',
                'identification',
                'data',
            ]))
        print('\nBye ..... OK!\n')
        sys.exit()
             
def main(argv):
    darksniffer = DarkSniffer(__version__)
    darksniffer.banner()
    darksniffer.intercept_package()
    
if __name__ == '__main__':
    main(sys.argv[1:])
