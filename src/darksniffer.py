#!/usr/bin/env python3

#   Author: Copyright (C) 2020 Michani. M. De La Calleja E. [ d4rk6h05t ~тёмный призрак ] 
#
#   I point out that the hacking-related material found in the github account (d4rk6h05t) is for educational and demonstration purposes only. 
#   You are responsible for your own actions.

__author__  = 'd4rk6h05t [Michani. M. De La Calleja E.]'
__version__ = 'v1.0.0'
__github__  = 'https://github.com/d4rk6h05t/dark-sniffer'
__email__   = 'd4rk6h05t_0d4y5@protonmail.ch'
__license__ = 'GNU GPLv3'

import os
import sys
import socket
import time
import datetime
import json
import csv

from struct import *
from optparse import OptionParser

try:
    
    from prettytable import PrettyTable, from_csv

    from protocols.IP import IP
    from protocols.TCP import TCP
    from protocols.UDP import UDP
    from protocols.ICMP import ICMP
    from protocols.Ethernet import Ethernet 

except ImportError as import_error:
    print(f'[!] Missing a package: {str(import_error)} ')
    sys.exit()
    
class DarkSniffer:
    
    AMOUNT_PACKETS = 5
    NO_PACKET = ['no_packet','datetime']
    METADATA_DATA = ['data']
    
    PACKET_TCP_METADATA = NO_PACKET + Ethernet.HEADER + IP.HEADER + TCP.HEADER + METADATA_DATA
    PACKET_ICMP_METADATA = NO_PACKET + Ethernet.HEADER + IP.HEADER + ICMP.HEADER + METADATA_DATA
    PACKET_UDP_METADATA = NO_PACKET + Ethernet.HEADER + IP.HEADER + UDP.HEADER + METADATA_DATA
    
    def __init__(self,filename):
        self._filename = filename
    
    def __repr__(self):
        return 'DarkSniffer({})'.format(__version__)
    
    @property
    def filename(self):
        return self._filename
    

    @filename.setter
    def filename(self, filename):
        self._filename = filename
    
    @staticmethod
    def banner():
        print('███████╗ █████╗ ██████╗ ██╗  ██╗     ███████╗███╗  ██╗██████╗██████╗██████╗███████╗██████╗ ', 
              '██╔═══█║██╔══██╗██╔══██╗██║ ██╔╝     ██╔════╝████╗ ██║╚═██╔═╝██╔═══╝██╔═══╝██╔════╝██╔══██╗',
              '██║   █║███████║██████╔╝█████╔╝█████╗███████╗██╔██╗██║  ██║  ██████╗██████╗█████╗  ██████╔╝',
              '██║   █║█ ╔══██║██╔══██╗██╔═██╗╚════╝╚════██║██║╚████║  ██║  ██╔═══╝██╔═══╝██╔══╝  ██╔══██╗',
              '███████║█ ║  ██║██║  ██║██║  ██╗     ███████║██║ ╚═██║██████╗██║    ██║    ███████╗██║  ██║',
              ' ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝     ╚══════╝╚═╝   ╚═╝╚═════╝╚═╝    ╚═╝    ╚══════╝╚═╝  ╚═╝',
              sep = '\n')
        print(f'[+] :: By: {__author__} :: {__version__}\n')
    
    @staticmethod
    def options():
        usage = 'usage: sudo ./darksniffer.py [options] [args]'

        parser = OptionParser(usage=usage)
        
        parser.add_option('-c', '--csv-file', type='string',dest='filename_csv', help='Save details into CSV file where the details of the intercepted packets')
        parser.add_option('-j', '--json-file',type='string',dest='filename_json',help='Save details into JSON file where the details of the intercepted packets')
        parser.add_option('-i', '--interactive', action='store_true', dest='interactive', help='Customize packet capture arguments')
        parser.add_option('-p', '--packets', type='int', dest='packets',  help='Amount of packages to be captured')
        parser.add_option('-P', '--protocol', type='string', dest='protocol',  help='Select a specific trotocol [TCP/ICMP/UDP]')
        parser.add_option('-e', '--empty-packet', action='store_true', dest='empty_packet', help='Accept empty packages in the data field')
        parser.add_option('-d', '--details-json', action='store_true', dest='json',  help='Display the data in detail in JSON Format')
        parser.add_option('-v', '--version', action='store_true', dest='version',  help='Display version for more information')
        
        (options, args) = parser.parse_args()
        return (options, args)
    
    def save_packets_json(self, header, packets_list):
        """
        Receives a list of captured packets and creates a dictionote to successfully run the script you must be rootnary (JSON) 
        of captured packets and stores them in a .json file
        """
        collect_packets = { 'metadata_packet': [] }
        for packets in packets_list:
            packet = dict().fromkeys(header)
            for (key,value), metadata in zip(packet.items(),packets):
                if key == 'data':
                    packet[key] = str(metadata)
                else:
                    packet[key] = metadata
            collect_packets['metadata_packet'].append(packet)
        json_collect_packets = json.dumps(collect_packets, indent = 4) 
        with open(self._filename + '.json', 'w') as outfile: 
            outfile.write(json_collect_packets) 
        return json_collect_packets
        
    def save_packets_csv(self, header, packets_list):
        """
        Receives a list of captured packets and stores them in a .csv file
        """
        with open(self._filename + '.csv', 'w') as outfile:  
            csv_writer = csv.writer(outfile)  
            csv_writer.writerow(header)  
            csv_writer.writerows(packets_list) 
    
    def load_progress_bar(self, packet_number, total_collect_packets):
        """
        Progress bar of captured packets 
        """
        prefix, suffix  = 'Loading...:', 'Progress:'
        if packet_number == total_collect_packets:
            prefix, suffix  = 'Ready ...:', 'Completed:'
        percent = ('{0:.' + str(0) + 'f}').format( (100 * packet_number) / float(total_collect_packets)  )
        filled_space = int( (50 * packet_number) // total_collect_packets )
        bar = '█' * filled_space + '-' * (50 - filled_space)
        print(f'\r[+] :: {prefix} |{bar}|  {suffix:}{percent}% ({packet_number}/{total_collect_packets} collected packets)', end = '\r')
        if packet_number == total_collect_packets: 
            print()
   
    def capture_packets(self,total_collect_packets,empty_packet,protocol_enable):
        """
        Packet capture mode, until the desired number of packets is reached
        AF_INET and AF_INET6 correspond to the protocol classification PF_INET and PF_INET6.
        Which include standard IP and TCP and UDP port numbers. 
        Create a raw socket and bind it to the public interface
        """
        try:
            collect_packets = list()
            
            if protocol_enable == 'TCP':
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            elif protocol_enable == 'ICMP' or protocol_enable == 'UDP':
                server_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            
            self.load_progress_bar(0, total_collect_packets)
        except socket.error as message:
            print(f'Problem in the socket cant create : {str(message[0])} SocketExeption: {message[1]}')
            sys.exit()
        packet_number = 0
        while True:
            time.sleep(0.1)
            self.load_progress_bar(packet_number, total_collect_packets)
            if packet_number == total_collect_packets:
                break
            # Receive data from the socket packetd. 
            packet = server_socket.recvfrom(65565)
            # TCP packet, Take the first 20 characters for the IP header.
            packet = packet[0] 
            ip_header = packet[0:20] 
            
            eth_header = packet[:Ethernet.LENGTH]
            eth_header_packet = Ethernet(eth_header,packet[0:6],packet[6:12])
            eth_header_unpacked = eth_header_packet.get_attributes() 
            
            ip_header_packet = IP(ip_header)
            ip_header_unpacked = ip_header_packet.get_attributes()
            ip_header_unpacked_length = ip_header_unpacked[0] 
            ip_header_unpacked_struct = ip_header_unpacked[1]
            
            x = ip_header_unpacked_length + Ethernet.LENGTH
            
            # [TCP] Transmission Control protocol [RFC 793][code:6]
            if protocol_enable == 'TCP':
                if ip_header_unpacked[2] == 6:
                    
                    tcp_header = packet[ip_header_unpacked_length:ip_header_unpacked_length + 20]
                    tcp_header_packet = TCP(tcp_header,ip_header_unpacked_length,packet)
                    tcp_header_unpacked = tcp_header_packet.get_attributes()
                    packet_info =  [ packet_number, str(datetime.datetime.now()), ] + eth_header_unpacked + ip_header_unpacked_struct + tcp_header_unpacked
                
                    if empty_packet == False:
                        collect_packets.append(packet_info)
                        packet_number += 1
                    else:
                        if tcp_header_unpacked[10] != b'':
                            collect_packets.append(packet_info)
                            packet_number += 1
                            
            # [ICMP] Internet Control Message protocol [RFC 792][code:1]
            elif protocol_enable == 'ICMP':
                if ip_header_unpacked[2] == 1:
                    
                    icmp_header = packet[x:( x + 4 )]
                    icmp_header_packet = ICMP(icmp_header)
                    icmp_header_unpacked = icmp_header_packet.get_attributes()
                    header_size = Ethernet.LENGTH + ip_header_unpacked_length + ICMP.LENGTH
                    data = packet[header_size:]
                    packet_info =  [ packet_number, str(datetime.datetime.now()), ] + eth_header_unpacked + ip_header_unpacked_struct + icmp_header_unpacked + [ data ]
                
                    if empty_packet == False:
                        collect_packets.append(packet_info)
                        packet_number += 1
                    else:
                        if data != b'':
                            collect_packets.append(packet_info)
                            packet_number += 1
                            
            # [UDP] User Datagram Protocol [RFC 768][code:17]
            elif protocol_enable == 'UDP':
                if ip_header_unpacked[2] == 17:
                    
                    udp_header = packet[x:( x + 8)]
                    udp_header_packet = UDP(udp_header)
                    udp_header_unpacked = udp_header_packet.get_attributes()
                    
                    header_size = Ethernet.LENGTH + ip_header_unpacked_length + UDP.LENGTH
                    data = packet[header_size:]
                    
                    packet_info =  [ packet_number, str(datetime.datetime.now()), ] + eth_header_unpacked + ip_header_unpacked_struct + udp_header_unpacked + [ data ]
                
                    if empty_packet == False:
                        collect_packets.append(packet_info)
                        packet_number += 1
                    else:
                        if data != b'':
                            collect_packets.append(packet_info)
                            packet_number += 1
        return collect_packets
        
def main(argv):
    
    (options, args) = DarkSniffer.options()
    darksniffer = DarkSniffer('collect_packets')
    
    amount_packets = darksniffer.AMOUNT_PACKETS
    current_protocol = darksniffer.PACKET_TCP_METADATA
    save_csv = empty_packet = packet_details = False
    protocol_packets = 'TCP'
    display_fields = ['no_packet','source_address','source_port','destination_port','time_to_live','fragment_Offset','sequence_number','acknowledgment_number']
    
    if options.protocol:
        protocol_packets = (options.protocol).upper()
        if (protocol_packets != 'TCP') and (protocol_packets != 'ICMP') and (protocol_packets != 'UDP'):
            sys.exit('The argument of the protocol is invalid!')
        
    if options.filename_csv:
        darksniffer.filename = options.filename_csv
        save_csv = True
        
    if options.filename_json:
        darksniffer.filename = options.filename_json
        
    if options.filename_csv:
        darksniffer.filename = options.filename_csv
    
    if options.packets:
        amount_packets = options.packets
    
    if options.empty_packet:
        empty_packet = True
    
    if options.json:
        packet_details = True
    
    if options.version:
        DarkSniffer.banner()
        print('\n\tThis program may be freely redistributed under',
                'the terms of the GNU General Public License (GLP V3).',
                sep = '\n\t')
        sys.exit()
    
    if options.interactive:
        DarkSniffer.banner()
        darksniffer.filename = input('[+]  ::  Enter a filename to JSON & CSV file : ')
        amount_packets = int(input('[+]  ::  Enter amount packets to capture : '))
        print('\t :: Warning: Be very careful when choosing ICMP as you need to perform some action', 
                ' :: that will trigger the sending of packages of this protocol. ',
                ' :: If you dont receive ICMP protocol packages, immediately kill the program with crtl + c',
                sep = '\n\t')
        protocol_packets = input('[+]  ::  Enter protocol packets to capture [TCP/ICMP/UDP]: ').upper()
        
        if protocol_packets == 'ICMP':
            current_protocol = darksniffer.PACKET_ICMP_METADATA
        elif protocol_packets == 'UDP':
            current_protocol = darksniffer.PACKET_UDP_METADATA
        
        response_empty_packet = input('[+]  ::  Accept empty packets [Y/N]: ')
        if response_empty_packet == 'Y' or response_empty_packet == 'y':
            empty_packet = True
        
        response_view_json = input('[+]  ::  View mode JSON File [Y/N]: ')
        if response_view_json == 'Y' or response_view_json == 'y':
            packet_details = True
        
        else:
            print('IP  Header: ', darksniffer.NO_PACKET + IP.HEADER)
            
            if protocol_packets == 'TCP':
                print('TCP Header: ', darksniffer.NO_PACKET + TCP.HEADER)
            elif protocol_packets == 'ICMP':
                print('ICMP Header: ', darksniffer.NO_PACKET + ICMP.HEADER)
            elif protocol_packets == 'UDP':
                print('UDP Header: ', darksniffer.NO_PACKET + UDP.HEADER)
            
            response_view_table = input(f'[+]  ::  View mode data in the table packet struct [IP/{protocol_packets}] : ').upper()
            
            if response_view_table == 'IP':
                display_fields = darksniffer.NO_PACKET + IP.HEADER
            elif response_view_table == 'TCP':
                display_fields = darksniffer.NO_PACKET + TCP.HEADER
            elif response_view_table == 'ICMP':
                display_fields = darksniffer.NO_PACKET + ICMP.HEADER
            elif response_view_table == 'UDP':
                display_fields = darksniffer.NO_PACKET + UDP.HEADER
            
    table = PrettyTable()
    table.field_names = current_protocol
    collect_packets = darksniffer.capture_packets(amount_packets,empty_packet,protocol_packets)
    
    if save_csv:
        darksniffer.save_packets_csv(current_protocol, collect_packets)
    
    packets_json = darksniffer.save_packets_json(current_protocol, collect_packets)
    
    for packet_info in collect_packets: 
        table.add_row(packet_info)
    
    if packet_details == False :
        print(table.get_string(fields = display_fields ))
    else:
        print(packets_json)        
    sys.exit()

if __name__ == '__main__':
    try:
        if sys.version_info >= (3, 5):
            if os.getuid() == 0:
                main(sys.argv[1:])
            else:
                sys.exit('[+] :: Note to successfully run the script you must be root.')
        else:
            sys.exit('[+] :: Please update your python version 3.5 or higher.')
    except KeyboardInterrupt:
        sys.exit('[+] :: Ctrl + C .................... Bye :C')
    except Exception as exeption:
        sys.exit(f'[+] :: An exception has occurred: {str(exeption)}')
