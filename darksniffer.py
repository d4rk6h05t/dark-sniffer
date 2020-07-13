#!/usr/bin/python
# -*- coding: utf-8 -*-
__author__  = 'd4rk6h05t [Michani. M. De La Calleja E.]'
__version__ = 'v1.0.0'
__github__  = 'https://github.com/d4rk6h05t/dark-sniffer'
__email__   = 'd4rk6h05t_0d4y5@protonmail.ch'
__license__ = 'GPL V3'
"""
I point out that the hacking-related material found in the github account (d4rk6h05t) is for educational and demonstration purposes only. 
You are responsible for your own actions.

DarkSniffer [ small DarkSniffer only TCP incoming packet ]
Sniffers are programs that can capture/sniff/detect packet of network traffic per packet and analyze
additional note to successfully run the script you must be root or prepend the sudo command at the time of executing the script, for example: 
 
 $ sudo python darksniffer.py
 or 
 $ sudo ./darksniffer.py
 
Author: d4rk6h05t [ Michani. M. De La Calleja E. / d4rk6h05t_0d4y5@protonmail.ch ]
"""
import csv  
import time
import json
import getopt
import datetime

from struct import *
import socket, sys, os
from prettytable import PrettyTable, from_csv

class DarkSniffer:
    
    ETH_LENGTH = 14
    ICMPH_LENGTH = 4
    
    AMOUNT_PACKETS = 5
    
    NO_PACKET = ['no_packet','datetime']
    
    ETH_HEADER = [ 'destination_mac_address', 'source_mac_address', 'eth_protocol', ]
   
    PACKET_IP_HEADER = [
        'version', 'type_of_service', 'total_length', 'identification', 'fragment_Offset',
        'time_to_live', 'tcp_protocol', 'header_checksum', 'source_address', 'destination_address',
    ]
    
    PACKET_TCP_HEADER = [
        'source_port', 'destination_port', 'sequence_number', 'acknowledgment_number', 'tcp_header_length', 
        'data_offset_reserved', 'tcp_flags', 'window', 'tcp_checksum', 'urgent_pointer',
    ]
    
    PACKET_ICMP_HEADER = [ 'icmp_type', 'code', 'checksum' ]
   
    METADATA_DATA = ['data']
    
    PACKET_TCP_METADATA = NO_PACKET + ETH_HEADER + PACKET_IP_HEADER + PACKET_TCP_HEADER + METADATA_DATA
    PACKET_ICMP_METADATA = NO_PACKET + ETH_HEADER + PACKET_IP_HEADER + PACKET_ICMP_HEADER + METADATA_DATA
    
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
        print(f'███████╗ █████╗ ██████╗ ██╗  ██╗     ███████╗███╗  ██╗██████╗██████╗██████╗███████╗██████╗ \n' 
              f'██╔═══█║██╔══██╗██╔══██╗██║ ██╔╝     ██╔════╝████╗ ██║╚═██╔═╝██╔═══╝██╔═══╝██╔════╝██╔══██╗\n'
              f'██║   █║███████║██████╔╝█████╔╝█████╗███████╗██╔██╗██║  ██║  ██████╗██████╗█████╗  ██████╔╝\n'
              f'██║   █║█ ╔══██║██╔══██╗██╔═██╗╚════╝╚════██║██║╚████║  ██║  ██╔═══╝██╔═══╝██╔══╝  ██╔══██╗\n'
              f'███████║█ ║  ██║██║  ██║██║  ██╗     ███████║██║ ╚═██║██████╗██║    ██║    ███████╗██║  ██║\n'
              f' ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝     ╚══════╝╚═╝   ╚═╝╚═════╝╚═╝    ╚═╝    ╚══════╝╚═╝  ╚═╝')
        print(f'[+] :: By: {__author__}  :: An small 5n1ff3r {__version__}\n')
    
    @staticmethod
    def usage():
        print (f' Usage: darksniffer [option] [args]\n'
               f'\t-f \t--file <filename>   \t Set name to JSON, CSV file where the details of the intercepted packets is stored \n'
               f'\t-c \t--customize         \t Customize packet capture arguments \n'
               f'\t-p \t--packets <amount>  \t Amount of packages to be captured \n'
               f'\t-e \t--empty-packet      \t Accept empty packages in the data field \n'
               f'\t-i \t--ip-header         \t Display the IP header struct \n'
               f'\t-t \t--tcp-header        \t Display the TCP header struct \n'
               f'\t-j \t--json-details      \t Display the data in detail \n'
               f'\t-h \t--help              \t Display this help and exit\n'
               f'\t-v \t--version           \t Display version for more information\n')
    
    def get_protocol(self,number_protocol):
        # based in IP protocol numbers found in the protocol field of the IPv4 header
        # for more info: https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
        # Currently the most commonly used protocol is TCP but there may be exceptions 
        # return a list with protocol, small description and rfc
        protocols = { 
            0: ['HOPOPT','IPv6 Hop-by-Hop Option','8200'], 
            1: ['ICMP', 'Internet Control Message protocol','792'], 
            2: ['IGMP', 'Internet Group Management protocol','1112'],
            3: ['GGP', 'Gateway-to-Gateway protocol', '823'], 
            4: ['IP-in-IP', 'IP in IP (encapsulation)', '2003'], 
            5: ['ST', 'Internet Stream protocol', '1190,1819'],
            6: ['TCP', 'Transmission Control protocol', '793'],
            7: ['CBT', 'Core-based trees', '2189'],
            8: ['EGP', 'Exterior Gateway protocol', '888'],
            9: ['IGP', 'Interior Gateway protocol', ''],
        } 
        return protocols.get(number_protocol, 'number_protocol')
    
    def save_packets_json(self, header, packets_list):
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
        with open(self._filename + '.csv', 'w') as outfile:  
            csv_writer = csv.writer(outfile)  
            csv_writer.writerow(header)  
            csv_writer.writerows(packets_list) 
    
    def load_progress_bar(self, packet_number, total_collect_packets):
        prefix, suffix  = 'Loading...:', 'Progress:'
        if packet_number == total_collect_packets:
            prefix, suffix  = 'Ready ...:', 'Completed:'
        percent = ('{0:.' + str(0) + 'f}').format( (100 * packet_number) / float(total_collect_packets)  )
        filled_space = int( (50 * packet_number) // total_collect_packets )
        bar = '█' * filled_space + '-' * (50 - filled_space)
        print(f'\r[+] :: {prefix} |{bar}|  {suffix:}{percent}% ({packet_number}/{total_collect_packets} collected packets)', end = '\r')
        if packet_number == total_collect_packets: 
            print()
    
    def unpack_eth_header(self, eth_header, destination_mac, source_mac):
        eth_header_unpacked = unpack('!6s6sH',eth_header)
        destination_mac_address = str(destination_mac)
        source_mac_address = str(source_mac)
        eth_protocol = socket.ntohs(eth_header_unpacked[2])
        return [ destination_mac_address, source_mac_address, eth_protocol ]
    
    def unpack_icmp_packet(self, icmp_header):
        icmp_header_unpacked = unpack('!BBH', icmp_header)
        icmp_type = icmp_header_unpacked[0]
        code = icmp_header_unpacked[1]
        checksum = icmp_header_unpacked[2]
        return [ icmp_type, code, checksum ]
    
    def unpack_ip_packet(self,ip_header):
        # At the moment, unpack them IP header
        ip_header_unpacked = unpack('!BBHHHBBH4s4s', ip_header) 
        
        # TCP IP packet metadata collection
        ip_header_length_version = ip_header_unpacked[0]
        ip_header_version = ip_header_length_version >> 4
        ip_header_length = ip_header_length_version & 0xF
        ip_header_unpacked_length = ip_header_length * 4
        
        # ttl [ Time to Live ] , protocol, header checksum, more
        version, type_of_service, total_length = ip_header_unpacked[0], ip_header_unpacked[1], ip_header_unpacked[2]
        identification, fragment_Offset, time_to_live = ip_header_unpacked[3], ip_header_unpacked[4], ip_header_unpacked[5]
        protocol, header_checksum =  ip_header_unpacked[6], ip_header_unpacked[7] 
        source_address,destination_address = socket.inet_ntoa(ip_header_unpacked[8]), socket.inet_ntoa(ip_header_unpacked[9])
        
        return ( ip_header_unpacked_length , [ 
            version, type_of_service, total_length, identification, fragment_Offset,
            time_to_live, (self.get_protocol(protocol))[0], header_checksum, source_address, destination_address,  
        ], protocol )
        
    def unpack_tcp_packet(self,tcp_header,ip_header_unpacked_length,packet): 
        # At the moment, unpack them TCP header
        tcp_header = unpack('!HHLLBBHHH' , tcp_header) 
        # Package metadata collection TCP header
        source_port, destination_port, sequence_number, acknowledgment_number = tcp_header[0], tcp_header[1], tcp_header[2], tcp_header[3]
        data_offset_reserved, tcp_flags, window, tcp_checksum, urgent_pointer = tcp_header[4] ,tcp_header[5], tcp_header[6], tcp_header[7], tcp_header[8]
        tcp_header_length = data_offset_reserved >> 4
        
        header_size = ( ip_header_unpacked_length + ( tcp_header_length * 4 ) )
        
        # Retrieve packet data TCP
        # If the target you're analyzing is using the https protocol, the information will obviously be encrypted. 
        # On the other hand, if the target you are scanning only uses http, the information will appear in plain text.
        data = packet[header_size:]
        
        return [ source_port, destination_port, sequence_number, acknowledgment_number, tcp_header_length, 
                data_offset_reserved, tcp_flags, window, tcp_checksum, urgent_pointer, data ]
   
    def collect_packets(self,total_collect_packets,empty_packet,protocol_enable):
        try:
            # AF_INET and AF_INET6 correspond to the protocol classification PF_INET and PF_INET6.
            # Which include standard IP and TCP and UDP port numbers. 
            # Create a raw socket and bind it to the public interface
            collect_packets = list()
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            self.load_progress_bar(0, total_collect_packets)
        except socket.error as message:
            print('Problem in the socket cant create.  : SocketExeption' + str(message[0]) + ' Message ' + message[1])
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
            eth_header = packet[:self.ETH_LENGTH]
            
            eth_header_unpacked = self.unpack_eth_header(eth_header,packet[0:6],packet[6:12])
            
            ip_header_unpacked = self.unpack_ip_packet(ip_header)
            ip_header_unpacked_length = ip_header_unpacked[0] 
            ip_header_unpacked_struct = ip_header_unpacked[1]
            if protocol_enable == 'TCP':
                # TCP Protocol
                if ip_header_unpacked[2] == 6:
                    tcp_header = packet[ip_header_unpacked_length:ip_header_unpacked_length + 20]
                    tcp_header_unpacked = self.unpack_tcp_packet(tcp_header,ip_header_unpacked_length,packet)
                    packet_info =  [ packet_number, str(datetime.datetime.now()), ] + eth_header_unpacked + ip_header_unpacked_struct + tcp_header_unpacked
                
                    if empty_packet == False:
                        collect_packets.append(packet_info)
                        packet_number += 1
                    else:
                        if tcp_header_unpacked[10] != b'':
                            collect_packets.append(packet_info)
                            packet_number += 1
            elif protocol_enable == 'ICMP':
                # ICMP Protocol
                if ip_header_unpacked[2] == 1:
                    x = ip_header_unpacked_length + self.ETH_LENGTH
                    icmp_header = packet[x:( x + 4 )]
                    icmp_header_unpacked = self.unpack_icmp_packet(icmp_header)
                    header_size = self.ETH_LENGTH + ip_header_unpacked_length + self.ICMPH_LENGTH
                    data = packet[header_size:]
                    packet_info =  [ packet_number, str(datetime.datetime.now()), ] + eth_header_unpacked + ip_header_unpacked_struct + icmp_header_unpacked + [ data ]
                
                    if empty_packet == False:
                        collect_packets.append(packet_info)
                        packet_number += 1
                    else:
                        if data != b'':
                            collect_packets.append(packet_info)
                            packet_number += 1
                      
        return collect_packets
             
def main(argv):
    try:
        opts, args = getopt.getopt(argv, 'hcfpeitjv', [
            'help','customize','file','packets','empty-packet','ip-header','tcp-header','json-details','version'
        ])
        darksniffer = DarkSniffer('collect_packets')
        amount_packets = darksniffer.AMOUNT_PACKETS
        current_protocol = darksniffer.PACKET_TCP_METADATA
        empty_packet = packet_details = False
        protocol_packets = 'TCP'
        target_hostname = 'google.com'
        display_fields = ['no_packet','source_address','source_port','destination_port','time_to_live','fragment_Offset','sequence_number','acknowledgment_number']
    except getopt.GetoptError:
        DarkSniffer.usage()
        sys.exit(2)
    
    for opt, arg in opts:
        
        if opt in ('-h', '--help'):
            DarkSniffer.usage()
            sys.exit()
        
        elif opt in ('-c', '--customize'):
            DarkSniffer.banner()
            darksniffer.filename = str(input('[+]  ::  Enter a filename to JSON & CSV file : '))
            amount_packets = int(input('[+]  ::  Enter amount packets to capture : '))
            print(f'[+] :: Warning: Be very careful when choosing ICMP as you need to perform some action\n' 
                  f'[+] :: that will trigger the sending of packages of this protocol. \n'
                  f'[+] :: If you dont receive ICMP protocol packages, immediately kill the program with crtl + c')
            protocol_packets = str(input('[+]  ::  Enter protocol packets to capture [TCP/ICMP]: ')).upper()
            
            if protocol_packets == 'ICMP':
                current_protocol = darksniffer.PACKET_ICMP_METADATA
            
            response_empty_packet = str(input('[+]  ::  Accept empty packets [Y/N]: '))
            if response_empty_packet == 'Y' or response_empty_packet == 'y':
                empty_packet = True
            
            response_view_json = str(input('[+]  ::  View mode JSON File [Y/N]: '))
            if response_view_json == 'Y' or response_view_json == 'y':
                packet_details = True
                break
            else:
                print('IP  Header: ', darksniffer.NO_PACKET + darksniffer.PACKET_IP_HEADER)
                print('TCP Header: ', darksniffer.NO_PACKET + darksniffer.PACKET_TCP_HEADER)
                response_view_table = (str(input('[+]  ::  View mode data in the table packet struct [IP/TCP] : '))).upper()
                if response_view_table == 'IP':
                    display_fields = darksniffer.NO_PACKET + darksniffer.PACKET_IP_HEADER
                elif response_view_table == 'TCP':
                    display_fields = darksniffer.NO_PACKET + darksniffer.PACKET_TCP_HEADER
                else:
                    break
        elif opt in ('-f', '--file'):
            darksniffer.filename = argv[1]
        elif opt in ('-p', '--packets'):
            amount_packets = int(argv[1])
        elif opt in ('-e', '--empty-packet'):
            empty_packet = True
        elif opt in ('-i', '--ip-header'):
            display_fields = darksniffer.NO_PACKET + darksniffer.PACKET_IP_HEADER
        elif opt in ('-t', '--tcp-header'):
            display_fields = darksniffer.NO_PACKET + darksniffer.PACKET_TCP_HEADER
        elif opt in ('-j', '--json-details'):
            packet_details = True
        elif opt in ('-v', '--version'):
           DarkSniffer.banner()
           DarkSniffer.usage()
           print(f'This program may be freely redistributed under'
                 f'the terms of the GNU General Public License (GLP V3).')
           sys.exit()
    
    table = PrettyTable()
    table.field_names = current_protocol
    collect_packets = darksniffer.collect_packets(amount_packets,empty_packet,protocol_packets)
    darksniffer.save_packets_csv(current_protocol, collect_packets)
    packets_json = darksniffer.save_packets_json(current_protocol, collect_packets)
    
    for packet_info in collect_packets: 
        table.add_row(packet_info)
    
    #print(packets_json)
    if packet_details == False :
        print(table.get_string(fields = display_fields ))
    else:
        print(packets_json)
        
    sys.exit()
    
if __name__ == '__main__':
    main(sys.argv[1:])
