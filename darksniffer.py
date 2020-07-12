#!/usr/bin/python
# -*- coding: utf-8 -*-
__author__  = 'd4rk6h05t [Michani. M. De La Calleja E.]'
__version__ = 'v1.0.0'
__github__  = 'https://github.com/d4rk6h05t/dark-sniffer'
__email__   = 'd4rk6h05t_0d4y5@protonmail.ch'
__license__ = 'GPL V3'
"""
We point out that the hacking related material found in the github account (d4rk6h05t) is for educational and demonstration purposes only.
We are not responsible for any damages. You are responsible for your own actions.

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
import binascii
import socket, sys, os
from struct import * 
from prettytable import PrettyTable, from_csv

class DarkSniffer:
    
    AMOUNT_PACKETS = 5
    
    NO_PACKET = ['no_packet',]
    
    PACKET_IP_HEADER = [
        'version', 'type_of_service', 'total_length', 'identification', 'fragment_Offset',
        'time_to_live', 'tcp_protocol', 'header_checksum', 'source_address', 'destination_address',
    ]
    
    PACKET_TCP_HEADER = [
        'source_port', 'destination_port', 'sequence_number', 'acknowledgment_number', 'tcp_header_length', 
        'data_offset_reserved', 'tcp_flags', 'window', 'tcp_checksum', 'urgent_pointer',
    ]
    
    PACKET_TCP_HEADER_DATA = ['data']
    
    PACKET_METADATA = NO_PACKET + PACKET_IP_HEADER + PACKET_TCP_HEADER + PACKET_TCP_HEADER_DATA
    
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
               f'\t-f \t--file <filename>   \t CSV file where a dictionary of the details of the intercepted pauqtes is stored \n'
               f'\t-p \t--packets <amount>  \t Amount of packages to be captured \n'
               f'\t-e \t--empty-packet      \t Accept empty packages in the data field \n'
               f'\t-i \t--ip-header         \t Display the IP header struct \n'
               f'\t-t \t--tcp-header        \t Display the TCP header struct \n'
               f'\t-d \t--details           \t Display the data in detail \n'
               f'\t-u \t--url               \t Capture packets from url pattern target \n'
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
    
    def display_metadata_packet(self,protocol,destination_address,tcp_header_length,ip_header_version,ip_header_length):
        print(f'\n[+] :: protocol : {protocol}'
             f' :: destination addr : {destination_address}'
             f' :: TCP Header Length : {tcp_header_length}'
             f' :: IP Headader Version : {ip_header_version}' 
             f' :: IP Header Length.: {ip_header_length}\n')
    
    def display_details_packet(self,collect_packets):
        for packet in collect_packets:
            print(f'[{packet[0]}]  :: ==========  I P   H E A D E R   F O R M A T ========== ::')
            print(f'[{packet[0]}]  :: IP Header Version : {packet[1]} \t'
                                f' :: Type Of Service : {packet[2]} \t'
                                f' :: IP HeaderTotal Length : {packet[3]} \t' 
                                f' :: Idientification: {packet[4]} \t'
                                f' :: Fragment offset : {packet[5]}')
            print(f'[{packet[0]}]  :: Time to live : {packet[6]} \t'
                                f' :: Protocol : {self.get_protocol(packet[7])} \t'
                                f' :: Header Checksum : {packet[8]} \t' 
                                f' :: Source Address: {packet[9]} \t'
                                f' :: Destination Address: : {packet[10]}')
            print(f'[{packet[0]}]  :: =========  T C P    H E A D E R   F O R M A T ========= ::')
            print(f'[{packet[0]}]  :: Source Port : {packet[11]} \t' 
                                f' :: Destination Port: {packet[12]} \t'
                                f' :: Sequence number: {packet[13]} \t'
                                f' :: Acknowledgment number: {packet[14]} \t'
                                f' :: TCP Header length : {packet[15]} \t')
            print(f'[{packet[0]}]  :: Data offset & reserved : {packet[16]} \t' 
                                f' :: TCP Flags: {packet[17]} \t'
                                f' :: Window: {packet[18]} \t'
                                f' :: TCP Checksumr: {packet[19]} \t'
                                f' :: Urgent Pointer : {packet[20]} \t')
            print(f'[{packet[0]}]  :: Data:{packet[21]}\n')
    
    def save_packets_data(self,header,packets_data):
        #collect_packets = {}
        #dict.fromkeys(self.PACKET_METADATA)
        with open(self._filename + '.csv', 'w') as csvfile:  
            csv_writer = csv.writer(csvfile)  
            csv_writer.writerow(header)  
            csv_writer.writerows(packets_data) 
    
    def load_progress_bar(self,packet_number, total_collect_packets):
        prefix, suffix  = 'Loading...:', 'Progress:'
        if packet_number == total_collect_packets:
            prefix, suffix  = 'Ready ...:', 'Completed:'
        percent = ('{0:.' + str(0) + 'f}').format( (100 * packet_number) / float(total_collect_packets)  )
        filled_space = int( (50 * packet_number) // total_collect_packets )
        bar = '█' * filled_space + '-' * (50 - filled_space)
        print(f'\r[+] :: {prefix} |{bar}|  {suffix:}{percent}% ({packet_number}/{total_collect_packets} collected packets)', end = '\r')
        if packet_number == total_collect_packets: 
            print()
    
    def unpack_ip_packet(self,ip_header):
        # At the moment, unpack them IP header
        ip_header_unpacked = unpack('!BBHHHBBH4s4s', ip_header) 
        
        # TCP IP packet metadata collection
        ip_header_length_version = ip_header_unpacked[0]
        ip_header_version = ip_header_length_version >> 4
        ip_header_length = ip_header_length_version & 0xF
        ip_header_unpacked_length = ip_header_length * 4
        
        # ttl [ Time to Live ] , TCP protocol, header checksum
        version, type_of_service, total_length = ip_header_unpacked[0], ip_header_unpacked[1], ip_header_unpacked[2]
        identification, fragment_Offset, time_to_live = ip_header_unpacked[3], ip_header_unpacked[4], ip_header_unpacked[5]
        tcp_protocol, header_checksum =  ip_header_unpacked[6], ip_header_unpacked[7] 
        source_address,destination_address = socket.inet_ntoa(ip_header_unpacked[8]), socket.inet_ntoa(ip_header_unpacked[9])
        
        return ( ip_header_unpacked_length , [ 
            version, type_of_service, total_length, identification, fragment_Offset,
            time_to_live, tcp_protocol, header_checksum, source_address, destination_address,  
        ])
        
    def unpack_tcp_packet(self,tcp_header,ip_header_unpacked_length,tcp_packet): 
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
        data = tcp_packet[header_size:]
        data_b2a_hex = binascii.b2a_hex(data)
        
        return [ source_port, destination_port, sequence_number, acknowledgment_number, tcp_header_length, 
                data_offset_reserved, tcp_flags, window, tcp_checksum, urgent_pointer, data, ]
   
    def collect_packets(self,total_collect_packets,empty_packet):
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
            tcp_packet = server_socket.recvfrom(65565)
            # TCP packet, Take the first 20 characters for the IP header.
            tcp_packet = tcp_packet[0] 
            ip_header = tcp_packet[0:20] 
    
            ip_header_unpacked = self.unpack_ip_packet(ip_header)
            ip_header_unpacked_length = ip_header_unpacked[0] 
            ip_header_unpacked_struct = ip_header_unpacked[1]
            tcp_header = tcp_packet[ip_header_unpacked_length:ip_header_unpacked_length + 20]
            
            tcp_header_unpacked = self.unpack_tcp_packet(tcp_header,ip_header_unpacked_length,tcp_packet)
        
            packet_info =  [ packet_number, ] + ip_header_unpacked_struct + tcp_header_unpacked
            
            if empty_packet == False:
                collect_packets.append(packet_info)
                packet_number += 1
            else:
                if tcp_header_unpacked[10] != b'':
                    collect_packets.append(packet_info)
                    packet_number += 1
            
        return collect_packets
             
def main(argv):
    try:
        opts, args = getopt.getopt(argv,'hfpeitduv',['help','file','packets','empty-packet','ip-header','tcp-header','details','url','version'])
        darksniffer = DarkSniffer('collect_packets')
        amount_packets = darksniffer.AMOUNT_PACKETS
        table = PrettyTable()
        table.field_names = darksniffer.PACKET_METADATA
        empty_packet = packet_details = False
        display_fields = ['no_packet','source_address','source_port','destination_port','time_to_live','fragment_Offset','sequence_number','acknowledgment_number']
    except getopt.GetoptError:
        DarkSniffer.usage()
        sys.exit(2)
        
    for opt, arg in opts:
        if opt in ('-h', '--help'):
            DarkSniffer.banner()
            DarkSniffer.usage()
            sys.exit()
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
        elif opt in ('-d', '--details'):
            packet_details = True
        elif opt in ('-u', '--url'):
            print('Here your url or address target!')
        elif opt in ('-v', '--version'):
           DarkSniffer.banner()
           sys.exit()
        
    collect_packets = darksniffer.collect_packets(amount_packets,empty_packet)
    darksniffer.save_packets_data(darksniffer.PACKET_METADATA, collect_packets)

    for packet_info in collect_packets: 
        table.add_row(packet_info)
        
    # tmp collect_packets change positions
    darksniffer.display_metadata_packet(collect_packets[0][3],collect_packets[0][2],collect_packets[0][12],collect_packets[0][4],collect_packets[0][5])
    
    if packet_details == False :
        print(table.get_string(fields = display_fields ))
    else:
        darksniffer.display_details_packet(collect_packets)
        
    sys.exit()
    
if __name__ == '__main__':
    main(sys.argv[1:])
