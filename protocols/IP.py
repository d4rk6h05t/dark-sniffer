#!/usr/bin/env python3
# Author: Copyright (C) 2020 d4rk6h05t [ Michani. M. De La Calleja E. / d4rk6h05t_0d4y5@protonmail.ch ]

import socket
from struct import *

class IP:
    
    HEADER = [
        'version', 'type_of_service', 'total_length', 'identification', 'fragment_Offset',
        'time_to_live', 'tcp_protocol', 'header_checksum', 'source_address', 'destination_address',
    ]
    
    def __init__(self,  ip_header):
        self._ip_header = ip_header
        self.unpack_ip_packet()
    
    def get_protocol(self,number_protocol):
        """
        based in IP protocol numbers found in the protocol field of the IPv4 header
        for more info: https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
        Currently the most commonly used protocol is TCP but there may be exceptions 
        return a list with protocol, small description and rfc
        """
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
            10: ['BBN-RCC-MON','BBN RCC Monitoring',''],
            11: ['NVP-II','Network Voice Protocol','741'],
            12: ['PUP','Xerox PUP',''],
            13: ['ARGUS','ARGUS',''],
            14: ['EMCON','EMCON',''],
            15: ['XNET','Cross Net Debugger',''],
            16: ['CHAOS','Chaos',''],
            17: ['UDP','User Datagram Protocol','768'],
            18: ['MUX','Multiplexing',''],
            19: ['DCN-MEAS','DCN Measurement Subsystems',''],
            20: ['HMP','Host Monitoring Protocol',''],
        } 
        return protocols.get(number_protocol, 'number_protocol')
    
    def unpack_ip_packet(self):
        """
        Unpacking of the IP header
        [! + BBHHHBBH4s4s] = (
            ('ip_header_length_version', 'B', 69),
            ('type_of_service', 'B', 0),
            ('total_length', 'H', 20),
            ('identification', 'H', 0),
            ('fragment_Offset', 'H', 0),
            ('time_to_live', 'B', 64),
            ('protocol', 'B', 0),
            ('header_checksum', 'H', 0)
            ('source_address', '4s', 0)
            ('destination_address', '4s', 0)
        )
        """
        ip_header_unpacked = unpack('!BBHHHBBH4s4s', self._ip_header) 
        
        # TCP IP packet metadata collection
        ip_header_length_version = ip_header_unpacked[0]
        ip_header_version = ip_header_length_version >> 4
        ip_header_length = ip_header_length_version & 0xF
        self._ip_header_unpacked_length = ip_header_length * 4
        
        # ttl [ Time to Live ] , protocol, header checksum, more
        self._version, self._type_of_service, self._total_length = ip_header_unpacked[0], ip_header_unpacked[1], ip_header_unpacked[2]
        self._identification, self._fragment_Offset, self._time_to_live = ip_header_unpacked[3], ip_header_unpacked[4], ip_header_unpacked[5]
        self._protocol, self._header_checksum =  ip_header_unpacked[6], ip_header_unpacked[7] 
        self._source_address, self._destination_address = socket.inet_ntoa(ip_header_unpacked[8]), socket.inet_ntoa(ip_header_unpacked[9])
        
    def get_attributes(self):
        return ( self._ip_header_unpacked_length , [ 
            self._version, self._type_of_service, self._total_length, self._identification, self._fragment_Offset,
            self._time_to_live, (self.get_protocol(self._protocol))[0], self._header_checksum, self._source_address, self._destination_address,  
        ], self._protocol )
