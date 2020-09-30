#!/usr/bin/env python3
# Author: Copyright (C) 2020 d4rk6h05t [ Michani. M. De La Calleja E. / d4rk6h05t_0d4y5@protonmail.ch ]

import socket
import binascii
from struct import *

class Ethernet:
    
    def __init__(self, eth_header, destination_mac, source_mac):
        self._eth_header = eth_header
        self._destination_mac = destination_mac
        self._source_mac = source_mac
        self.unpack_eth_packet()
                
    def mac(self,octet):
        """
        Converts byte octect into mac address format
        """
        mac = binascii.hexlify(octet)
        mac = list(str((mac).decode('utf-8')))
        for i in [2,5,8,11,14]:
            mac.insert(i,':')
        return ''.join(mac)
        
    def unpack_eth_packet(self):
        """
        Unpacking of the eth header 
        [ ! + 6s6sH ] = (
            ('destination_mac_address', '6s', ''),
            ('source_mac_address', '6s', ''), 
            ('eth_protocol', 'H', 2048)
        )
        """
        eth_header_unpacked = unpack('!6s6sH',self._eth_header)
        self._destination_mac_address = self.mac(self._destination_mac)
        self._source_mac_address = self.mac(self._source_mac)
        self._eth_protocol = socket.ntohs(eth_header_unpacked[2])
        
    def get_attributes(self):
        return [ self._destination_mac_address, self._source_mac_address, self._eth_protocol ]
