#!/usr/bin/env python3
# Author: Copyright (C) 2020 d4rk6h05t [ Michani. M. De La Calleja E. / d4rk6h05t_0d4y5@protonmail.ch ]

from struct import *

class ICMP:
    
    def __init__(self,  icmp_header):
        self._icmp_header = icmp_header
        self.unpack_icmp_packe()
        
    def unpack_icmp_packet(self):
        """
        Unpacking of the ICMP header
        [ ! + BBH ] = (
            ('type', 'B', 8),
            ('code', 'B', 0),
            ('checksum', 'H', 0)
        ) 
        """
        icmp_header_unpacked = unpack('!BBH', icmp_header)
        self._icmp_type = icmp_header_unpacked[0]
        self._code = icmp_header_unpacked[1]
        self._checksum = icmp_header_unpacked[2]
        
    def get_attributes(self):
        return [ self._icmp_type, self._code, self._checksum ]
