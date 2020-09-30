#!/usr/bin/env python3
# Author: Copyright (C) 2020 d4rk6h05t [ Michani. M. De La Calleja E. / d4rk6h05t_0d4y5@protonmail.ch ]

from struct import *

class UDP:
    
    def __init__(self,  udp_header):
        self._udp_header = udp_header
        self.unpack_udp_packet()
        
    def unpack_udp_packet(self):
        """
        Unpacking of the UDP header
        [ ! + HHHH ] =  (
            ('source_port', 'H', 57005),
            ('destination_port', 'H', 0),
            ('u_length', 'H', 8),
            ('checksum', 'H', 0)
        )   
        """
        udp_header =  unpack('!HHHH', self._udp_header)
        self._source_port, self._destination_port = udp_header[0], udp_header[1]
        self._u_length, self._checksum = udp_header[2], udp_header[3]
        
    def get_attributes(self):
        return [ self._source_port, self._destination_port, self._u_length, self._checksum ]
