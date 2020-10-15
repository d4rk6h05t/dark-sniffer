#!/usr/bin/env python3

#   Author: Copyright (C) 2020 Michani. M. De La Calleja E. [ d4rk6h05t ~тёмный призрак ]

from struct import *

class TCP:
    
    HEADER = [
        'source_port', 'destination_port', 'sequence_number', 'acknowledgment_number', 'tcp_header_length', 
        'data_offset_reserved', 'tcp_flags', 'window', 'tcp_checksum', 'urgent_pointer',
    ]
    
    def __init__(self, tcp_header, ip_header_unpacked_length, packet):
        self._tcp_header = tcp_header
        self._ip_header_unpacked_length = ip_header_unpacked_length
        self._packet = packet
        self.unpack_tcp_packet()
    
    def unpack_tcp_packet(self): 
        """
        Unpacking of the TCP header
        [ ! + HHLLBBHHH ] = (
            ('destination_port', 'H', 0),
            ('sequence_number', 'I', 3735928559L),
            ('acknowledgment_number', 'I', 0),
            ('data_offset_reserved', 'B', 80),
            ('tcp_flags', 'B', 2),
            ('window', 'H', 65535),
            ('checksum', 'H', 0),
            ('urgent_pointer', 'H', 0)
        )
        """
        tcp_header = unpack('!HHLLBBHHH' , self._tcp_header) 
        # Package metadata collection TCP header
        self._source_port, self._destination_port, self._sequence_number = tcp_header[0], tcp_header[1], tcp_header[2] 
        self._acknowledgment_number, self._data_offset_reserved, self._tcp_flags = tcp_header[3], tcp_header[4], tcp_header[5]
        self._window, self._tcp_checksum, self._urgent_pointer = tcp_header[6], tcp_header[7], tcp_header[8]
        
        self._tcp_header_length = self._data_offset_reserved >> 4
        
        header_size = ( self._ip_header_unpacked_length + ( self._tcp_header_length * 4 ) )
        
        # Retrieve packet data TCP
        # If the target you're analyzing is using the https protocol, the information will obviously be encrypted. 
        # On the other hand, if the target you are scanning only uses http, the information will appear in plain text.
        self._data = self._packet[header_size:]
        
    def get_attributes(self):
        return [ self._source_port, self._destination_port, self._sequence_number, self._acknowledgment_number, self._tcp_header_length, 
                self._data_offset_reserved, self._tcp_flags, self._window, self._tcp_checksum, self._urgent_pointer, self._data ]
