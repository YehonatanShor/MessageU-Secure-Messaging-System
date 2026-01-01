"""
Protocol parsing utilities for MessageU server.

This module handles parsing and validation of the binary protocol,
including request headers and protocol version checking.
"""

import struct
from config import constants


def parse_request_header(header_data):
    """
    Parse a request header and return its components.
    
    Args:
        header_data: Raw header bytes (REQUEST_HEADER_SIZE bytes)
        
    Returns:
        tuple: (client_id, version, code, payload_size)
            - client_id: bytes (16 bytes)
            - version: int (1 byte)
            - code: int (2 bytes)
            - payload_size: int (4 bytes)
            
    Raises:
        struct.error: If header cannot be unpacked
    """
    client_id = header_data[:constants.CLIENT_UUID_SIZE]
    version, code, payload_size = struct.unpack(
        '!BHI', 
        header_data[constants.CLIENT_UUID_SIZE:])
    return client_id, version, code, payload_size


def validate_client_version(version):
    """
    Validate that the client version matches server requirements.
    
    Args:
        version: Client version number
        
    Returns:
        bool: True if version is valid, False otherwise
    """
    return version == constants.CLIENT_VERSION



