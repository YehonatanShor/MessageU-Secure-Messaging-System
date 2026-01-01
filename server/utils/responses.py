"""
Response building utilities for MessageU server.

This module provides functions for constructing and sending responses
to clients according to the protocol specification.
"""

import struct
from config import constants


def send_response(conn, response_code, payload):
    """
    Send a response to the client.
    
    Args:
        conn: The client connection socket
        response_code: The response code (from constants)
        payload: The response payload as bytes
    """
    try:
        header = struct.pack(
            '!BHI',
            constants.SERVER_VERSION,
            response_code,
            len(payload))
        conn.sendall(header + payload)
    except Exception as e:
        print(f"Error sending response code {response_code}: {e}")


def send_error_response(conn, error_message):
    """
    Send an error response to the client.
    
    Args:
        conn: The client connection socket
        error_message: The error message to send (will be encoded as UTF-8)
    """
    print(f"Sending error to {conn.getpeername()}: {error_message}")
    payload = error_message.encode('utf-8')
    header = struct.pack(
        '!BHI',
        constants.SERVER_VERSION,
        constants.RESPONSE_CODE_GENERAL_ERROR,
        len(payload))
    try:
        conn.sendall(header + payload)
    except Exception as e:
        print(f"Error sending error response: {e}")


def send_registration_success(conn, client_uuid_bytes):
    """
    Send registration success response with assigned UUID to client.
    
    Args:
        conn: The client connection socket
        client_uuid_bytes: The UUID assigned to the client (16 bytes)
    """
    print(
        f"Sending registration success to {conn.getpeername()}, UUID: {client_uuid_bytes.hex()}")
    header = struct.pack(
        '!BHI',
        constants.SERVER_VERSION,
        constants.RESPONSE_CODE_REGISTER_SUCCESS,
        len(client_uuid_bytes))
    try:
        conn.sendall(header + client_uuid_bytes)
    except Exception as e:
        print(f"Error sending success response: {e}")


