"""
Connection state management for MessageU server.

This module handles the state machine for parsing client requests,
managing buffers and tracking request progress.
"""

from config import constants


class ConnectionState:
    """
    Manages the state of a client connection.
    
    Tracks the current parsing state (HEADER or PAYLOAD), buffer contents,
    and expected data lengths for request parsing.
    """
    
    def __init__(self):
        """Initialize connection state for a new request."""
        self.reset_for_new_request()

    def reset_for_new_request(self):
        """
        Reset state for processing a new request.
        Sets state to HEADER and clears buffer.
        """
        self.state = "HEADER"
        self.buffer = b""
        self.expected_len = constants.REQUEST_HEADER_SIZE
        self.client_id = b""
        self.request_code = 0

    def set_payload_state(self, client_id, code, payload_size):
        """
        Transition to PAYLOAD state after header is parsed.
        
        Args:
            client_id: The client's UUID as bytes
            code: The request code
            payload_size: Expected payload size in bytes
        """
        self.state = "PAYLOAD"
        self.client_id = client_id
        self.request_code = code
        self.expected_len = payload_size

