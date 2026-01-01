"""
Server socket and event loop management for MessageU server.

This module handles socket creation, connection acceptance, data reading,
and the main event loop using Python's selectors API.
"""

import struct
import selectors
import socket
from config import constants
from network.connection import ConnectionState
from network.protocol import parse_request_header, validate_client_version
from utils.responses import send_error_response


class MessageUServer:
    """
    Manages the server socket and event loop.
    
    Handles connection acceptance, data reading, and event dispatching
    using Python's selectors API for efficient I/O multiplexing.
    """
    
    def __init__(self, db_manager, port=None):
        """
        Initialize the server.
        
        Args:
            db_manager: DatabaseManager instance
            port: Port number (if None, will read from file or use default)
        """
        self.db = db_manager
        self.port = port
        self.sel = selectors.DefaultSelector()
        self.sock = None
        self.handle_request = None  # Will be set by caller
        
    def _accept_connection(self, sock, mask):
        """
        Accept a new client connection.
        
        Args:
            sock: The listening socket
            mask: Event mask (unused)
        """
        conn, addr = sock.accept()
        print('accepted connection from', addr)

        # Non-blocking socket
        conn.setblocking(False)

        # Register connection for reading with a new ConnectionState
        self.sel.register(
            conn,
            selectors.EVENT_READ,
            data={
                "callback": self._read_data,
                "state": ConnectionState()})

    def _read_data(self, conn, mask):
        """
        Read data from a client connection and process requests.
        
        Args:
            conn: The client connection socket
            mask: Event mask (unused)
        """
        # Get connection state
        state = self.sel.get_key(conn).data["state"]

        # Read data
        try:
            data = conn.recv(8192)
        except ConnectionError:
            self.sel.unregister(conn)
            conn.close()
            return
        if not data:
            self.sel.unregister(conn)
            conn.close()
            return

        # Append new data to buffer
        state.buffer += data

        # Process all complete requests in buffer
        while True:
            # Process HEADER
            if state.state == "HEADER":
                if len(state.buffer) >= constants.REQUEST_HEADER_SIZE:
                    # Extract header
                    header_data = state.buffer[:constants.REQUEST_HEADER_SIZE]
                    try:
                        client_id, version, code, payload_size = parse_request_header(header_data)
                    except struct.error:
                        send_error_response(conn, "Invalid request header format.")
                        self.sel.unregister(conn)
                        conn.close()
                        return

                    # Verify client version
                    if not validate_client_version(version):
                        send_error_response(
                            conn, f"Wrong client version: {version}")
                        self.sel.unregister(conn)
                        conn.close()
                        return

                    # Set to expect payload
                    state.set_payload_state(client_id, code, payload_size)
                    state.buffer = state.buffer[constants.REQUEST_HEADER_SIZE:]
                else:
                    break

            # Process PAYLOAD
            if state.state == "PAYLOAD":
                if len(state.buffer) >= state.expected_len:
                    # We have a complete payload, process the request
                    if self.handle_request:
                        self.handle_request(conn, state)
                else:
                    break
            if not state.buffer:
                break

    def start(self, port=None, port_filename=None):
        """
        Start the server and begin listening for connections.
        
        Args:
            port: Port number (if None, will read from file or use default)
            port_filename: Filename to read port from (if None, uses default)
        """
        # Determine port
        if port is None:
            port = constants.DEFAULT_PORT
            # Try to read port from file
            if port_filename is None:
                port_filename = constants.PORT_FILENAME
            try:
                with open(port_filename, "r") as f:
                    port_str = f.read().strip()
                    if port_str:
                        port = int(port_str)
            except Exception as e:
                print(f"Using default port {port} ({e})")
        
        self.port = port

        # Create listening socket
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('0.0.0.0', port))  # Bind to all interfaces
        self.sock.listen(100)
        self.sock.setblocking(False)  # Non-blocking socket
        self.sel.register(
            self.sock, selectors.EVENT_READ, data={
                "callback": self._accept_connection})  # Accept new connections
        print(f"Server (v{constants.SERVER_VERSION}) listening on 0.0.0.0: {port}")

    def run(self):
        """
        Run the main event loop.
        
        Blocks until KeyboardInterrupt or error.
        """
        # Main event loop
        try:
            while True:
                events = self.sel.select()

                # Handle events
                for key, mask in events:
                    key.data["callback"](key.fileobj, mask)
        except KeyboardInterrupt:
            print("Server shutting down.")

        # Graceful shutdown
        finally:
            self.shutdown()

    def shutdown(self):
        """Gracefully shutdown the server and close all connections."""
        if self.sel:
            self.sel.close()
        if self.sock:
            self.sock.close()

