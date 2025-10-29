import selectors
import socket
import struct  # Used for packing/unpacking the 4-byte header - conversion between Big Indian and Little Indian

DEFAULT_PORT = 1357
PORT_FILENAME = "myport.info"

# Create a default selector (picks the best one for the OS)
sel = selectors.DefaultSelector()

# A helper class to store the state for each client connection.
class ConnectionState:
    def __init__(self):
        self.reset()
    def reset(self):
        self.state = "HEADER"  # Initial state: expecting a 4-byte header
        self.buffer = b""      # Buffer to accumulate incoming data
        self.msg_len = 0       # The expected length of the message body

# Callback function called by the selector to handle reading from a client socket
def read(conn, mask):

    state_data = sel.get_key(conn).data["state"] # Get the state for this specific client

    try:
        data = conn.recv(1024) # Read whatever data is available (up to 1024 bytes)
    except ConnectionError:
        print('closing', conn, '(ConnectionError)')
        sel.unregister(conn)
        conn.close()
        return

    if not data:
        # If recv returns empty bytes, the client has closed the connection
        print('closing', conn, '(client closed)')
        sel.unregister(conn)
        conn.close()
        return

    state_data.buffer += data # Append received data to the buffer

    # loop in case multiple messages (Header+Body) were received in a single 'recv' call.
    while True:
        # state 1: If we are waiting for a header
        if state_data.state == "HEADER": 
            if len(state_data.buffer) >= 4: # Check if we have at least 4 bytes (the header size)
                state_data.msg_len = struct.unpack('!I', state_data.buffer[:4])[0] # Unpack the header    
                state_data.buffer = state_data.buffer[4:] # Remove the header from the buffer, keep the rest
                state_data.state = "BODY" # Change state to wait for the message body
            else:
                # Not enough data for a header, wait for more
                break

        # state 2: If we are waiting for the body
        if state_data.state == "BODY":
            if len(state_data.buffer) >= state_data.msg_len: # Check if we have accumulated the full message length
                message_body = state_data.buffer[:state_data.msg_len] # Extract the complete message
                state_data.buffer = state_data.buffer[state_data.msg_len:] # Remove the message, keep any extra data for the next message
                
                print('echoing', repr(message_body), 'to', conn) # Log the message being echoed and processed
                
                # Echo it back using the same protocol (Header + Body)
                header = struct.pack('!I', len(message_body))
                conn.sendall(header + message_body)
                
                state_data.reset() # Reset state to wait for the next header (new message)
            else:
                # Not enough data for a full body, wait for more
                break

# Callback function called by the selector when a new client connects
def accept(sock, mask):
    conn, addr = sock.accept()  # Should be ready
    print('accepted', conn, 'from', addr)
    conn.setblocking(False)  # Set the new client socket to non-blocking
    
    # Create the data object to store for this client
    client_data = {
        "callback": read,
        "state": ConnectionState() # Create a new state object for this client
    }
    # Register the new client socket with the selector
    sel.register(conn, selectors.EVENT_READ, data=client_data)

# Tries to read the port from PORT_FILENAME
def get_port():
    try:
        with open(PORT_FILENAME, 'r') as f:
            port_str = f.read().strip()
            port = int(port_str)
            print(f"Read port {port} from {PORT_FILENAME}")
            return port
    except FileNotFoundError:
        print(f"WARNING: '{PORT_FILENAME}' not found. Using default port {DEFAULT_PORT}.")
        return DEFAULT_PORT
    except ValueError:
        print(f"WARNING: '{PORT_FILENAME}' contains invalid data. Using default port {DEFAULT_PORT}.")
        return DEFAULT_PORT

def main():
    port = get_port() # Get port from file or use default - 1357 port

    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Allow the socket to reuse the address (prevents "Address already in use")
    sock.bind(('localhost', port)) # Use the 'port' variable instead of a hardcoded number
    sock.listen(100)
    sock.setblocking(False) # Set the main listening socket to non-blocking

    # Register the listening socket and call 'accept' when a new client connects
    sel.register(sock, selectors.EVENT_READ, data={"callback": accept})
    
    print(f"Server is listening on localhost: {port}")

    # This is the main event loop
    try:
        while True:
            events = sel.select()  # Wait for an event (blocking)
            for key, mask in events: 
                callback = key.data["callback"] # For each event, get the callback function we stored
                callback(key.fileobj, mask) # Call the appropriate callback function
    except KeyboardInterrupt:
        print("\nServer shutting down.")
    finally:
        sel.close()
        sock.close()

# the entry point of the script
if __name__ == "__main__":
    main() # Calls the function only if we ran the file directly