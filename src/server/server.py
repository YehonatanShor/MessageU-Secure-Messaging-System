import selectors
import socket
import struct  # For packing/unpacking binary data
import uuid    # For generating unique client IDs

DEFAULT_PORT = 1357
PORT_FILENAME = "myport.info"

# client request code from server 
CLIENT_VERSION = 1;
REQUEST_CODE_REGISTER = 600;
REQUEST_CODE_CLIENTS_LIST = 601;
REQUEST_CODE_PUBLIC_KEY = 602;
REQUEST_CODE_SEND_TEXT_MESSAGE = 603;
REQUEST_CODE_WAITING_MESSAGES = 604;

# size in bytes
CLIENT_UUID_SIZE = 16;
CLIENT_VERSION_SIZE = 1;
REQUEST_CODE_SIZE = 2;
REQUEST_PAYLOAD_SIZE = 4;
USERNAME_FIXED_SIZE = 255;
PUBLIC_KEY_FIXED_SIZE = 160;
REGISTRATION_PAYLOAD_SIZE = USERNAME_FIXED_SIZE + PUBLIC_KEY_FIXED_SIZE
REQUEST_HEADER_SIZE = 16 + 1 + 2 + 4; # ClientID(16) + Version(1) + Code(2) + PayloadSize(4)

# server response code to client
SERVER_VERSION = 1;
RESPONSE_CODE_REGISTER_SUCCESS = 1600
RESPONSE_CODE_REGISTER_SUCCESS = 2100;
RESPONSE_CODE_DISPLAYING_CLIENTS_LIST = 2101;
RESPONSE_CODE_SEND_PUBLIC_KEY = 2102;
RESPONSE_CODE_SEND_TEXT_MESSAGE = 2103;
RESPONSE_CODE_PULL_WAITING_MESSAGE = 2104;
RESPONSE_CODE_GENERAL_ERROR = 9000;

# size in bytes
SERVER_VERSION_SIZE = 1;
RESPONSE_CODE_SIZE = 2;
RESPONSE_PAYLOAD_SIZE = 4;
RESPONSE_HEADER_SIZE = 1 + 2 + 4; # Version(1) + Code(2) + PayloadSize(4)


# --- In-Memory RAM Storage (as requested) ---
clients_db = {} # This DB holds client info, keyed by UUID (as hex string)
clients_by_name = {} # This DB is for fast name lookup
message_queues = {} # This DB will hold messages for offline users

sel = selectors.DefaultSelector() # Selector Setup

class ConnectionState:
    """
    A helper class to store the state for each client connection.
    This allows our 'read' function to be a simple state machine.
    """
    def __init__(self):
        self.reset_for_new_request()

    def reset_for_new_request(self):
        self.state = "HEADER"
        self.buffer = b""
        self.expected_len = REQUEST_HEADER_SIZE
        self.request_code = 0

    def set_payload_state(self, code, payload_size):
        self.state = "PAYLOAD"
        self.request_code = code
        self.expected_len = payload_size

# --- Response Functions ---
def send_error_response(conn, error_message):
    """Sends a generic error message to the client."""
    print(f"Sending error to {conn.getpeername()}: {error_message}")
    payload = error_message.encode('utf-8')
    header = struct.pack('!BHI', CLIENT_VERSION, RESPONSE_CODE_GENERAL_ERROR, len(payload))
    try:
        conn.sendall(header + payload)
    except Exception as e:
        print(f"Error sending error response: {e}")

def send_registration_success(conn, client_uuid):
    """Sends a successful registration response with the new UUID (16 raw bytes)."""
    print(f"Sending success to {conn.getpeername()}, UUID: {client_uuid.hex}")
    payload = client_uuid.bytes # Send the 16-byte raw UUID
    if len(payload) != CLIENT_UUID_SIZE:
        # This should never happen, but good to check
        raise ValueError("Generated UUID is not 16 bytes")
        
    header = struct.pack('!BHI', CLIENT_VERSION, RESPONSE_CODE_REGISTER_SUCCESS, len(payload))
    try:
        conn.sendall(header + payload)
    except Exception as e:
        print(f"Error sending success response: {e}")

# --- Request Handlers ---
def handle_registration(conn, payload):
    """Handles a registration request (Code 600)."""
    try:
        # 1. Check payload size
        if len(payload) != REGISTRATION_PAYLOAD_SIZE:
            send_error_response(conn, f"Invalid payload size. Expected {REGISTRATION_PAYLOAD_SIZE}.")
            return

        # 2. Unpack the fixed-size payload
        username_bytes = payload[0:USERNAME_FIXED_SIZE]
        public_key = payload[USERNAME_FIXED_SIZE:]

        # 3. Decode username, stripping null bytes from padding
        username = username_bytes.decode('utf-8').rstrip('\0')
        if not username:
             send_error_response(conn, "Username cannot be empty.")
             return

        # 4. Check if name exists in our RAM database
        if username in clients_by_name:
            send_error_response(conn, "Username already exists.")
            return

        # 5. Create new user
        new_uuid = uuid.uuid4()
        
        # 6. Store in RAM databases
        clients_by_name[username] = new_uuid.hex
        clients_db[new_uuid.hex] = {
            "name": username,
            "public_key": public_key
        }
        
        print(f"Registered new user '{username}' with UUID {new_uuid.hex}")
        
        # 7. Send success response back to client
        send_registration_success(conn, new_uuid)

    except Exception as e:
        print(f"Error processing registration: {e}")
        send_error_response(conn, "Invalid registration payload.")


def handle_request(conn, state):
    """
    Dispatches a complete request (Header + Payload) to the correct handler.
    """
    # Extract the payload
    payload = state.buffer[:state.expected_len]
    
    # --- Dispatch based on request code ---
    if state.request_code == REQUEST_CODE_REGISTER:
        print(f"Received registration request from {conn.getpeername()}")
        handle_registration(conn, payload)
    
    # --- Other request codes will go here ---
    # elif state.request_code == REQUEST_CODE_CLIENT_LIST:
    #     handle_client_list(conn, payload)
        
    else:
        print(f"Received unknown request code {state.request_code}")
        send_error_response(conn, f"Unknown request code: {state.request_code}")

    # Remove the processed request from the buffer and reset state
    state.buffer = state.buffer[state.expected_len:]
    state.reset_for_new_request()


# --- Main I/O Callbacks ---
def read(conn, mask):
    """
    Callback called by the selector when a socket is ready for reading.
    This is our state machine.
    """
    state = sel.get_key(conn).data["state"] # Get the state for this client

    try:
        data = conn.recv(1024)
    except ConnectionError:
        print(f'closing {conn.getpeername()} (ConnectionError)')
        sel.unregister(conn)
        conn.close()
        return

    if not data:
        print(f'closing {conn.getpeername()} (client closed)')
        sel.unregister(conn)
        conn.close()
        return

    state.buffer += data

    # Loop to process all complete messages in the buffer
    while True:
        if state.state == "HEADER":
            # 1. בדוק אם יש לנו מספיק נתונים לכל הכותרת (23 בתים)
            if len(state.buffer) >= REQUEST_HEADER_SIZE:
                
                # 2. חתוך את כל 23 הבתים מהחוצץ
                full_header_data = state.buffer[:REQUEST_HEADER_SIZE]
                
                # 3. חתוך *רק* את 7 הבתים שאנו רוצים לפענח,
                #    תוך התעלמות מ-16 הבתים הראשונים.
                header_to_parse = full_header_data[CLIENT_UUID_SIZE:] # לוקח מבת 16 עד הסוף
                
                # 4. עכשיו header_to_parse הוא בגודל 7, ו-unpack יעבוד
                version, code, payload_size = struct.unpack('!BHI', header_to_parse)
                
                print(f"Received header from {conn.getpeername()}: version={version}, code={code}, payload_size={payload_size}")
                
                if version != CLIENT_VERSION:
                    print(f"Closing {conn.getpeername()}, invalid client version: {version}")
                    sel.unregister(conn)
                    conn.close()
                    return

                # 5. הגדר את המצב הבא (Payload)
                state.set_payload_state(code, payload_size)
                
                # 6. תקן את הבאג השני: הסר את *כל* 23 הבתים מהחוצץ
                state.buffer = state.buffer[REQUEST_HEADER_SIZE:]
            else:
                break # Not enough data for a header, wait for more

        if state.state == "PAYLOAD":
            if len(state.buffer) >= state.expected_len:
                # We have a full request (Payload)
                handle_request(conn, state)
                # handle_request will reset the state, so we loop again
                # to check if there's another full request in the buffer
            else:
                break # Not enough data for the payload, wait for more
        
        if not state.buffer:
            break # No more data in buffer

def accept(sock, mask):
    """
    Callback called by the selector when the listening socket is ready.
    """
    conn, addr = sock.accept()
    print('accepted connection from', addr)
    conn.setblocking(False)
    
    client_data = {
        "callback": read,
        "state": ConnectionState()
    }
    sel.register(conn, selectors.EVENT_READ, data=client_data)

# --- Main Server Entry Point ---
def main():
    # Load port from myport.info (as requested in previous turn)
    port = DEFAULT_PORT # Default
    try:
        with open(PORT_FILENAME, "r") as f:
            port = int(f.read().strip())
    except (FileNotFoundError, ValueError):
        print("myport.info not found or invalid. Using default port 1357.")
        port = DEFAULT_PORT

    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('localhost', port))
    sock.listen(100)
    sock.setblocking(False)

    sel.register(sock, selectors.EVENT_READ, data={"callback": accept})
    print(f"Server listening on localhost:{port}")

    try:
        while True:
            events = sel.select()
            for key, mask in events:
                callback = key.data["callback"]
                callback(key.fileobj, mask)
    except KeyboardInterrupt:
        print("\nServer shutting down.")
    finally:
        sel.close()
        sock.close()

if __name__ == "__main__":
    main()