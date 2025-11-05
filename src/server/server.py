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

# Message Types (for payload of code 603)
MSG_TYPE_SYM_KEY_REQUEST = 1
MSG_TYPE_SYM_KEY_SEND = 2
MSG_TYPE_TEXT_MESSAGE = 3

# size in bytes
CLIENT_UUID_SIZE = 16;
CLIENT_VERSION_SIZE = 1;
REQUEST_CODE_SIZE = 2;
REQUEST_PAYLOAD_SIZE = 4;
REQUEST_HEADER_SIZE = 16 + 1 + 2 + 4; # ClientID(16) + Version(1) + Code(2) + PayloadSize(4)
USERNAME_FIXED_SIZE = 255;
PUBLIC_KEY_FIXED_SIZE = 160;
REGISTRATION_PAYLOAD_SIZE = USERNAME_FIXED_SIZE + PUBLIC_KEY_FIXED_SIZE

# server response code to client
SERVER_VERSION = 1;
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

# Global counter for unique message IDs
g_message_id_counter = 0

# DB for storing clients data in RAM
clients_db = {} # This DB holds client info, keyed by UUID (as hex string)
clients_by_name = {} # This DB is for fast name lookup
message_queues = {} # This DB will hold messages for offline users

sel = selectors.DefaultSelector() # Selector Setup

# A helper class to store the state for each client connection.
class ConnectionState:
    def __init__(self):
        self.reset_for_new_request()

    def reset_for_new_request(self):
        self.state = "HEADER" 
        self.buffer = b"" # Buffer to hold incoming data
        self.expected_len = REQUEST_HEADER_SIZE # Expecting the full 23-byte header
        self.client_id = b"" # Will hold the Client's UUID (16 bytes)
        self.request_code = 0

    def set_payload_state(self, client_id, code, payload_size):
        self.state = "PAYLOAD"
        self.client_id = client_id # Store the Clients UUID
        self.request_code = code
        self.expected_len = payload_size

# --- Response Functions ---

# Generic response sender to send any response to the client
def send_response(conn, response_code, payload):
    try:
        header = struct.pack('!BHI', CLIENT_VERSION, response_code, len(payload))
        conn.sendall(header + payload)
    except Exception as e:
        print(f"Error sending response code {response_code}: {e}")

# Sends a generic error message to the client
def send_error_response(conn, error_message):
    print(f"Sending error to {conn.getpeername()}: {error_message}")
    payload = error_message.encode('utf-8')
    header = struct.pack('!BHI', CLIENT_VERSION, RESPONSE_CODE_GENERAL_ERROR, len(payload))
    try:
        conn.sendall(header + payload)
    except Exception as e:
        print(f"Error sending error response: {e}")

# Sends a successful registration response with the new UUID (16 bytes)
def send_registration_success(conn, client_uuid):
    print(f"Sending success to {conn.getpeername()}, UUID: {client_uuid.hex}")
    payload = client_uuid.bytes # Send the 16-byte UUID
    if len(payload) != CLIENT_UUID_SIZE: # This should never happen, but good to check
        raise ValueError("Generated UUID is not 16 bytes")
        
    header = struct.pack('!BHI', CLIENT_VERSION, RESPONSE_CODE_REGISTER_SUCCESS, len(payload))
    try:
        conn.sendall(header + payload)
    except Exception as e:
        print(f"Error sending success response: {e}")

# --- Request Handlers ---

# Handles a registration request (Code 600)
def handle_registration(conn, payload):
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
        
        # 7. Send success response back to client
        send_registration_success(conn, new_uuid)

    # 8. Handle any unexpected errors
    except Exception as e:
        print(f"Error processing registration: {e}")
        send_error_response(conn, "Invalid registration payload.")

# Handles a request for the client list (Code 601)
def handle_client_list(conn, client_id_bytes):
    # 1. Verify the client is registered
    client_id_hex = client_id_bytes.hex()
    if client_id_hex not in clients_db:
        send_error_response(conn, "You are not registered.")
        return

    # 2. Build the payload
    payload_chunks = []
    requester_name = clients_db[client_id_hex]['name']
    print(f"Sending client list to '{requester_name}'...")

    # 3. For each client in the DB, add their UUID and name to the payload
    for uuid_hex, info in clients_db.items():
        # Don't send the user their own name
        if uuid_hex == client_id_hex:
            continue
            
        # Add the client's UUID (16 bytes)
        payload_chunks.append(uuid.UUID(uuid_hex).bytes)
        
        # Add the client's name (padded to 255 bytes)
        name_bytes = info['name'].encode('utf-8')
        padded_name = name_bytes.ljust(USERNAME_FIXED_SIZE, b'\0')
        payload_chunks.append(padded_name)

    # 4. Join all chunks into one big payload
    full_payload = b"".join(payload_chunks)
    
    # 5. Send the response
    send_response(conn, RESPONSE_CODE_DISPLAYING_CLIENTS_LIST, full_payload)

# Handles a request for another client's public key (Code 602)
def handle_public_key_request(conn, client_id_bytes, payload):
    
    # 1. Authenticate the *requester*
    requester_id_hex = client_id_bytes.hex()
    if requester_id_hex not in clients_db: # if user is not registered
        send_error_response(conn, "Authentication failed. You are not registered.")
        return

    # 2. Validate the payload (should be a 16-byte UUID)
    if len(payload) != CLIENT_UUID_SIZE:
        send_error_response(conn, f"Invalid payload size. Expected {CLIENT_UUID_SIZE} bytes.")
        return
        
    # 3. Find the *target* client in the database
    target_id_hex = payload.hex()
    if target_id_hex not in clients_db: # if target client does not exist
        send_error_response(conn, "The requested client UUID does not exist.")
        return
        
    # 4. Get the target's info
    target_info = clients_db[target_id_hex]
    target_public_key = target_info["public_key"] # This is 160 bytes
    
    # 5. Build the response payload (Target's UUID + Target's Public Key)
    response_payload = payload + target_public_key # 16 + 160 = 176 bytes
    
    print(f"Sending public key for '{target_info['name']}' to '{clients_db[requester_id_hex]['name']}'")
    
    # 6. Send the response
    send_response(conn, RESPONSE_CODE_SEND_PUBLIC_KEY, response_payload)

# Generates a new unique message ID
def get_new_message_id():
    global g_message_id_counter
    g_message_id_counter += 1
    return g_message_id_counter

# Handles a request to send a message (Code 603)
def handle_send_message(conn, client_id_bytes, payload):
    
    # 1. Authenticate the *sender*
    sender_id_hex = client_id_bytes.hex()
    if sender_id_hex not in clients_db:
        send_error_response(conn, "Authentication failed. You are not registered.")
        return

    # 2. Parse the inner payload header
    try:
        target_id_bytes = payload[0:CLIENT_UUID_SIZE]
        msg_type = payload[CLIENT_UUID_SIZE : CLIENT_UUID_SIZE + 1][0] # Get the 1 byte
        content_size_bytes = payload[CLIENT_UUID_SIZE + 1 : CLIENT_UUID_SIZE + 1 + 4]
        content_size = struct.unpack('!I', content_size_bytes)[0]
        
        # 3. Extract the message content
        content = payload[CLIENT_UUID_SIZE + 1 + 4:]
        
        # 4. Validate content size
        if len(content) != content_size:
            send_error_response(conn, "Message content size mismatch.")
            return

    except Exception as e:
        print(f"Error parsing send_message payload: {e}")
        send_error_response(conn, "Invalid message payload structure.")
        return

    # 5. Find the target client
    target_id_hex = target_id_bytes.hex()
    if target_id_hex not in clients_db:
        send_error_response(conn, "Target client UUID does not exist.")
        return
        
    # --- At this point, sender and target are valid ---
    
    # 6. Generate a new message ID
    new_msg_id = get_new_message_id()

    # 7. Store the message in the target's queue
    # The server stores the *full encrypted payload*
    # It cannot read the content (End-to-End Encryption)
    message_to_store = {
        "id": new_msg_id,
        "from_uuid": sender_id_hex,
        "type": msg_type,
        "content": content
    }
    
    # Initialize queue if it doesn't exist
    if target_id_hex not in message_queues:
        message_queues[target_id_hex] = []
    
    # Add message to the target's queue
    message_queues[target_id_hex].append(message_to_store)
    
    print(f"Stored message (ID: {new_msg_id}, Type: {msg_type}) from {sender_id_hex} for {target_id_hex}")

    # 8. Send confirmation (Code 2103) back to the *sender*
    # Payload: Target's UUID (16) + Message ID (4)
    response_payload = target_id_bytes + struct.pack('!I', new_msg_id)
    send_response(conn, RESPONSE_CODE_SEND_TEXT_MESSAGE, response_payload)

# Handles a request to pull waiting messages (Code 604)
def handle_pull_messages(conn, client_id_bytes):
    
    # 1. Authenticate the *requester*
    requester_id_hex = client_id_bytes.hex()
    if requester_id_hex not in clients_db:
        send_error_response(conn, "Authentication failed. You are not registered.")
        return

    # 2. Find the user's message queue
    if requester_id_hex not in message_queues or not message_queues[requester_id_hex]:
        # No messages are waiting
        print(f"No messages for '{clients_db[requester_id_hex]['name']}'. Sending empty response.")
        send_response(conn, RESPONSE_CODE_PULL_WAITING_MESSAGE, b"") # Send 0-length payload
        return

    # 3. Build the payload
    payload_chunks = []
    
    # Get the list of messages and *clear the queue* (atomic operation)
    messages_to_send = message_queues.pop(requester_id_hex)
    
    print(f"Sending {len(messages_to_send)} messages to '{clients_db[requester_id_hex]['name']}'...")

    # 4. For each message, pack it according to the protocol
    for msg in messages_to_send:
        # Payload: From_UUID (16) + MsgID (4) + Type (1) + Size (4) + Content (N)
        
        # From_UUID (16)
        payload_chunks.append(uuid.UUID(msg["from_uuid"]).bytes)
        # MsgID (4)
        payload_chunks.append(struct.pack('!I', msg["id"]))
        # Type (1)
        payload_chunks.append(struct.pack('!B', msg["type"]))
        # Content Size (4)
        payload_chunks.append(struct.pack('!I', len(msg["content"])))
        # Content (N)
        payload_chunks.append(msg["content"])

    # 5. Join all chunks into one big payload
    full_payload = b"".join(payload_chunks)
    
    # 6. Send the response
    send_response(conn, RESPONSE_CODE_PULL_WAITING_MESSAGE, full_payload)

# Dispatches a complete request (Header + Payload) to the correct handler.
def handle_request(conn, state):

    payload = state.buffer[:state.expected_len] # Extract the payload
    
    # --- Dispatch based on request code ---

    # Registration request (600)
    if state.request_code == REQUEST_CODE_REGISTER:
        print(f"Received registration request from {conn.getpeername()}")
        handle_registration(conn, payload)

    # Clients list request (601)
    elif state.request_code == REQUEST_CODE_CLIENTS_LIST:
        # All other requests must come from a registered client
        handle_client_list(conn, state.client_id)

    # Public key request (602)
    elif state.request_code == REQUEST_CODE_PUBLIC_KEY:
        handle_public_key_request(conn, state.client_id, payload)

    # Send message request (603)
    elif state.request_code == REQUEST_CODE_SEND_TEXT_MESSAGE:
        handle_send_message(conn, state.client_id, payload)

    elif state.request_code == REQUEST_CODE_WAITING_MESSAGES:
        handle_pull_messages(conn, state.client_id)

    # Unknown request code    
    else:
        print(f"Received unknown request code {state.request_code}")
        send_error_response(conn, f"Unknown request code: {state.request_code}")

    # Remove the processed request from the buffer and reset state
    state.buffer = state.buffer[state.expected_len:]
    state.reset_for_new_request()

# Callback called by the selector when a socket is ready for reading.
def read(conn, mask):

    state = sel.get_key(conn).data["state"] 

    try:
        data = conn.recv(1024)
    except ConnectionError: # Client disconnected abruptly
        print(f'closing {conn.getpeername()} (ConnectionError)')
        sel.unregister(conn)
        conn.close()
        return

    if not data: # No data means the client closed the connection
        print(f'closing {conn.getpeername()} (client closed)')
        sel.unregister(conn)
        conn.close()
        return

    state.buffer += data # Append new data to the buffer

    # Keep the server running and process as many complete requests as possible
    while True: 
        if state.state == "HEADER":
            if len(state.buffer) >= REQUEST_HEADER_SIZE:
                # 1. We have a full 23-byte header
                full_header_data = state.buffer[:REQUEST_HEADER_SIZE]
                
                # 2. Extract the ClientID (first 16 bytes)
                client_id_from_header = full_header_data[:CLIENT_UUID_SIZE]
                
                # 3. Extract the part to parse (last 7 bytes)
                header_to_parse = full_header_data[CLIENT_UUID_SIZE:]
                
                # 4. Unpack the standard header
                version, code, payload_size = struct.unpack('!BHI', header_to_parse)
                
                # 4a. Validate client version
                if version != CLIENT_VERSION:
                    print(f"Closing {conn.getpeername()}, invalid client version: {version}")
                    sel.unregister(conn)
                    conn.close()
                    return

                # 5. Set state for payload
                state.set_payload_state(client_id_from_header, code, payload_size)
                
                # 6. Remove the *full* 23-byte header from the buffer
                state.buffer = state.buffer[REQUEST_HEADER_SIZE:]
            else:
                break # Not enough data for a header, wait for more

        if state.state == "PAYLOAD":
            if len(state.buffer) >= state.expected_len:
                # We have a full request (Payload)
                handle_request(conn, state)
            else:
                break # Not enough data for the payload, wait for more
        
        if not state.buffer:
            break # No more data in buffer

# Callback called by the selector when the listening socket is ready to connect whith a new client
def accept(sock, mask):

    conn, addr = sock.accept()
    print('accepted connection from', addr)
    conn.setblocking(False)
    
    # Register the new connection for reading
    client_data = {
        "callback": read,
        "state": ConnectionState()
    }
    sel.register(conn, selectors.EVENT_READ, data=client_data)

# Main Server Entry Point
def main():
    # Load port from myport.info (as requested in previous turn)
    port = DEFAULT_PORT # Default
    try:
        with open(PORT_FILENAME, "r") as f:
            port = int(f.read().strip())
    except (FileNotFoundError, ValueError): # File not found or invalid content
        print("myport.info not found or invalid. Using default port 1357.")
        port = DEFAULT_PORT

    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('localhost', port))
    sock.listen(100)
    sock.setblocking(False) # Non-blocking socket

    # Register the listening socket to accept new connections
    sel.register(sock, selectors.EVENT_READ, data={"callback": accept})
    print(f"Server listening on localhost:{port}")

    # Event loop
    try:
        while True:
            events = sel.select() # Blocking call, waits for events\
            # Process all events
            for key, mask in events: # key stands for a registered socket, mask for the event type
                callback = key.data["callback"] # Get the callback function
                callback(key.fileobj, mask) # Call appropriate callback function with the socket and mask
    except KeyboardInterrupt: # Graceful shutdown on Ctrl+C
        print("\nServer shutting down.")
    finally:
        sel.close()
        sock.close()

# the entry point of the script
if __name__ == "__main__":
    main() # Calls the function only if we ran the file directly