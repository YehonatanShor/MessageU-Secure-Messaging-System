# command in terminal: cd C:\Users\User\Documents\Yehonatan\open-university\defensive-programing\MessageU1\src\server

import selectors
import socket
import struct  # For packing/unpacking binary data
import uuid    # For generating unique client IDs
import sqlite3 # For database operations
import os # For file operations
from datetime import datetime # For timestamping messages

DEFAULT_PORT = 1357 # Default port if port file is missing or invalid
PORT_FILENAME = "myport.info"
DB_FILENAME = "defensive.db"

# client request code from server 
CLIENT_VERSION = 2;
REQUEST_CODE_REGISTER = 600;
REQUEST_CODE_CLIENTS_LIST = 601;
REQUEST_CODE_PUBLIC_KEY = 602;
REQUEST_CODE_SEND_TEXT_MESSAGE = 603;
REQUEST_CODE_WAITING_MESSAGES = 604;

# Message Types (for payload of code 603)
MSG_TYPE_SYM_KEY_REQUEST = 1
MSG_TYPE_SYM_KEY_SEND = 2
MSG_TYPE_TEXT_MESSAGE = 3
MSG_TYPE_FILE = 4

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
SERVER_VERSION = 2;
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

# --- Database Manager---
class DatabaseManager:
    # Initializes the database connection and creates tables if they don't exist.
    def __init__(self, db_file):
        self.db_file = db_file
        try:
            self._initialize_db()
        except sqlite3.Error as e:
            print(f"FATAL DB ERROR: Could not initialize database: {e}")
            raise # Re-raise exception to stop the server if DB can't be created

    # Internal method to get a new DB connection
    def _get_connection(self):
        # The connection itself can fail (e.g., permissions)
        return sqlite3.connect(self.db_file, timeout=5) # Timeout to avoid locking issues

    # Internal method to create the database tables if they don't exist
    def _initialize_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS clients (
                    ID BLOB PRIMARY KEY,
                    UserName TEXT NOT NULL UNIQUE,
                    PublicKey BLOB NOT NULL,
                    LastSeen TEXT NOT NULL
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS messages (
                    ID INTEGER PRIMARY KEY AUTOINCREMENT,
                    ToClient BLOB NOT NULL,
                    FromClient BLOB NOT NULL,
                    Type INTEGER NOT NULL,
                    Content BLOB NOT NULL,
                    FOREIGN KEY(ToClient) REFERENCES clients(ID),
                    FOREIGN KEY(FromClient) REFERENCES clients(ID)
                )
            ''')
            conn.commit()
        print(f"Database initialized at {self.db_file}")

    # Updates the LastSeen timestamp for a client   
    def update_last_seen(self, client_uuid_bytes):
        try:
            with self._get_connection() as conn:
                conn.execute("UPDATE clients SET LastSeen = ? WHERE ID = ?", 
                             (datetime.now().isoformat(), client_uuid_bytes))
        except sqlite3.Error as e:
            print(f"DB Error (update_last_seen): {e}")

    # Registers a new client. Returns True on success, False if username exists
    def register_client(self, uuid_bytes, username, public_key):
        try:
            with self._get_connection() as conn:
                conn.execute("INSERT INTO clients (ID, UserName, PublicKey, LastSeen) VALUES (?, ?, ?, ?)",
                             (uuid_bytes, username, public_key, datetime.now().isoformat()))
            return True
        except sqlite3.IntegrityError: # Username already exists
            return False  
        except sqlite3.Error as e: # Catch any other DB error (e.g., disk full, locked)
            print(f"DB Error (register_client): {e}")
            return False

    # Checks if a client exists by UUID
    def client_exists(self, uuid_bytes):
        try:
            with self._get_connection() as conn:
                cursor = conn.execute("SELECT 1 FROM clients WHERE ID = ?", (uuid_bytes,))
                return cursor.fetchone() is not None
        except sqlite3.Error as e:
            print(f"DB Error (client_exists): {e}")
            return False # Assume not exists if DB fails

    # Retrieves the username for a given client UUID
    def get_client_name(self, uuid_bytes):
        try:
            with self._get_connection() as conn:
                cursor = conn.execute("SELECT UserName FROM clients WHERE ID = ?", (uuid_bytes,))
                row = cursor.fetchone()
                return row[0] if row else None
        except sqlite3.Error as e:
            print(f"DB Error (get_client_name): {e}")
            return None

    # Retrieves the public key and username for a given client UUID
    def get_public_key(self, uuid_bytes):
        try:
            with self._get_connection() as conn:
                cursor = conn.execute("SELECT PublicKey, UserName FROM clients WHERE ID = ?", (uuid_bytes,))
                return cursor.fetchone()
        except sqlite3.Error as e:
            print(f"DB Error (get_public_key): {e}")
            return None

    # Returns a list of (uuid_bytes, username) for all clients
    def get_all_clients(self):
        try:
            with self._get_connection() as conn:
                cursor = conn.execute("SELECT ID, UserName FROM clients")
                return cursor.fetchall()
        except sqlite3.Error as e:
            print(f"DB Error (get_all_clients): {e}")
            return [] # Return empty list on failure

    # Saves a message to the database and returns the message ID
    def save_message(self, to_client, from_client, msg_type, content):
        try:
            with self._get_connection() as conn:
                cursor = conn.execute("INSERT INTO messages (ToClient, FromClient, Type, Content) VALUES (?, ?, ?, ?)",
                                      (to_client, from_client, msg_type, content))
                return cursor.lastrowid # Return the auto-generated message ID
        except sqlite3.Error as e:
            print(f"DB Error (save_message): {e}")
            raise e # Re-raise to let the handler know it failed

    # Retrieves and deletes all waiting messages for a client
    def get_waiting_messages(self, client_uuid_bytes):
        messages = []
        try:
            with self._get_connection() as conn:
                # 'with conn:' creates an atomic transaction
                with conn:
                    # 1. Get messages
                    cursor = conn.execute("SELECT ID, FromClient, Type, Content FROM messages WHERE ToClient = ?", (client_uuid_bytes,))
                    messages = cursor.fetchall()
                    # 2. Delete pulled messages
                    conn.execute("DELETE FROM messages WHERE ToClient = ?", (client_uuid_bytes,))
            return messages
        except sqlite3.Error as e:
            print(f"DB Error (get_waiting_messages): {e}")
            return [] # Return empty list on failure

# --- Global DB instance ---
db = DatabaseManager(DB_FILENAME)
sel = selectors.DefaultSelector()

# --- Connection State ---
class ConnectionState:
    def __init__(self):
        self.reset_for_new_request()

    def reset_for_new_request(self):
        self.state = "HEADER"
        self.buffer = b""
        self.expected_len = REQUEST_HEADER_SIZE
        self.client_id = b""
        self.request_code = 0

    def set_payload_state(self, client_id, code, payload_size):
        self.state = "PAYLOAD"
        self.client_id = client_id
        self.request_code = code
        self.expected_len = payload_size

# --- Response Functions ---
def send_response(conn, response_code, payload):
    try:
        header = struct.pack('!BHI', SERVER_VERSION, response_code, len(payload))
        conn.sendall(header + payload)
    except Exception as e:
        print(f"Error sending response code {response_code}: {e}")

# --- Error and Success Responses ---
def send_error_response(conn, error_message):
    print(f"Sending error to {conn.getpeername()}: {error_message}")
    payload = error_message.encode('utf-8')
    header = struct.pack('!BHI', SERVER_VERSION, RESPONSE_CODE_GENERAL_ERROR, len(payload))
    try:
        conn.sendall(header + payload)
    except Exception as e:
        print(f"Error sending error response: {e}")

def send_registration_success(conn, client_uuid_bytes):
    print(f"Sending registration success to {conn.getpeername()}, UUID: {client_uuid_bytes.hex()}")
    header = struct.pack('!BHI', SERVER_VERSION, RESPONSE_CODE_REGISTER_SUCCESS, len(client_uuid_bytes))
    try:
        conn.sendall(header + client_uuid_bytes)
    except Exception as e:
        print(f"Error sending success response: {e}")

# --- Request Handlers ---

def handle_registration(conn, payload):
    try:
        # 1. Validate payload size
        if len(payload) != REGISTRATION_PAYLOAD_SIZE:
            send_error_response(conn, "Invalid registration payload size.")
            return

        # 2. Parse username and public key
        username_bytes = payload[0:USERNAME_FIXED_SIZE]
        public_key = payload[USERNAME_FIXED_SIZE:]
        username = username_bytes.decode('utf-8').rstrip('\0')

        # 3. Validate username
        if not username:
             send_error_response(conn, "Username cannot be empty.")
             return

        new_uuid_bytes = uuid.uuid4().bytes
        
        # 4. Try to register in DB
        if db.register_client(new_uuid_bytes, username, public_key):
             print(f"Registered new user '{username}' with UUID {new_uuid_bytes.hex()}")
             send_registration_success(conn, new_uuid_bytes)
        # if already exists, register_client will return False
        else:
             send_error_response(conn, "Username already exists.")

    except Exception as e:
        print(f"Error processing registration: {e}")
        send_error_response(conn, "Registration failed.")

# Handles sending a list of all clients to the requester except themselves
def handle_client_list(conn, client_id_bytes):
    # 1. Authenticate requester
    if not db.client_exists(client_id_bytes):
        send_error_response(conn, "Authentication failed. You are not registered.")
        return
    
    # 2. Update last seen
    db.update_last_seen(client_id_bytes)
    requester_name = db.get_client_name(client_id_bytes)
    print(f"Sending client list to '{requester_name}'...")

    # 3. Build payload - list of (UUID + Username)
    all_clients = db.get_all_clients()
    payload_chunks = []
    for uuid_bytes, username in all_clients:
        if uuid_bytes == client_id_bytes: continue # Don't send own name
        
        payload_chunks.append(uuid_bytes) # 16 bytes
        name_bytes = username.encode('utf-8').ljust(USERNAME_FIXED_SIZE, b'\0')
        payload_chunks.append(name_bytes) # 255 bytes

    # 4. Send users list to client
    send_response(conn, RESPONSE_CODE_DISPLAYING_CLIENTS_LIST, b"".join(payload_chunks))

# Handles sending a public key of the requested client to the requester
def handle_public_key_request(conn, client_id_bytes, payload):
    # 1. Authenticate requester
    if not db.client_exists(client_id_bytes):
        send_error_response(conn, "Authentication failed.")
        return
    
    # 2. Update last seen
    db.update_last_seen(client_id_bytes)

    # 3. Parse target UUID
    if len(payload) != CLIENT_UUID_SIZE:
        send_error_response(conn, "Invalid target UUID size.")
        return
        
    target_uuid_bytes = payload
    result = db.get_public_key(target_uuid_bytes) 
    
    # 4. Send public key or error
    if result:
        target_pub_key, target_name = result
        requester_name = db.get_client_name(client_id_bytes)
        print(f"Sending public key of '{target_name}' to '{requester_name}'...")
        # send TargetUUID (16) + PublicKey (160) to client
        send_response(conn, RESPONSE_CODE_SEND_PUBLIC_KEY, target_uuid_bytes + target_pub_key)
    else:
        send_error_response(conn, "Client not found.")

# Handles sending text message to another client
def handle_send_message(conn, client_id_bytes, payload):
    # 1. Authenticate sender
    if not db.client_exists(client_id_bytes):
        send_error_response(conn, "Authentication failed.")
        return
    
    # 2. Update last seen
    db.update_last_seen(client_id_bytes)

    # 3. Parse message
    try:
        target_id_bytes = payload[:CLIENT_UUID_SIZE]
        msg_type = payload[CLIENT_UUID_SIZE]
        content_size = struct.unpack('!I', payload[CLIENT_UUID_SIZE+1 : CLIENT_UUID_SIZE+5])[0]
        content = payload[CLIENT_UUID_SIZE+5:]

        # 3a. Validate message
        if len(content) != content_size:
             send_error_response(conn, "Message size mismatch.")
             return
        
        # 3b. Validate target client exists
        if not db.client_exists(target_id_bytes):
             send_error_response(conn, "Target client does not exist.")
             return

        # 4. Save message on DB and get MsgID
        msg_id = db.save_message(target_id_bytes, client_id_bytes, msg_type, content)
        print(f"Message {msg_id} saved for {target_id_bytes.hex()} from {client_id_bytes.hex()}")

        # 5. Send to client confirmation: TargetUUID (16) + MsgID (4)
        response_payload = target_id_bytes + struct.pack('!I', msg_id)
        send_response(conn, RESPONSE_CODE_SEND_TEXT_MESSAGE, response_payload)

    except Exception as e:
        print(f"Error handling send_message: {e}")
        send_error_response(conn, "Invalid message format.")

# Handles pulling waiting messages for a client
def handle_pull_messages(conn, client_id_bytes):
    # 1. Authenticate requester
    if not db.client_exists(client_id_bytes):
        send_error_response(conn, "Authentication failed.")
        return
    
    # 2. Update last seen and get messages
    db.update_last_seen(client_id_bytes)
    messages = db.get_waiting_messages(client_id_bytes) # List of (ID, FromClient, Type, Content)
    
    # 2a. If no messages, send empty response
    if not messages:
        send_response(conn, RESPONSE_CODE_PULL_WAITING_MESSAGE, b"")
        return
    
    # 3. Build payload and send
    print(f"Sending {len(messages)} messages to {client_id_bytes.hex()}")
    payload_chunks = []
    for msg_id, from_uuid, msg_type, content in messages:
        payload_chunks.append(from_uuid)                       # 16 bytes
        payload_chunks.append(struct.pack('!I', msg_id))       # 4 bytes
        payload_chunks.append(struct.pack('!B', msg_type))     # 1 byte
        payload_chunks.append(struct.pack('!I', len(content))) # 4 bytes
        payload_chunks.append(content)                         # N bytes

    send_response(conn, RESPONSE_CODE_PULL_WAITING_MESSAGE, b"".join(payload_chunks))

# --- Main Handler Dispatcher ---
def handle_request(conn, state):
    payload = state.buffer[:state.expected_len] # Extract payload
    
    # Dispatch based on request code
    if state.request_code == REQUEST_CODE_REGISTER:
        handle_registration(conn, payload)
    elif state.request_code == REQUEST_CODE_CLIENTS_LIST:
        handle_client_list(conn, state.client_id)
    elif state.request_code == REQUEST_CODE_PUBLIC_KEY:
        handle_public_key_request(conn, state.client_id, payload)
    elif state.request_code == REQUEST_CODE_SEND_TEXT_MESSAGE:
        handle_send_message(conn, state.client_id, payload)
    elif state.request_code == REQUEST_CODE_WAITING_MESSAGES:
        handle_pull_messages(conn, state.client_id)
    else:
        print(f"Unknown request code: {state.request_code}")
        send_error_response(conn, f"Unknown request code: {state.request_code}")

    # Remove processed data from buffer and reset state
    state.buffer = state.buffer[state.expected_len:]
    state.reset_for_new_request()

# --- I/O Loop ---
def read(conn, mask):
    state = sel.get_key(conn).data["state"] # Get connection state
    # 1. Read data
    try:
        data = conn.recv(8192)
    except ConnectionError:
        sel.unregister(conn)
        conn.close()
        return
    if not data:
        sel.unregister(conn)
        conn.close()
        return

    state.buffer += data

    # 2. Process all complete requests in buffer
    while True:
        # 2a. Process HEADER
        if state.state == "HEADER":
            if len(state.buffer) >= REQUEST_HEADER_SIZE:
                # Parse header
                header_data = state.buffer[:REQUEST_HEADER_SIZE]
                client_id = header_data[:CLIENT_UUID_SIZE]
                version, code, payload_size = struct.unpack('!BHI', header_data[CLIENT_UUID_SIZE:])
                
                # Verify client version
                if version != CLIENT_VERSION:
                    send_error_response(conn, f"Wrong client version: {version}")
                    sel.unregister(conn)
                    conn.close()
                    return

                # Set to expect payload
                state.set_payload_state(client_id, code, payload_size)
                state.buffer = state.buffer[REQUEST_HEADER_SIZE:]
            else:
                break

        # 2b. Process PAYLOAD
        if state.state == "PAYLOAD":
            if len(state.buffer) >= state.expected_len:
                # We have a complete payload, process the request
                handle_request(conn, state)
            else:
                break
        if not state.buffer:
            break

# --- Accept New Connections ---
def accept(sock, mask):
    conn, addr = sock.accept()
    print('accepted connection from', addr)

    # Non-blocking socket
    conn.setblocking(False)

    # Register connection for reading with a new ConnectionState
    sel.register(conn, selectors.EVENT_READ, data={"callback": read, "state": ConnectionState()})

# --- Main Server Loop ---
def main():
    port = 1357 # default port

    # Try to read port from file
    try:
        with open(PORT_FILENAME, "r") as f:
            port_str = f.read().strip()
            if port_str: port = int(port_str)
    except Exception as e:
        print(f"Using default port {port} ({e})")

    # Create listening socket
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('localhost', port))
    sock.listen(100)
    sock.setblocking(False) # Non-blocking socket
    sel.register(sock, selectors.EVENT_READ, data={"callback": accept}) # Accept new connections
    print(f"Server (v{SERVER_VERSION}) listening on localhost:{port}")

    # Main event loop
    try:
        while True:
            events = sel.select()

            # Handle events
            for key, mask in events:
                key.data["callback"](key.fileobj, mask)
    except KeyboardInterrupt:
        print("Server shutting down.")

    # Graceful shutdown
    finally:
        sel.close()
        sock.close()

# the entry point of the script
if __name__ == "__main__":
    main() # Calls the function only if we run the file directly