import struct  # For packing/unpacking binary data
import uuid    # For generating unique client IDs

# Import all protocol and configuration constants
from config import constants
# Import response building utilities
from utils.responses import send_response, send_error_response, send_registration_success
# Import database manager
from database.manager import DatabaseManager
# Import network components
from network.server import MessageUServer

# Global DB instance
db = DatabaseManager(constants.DB_FILENAME)

# Handles user registration


def handle_registration(conn, payload):
    try:
        # Validate payload size
        if len(payload) != constants.REGISTRATION_PAYLOAD_SIZE:
            send_error_response(conn, "Invalid registration payload size.")
            return

        # Extract username and public key
        username_bytes = payload[0:constants.USERNAME_FIXED_SIZE]
        public_key = payload[constants.USERNAME_FIXED_SIZE:]
        username = username_bytes.decode('utf-8').rstrip('\0')

        # Validate username
        if not username:
            send_error_response(conn, "Username cannot be empty.")
            return

        new_uuid_bytes = uuid.uuid4().bytes

        # Try register in DB
        if db.register_client(new_uuid_bytes, username, public_key):
            print(
                f"Registered new user '{username}' with UUID {
                    new_uuid_bytes.hex()}")
            send_registration_success(conn, new_uuid_bytes)
        # If already exists, register_client will return False
        else:
            send_error_response(conn, "Username already exists.")

    except Exception as e:
        print(f"Error processing registration: {e}")
        send_error_response(conn, "Registration failed.")

# Handles sending list of all users to the requester except themselves


def handle_client_list(conn, client_id_bytes):
    # Authenticate requester
    if not db.client_exists(client_id_bytes):
        send_error_response(
            conn, "Authentication failed. You are not registered.")
        return

    # Update last seen
    db.update_last_seen(client_id_bytes)
    requester_name = db.get_client_name(client_id_bytes)
    print(f"Sending client list to '{requester_name}'...")

    # Build payload - list of (UUID + Username)
    all_clients = db.get_all_clients()
    payload_chunks = []
    for uuid_bytes, username in all_clients:
        if uuid_bytes == client_id_bytes:
            continue  # Don't send own name

        # Append UUID and padded username to payload
        payload_chunks.append(uuid_bytes)  # 16 bytes
        name_bytes = username.encode('utf-8').ljust(constants.USERNAME_FIXED_SIZE, b'\0')
        payload_chunks.append(name_bytes)  # 255 bytes

    # Send users list to requester
    send_response(
        conn,
        constants.RESPONSE_CODE_DISPLAYING_CLIENTS_LIST,
        b"".join(payload_chunks))

# Handles sending public key of requested user to requester


def handle_public_key_request(conn, client_id_bytes, payload):
    # Authenticate requester
    if not db.client_exists(client_id_bytes):
        send_error_response(conn, "Authentication failed.")
        return

    # Update last seen
    db.update_last_seen(client_id_bytes)

    # Validate payload size
    if len(payload) != constants.CLIENT_UUID_SIZE:
        send_error_response(conn, "Invalid target UUID size.")
        return

    # Extract target UUID
    target_uuid_bytes = payload
    result = db.get_public_key(target_uuid_bytes)

    # Send public key to requester
    if result:
        target_pub_key, target_name = result
        requester_name = db.get_client_name(client_id_bytes)
        print(
            f"Sending public key of '{target_name}' to '{requester_name}'...")
        # send TargetUUID (16) + PublicKey (160) to client
        send_response(
            conn,
            constants.RESPONSE_CODE_SEND_PUBLIC_KEY,
            target_uuid_bytes +
            target_pub_key)
    else:
        send_error_response(conn, "Client not found.")

# Handles sending text message to another user


def handle_send_message(conn, client_id_bytes, payload):
    # Authenticate sender
    if not db.client_exists(client_id_bytes):
        send_error_response(conn, "Authentication failed.")
        return

    # Update last seen
    db.update_last_seen(client_id_bytes)

    # # Extract message
    try:
        target_id_bytes = payload[:constants.CLIENT_UUID_SIZE]
        msg_type = payload[constants.CLIENT_UUID_SIZE]
        content_size = struct.unpack(
            '!I', payload[constants.CLIENT_UUID_SIZE + 1: constants.CLIENT_UUID_SIZE + 5])[0]
        content = payload[constants.CLIENT_UUID_SIZE + 5:]

        # Validate message size
        if len(content) != content_size:
            send_error_response(conn, "Message size mismatch.")
            return

        # Validate target client existence
        if not db.client_exists(target_id_bytes):
            send_error_response(conn, "Target client does not exist.")
            return

        # Save message on DB and get message ID
        msg_id = db.save_message(
            target_id_bytes,
            client_id_bytes,
            msg_type,
            content)
        print(
            f"Message {msg_id} saved for {
                db.get_client_name(target_id_bytes)} from {
                db.get_client_name(client_id_bytes)}")

        # Send client confirmation: TargetUUID (16) + MsgID (4)
        response_payload = target_id_bytes + struct.pack('!I', msg_id)
        send_response(conn, constants.RESPONSE_CODE_SEND_TEXT_MESSAGE, response_payload)

    except Exception as e:
        print(f"Error handling send_message: {e}")
        send_error_response(conn, "Invalid message format.")

# Handles pulling waiting messages for a user


def handle_pull_messages(conn, client_id_bytes):
    # 1. Authenticate requester
    if not db.client_exists(client_id_bytes):
        send_error_response(conn, "Authentication failed.")
        return

    # 2. Update last seen and get messages
    db.update_last_seen(client_id_bytes)
    # List of (ID, FromClient, Type, Content)
    messages = db.get_waiting_messages(client_id_bytes)

    # 2a. If no messages, send empty response
    if not messages:
        send_response(conn, constants.RESPONSE_CODE_PULL_WAITING_MESSAGE, b"")
        return

    # 3. Build payload and send
    print(
        f"Sending {
            len(messages)} messages to {
            db.get_client_name(client_id_bytes)}")
    payload_chunks = []
    for msg_id, from_uuid, msg_type, content in messages:
        payload_chunks.append(from_uuid)                       # 16 bytes
        payload_chunks.append(struct.pack('!I', msg_id))       # 4 bytes
        payload_chunks.append(struct.pack('!B', msg_type))     # 1 byte
        payload_chunks.append(struct.pack('!I', len(content)))  # 4 bytes
        payload_chunks.append(content)                         # N bytes

    send_response(
        conn,
        constants.RESPONSE_CODE_PULL_WAITING_MESSAGE,
        b"".join(payload_chunks))

# Handles request to delete user


def handle_delete_user(conn, client_id_bytes):
    # 1. Authenticate
    if not db.client_exists(client_id_bytes):
        send_error_response(conn, "Authentication failed. User not found.")
        return

    client_name = db.get_client_name(client_id_bytes)
    print(f"Request to delete user: {client_name}")

    # 2. Perform deletion
    if db.delete_client(client_id_bytes):
        print(f"User {client_name} deleted successfully.")
        send_response(conn, constants.RESPONSE_CODE_DELETE_USER_SUCCESS, b"")
    else:
        send_error_response(conn, "Failed to delete user from database.")

# Main handler - matches users request to appropriate handling function


def handle_request(conn, state):

    # Extract payload
    payload = state.buffer[:state.expected_len]

    # Dispatch based on request code
    if state.request_code == constants.REQUEST_CODE_REGISTER:
        handle_registration(conn, payload)
    elif state.request_code == constants.REQUEST_CODE_CLIENTS_LIST:
        handle_client_list(conn, state.client_id)
    elif state.request_code == constants.REQUEST_CODE_PUBLIC_KEY:
        handle_public_key_request(conn, state.client_id, payload)
    elif state.request_code == constants.REQUEST_CODE_SEND_TEXT_MESSAGE:
        handle_send_message(conn, state.client_id, payload)
    elif state.request_code == constants.REQUEST_CODE_WAITING_MESSAGES:
        handle_pull_messages(conn, state.client_id)
    elif state.request_code == constants.REQUEST_CODE_DELETE_USER:
        handle_delete_user(conn, state.client_id)
    else:
        print(f"Unknown request code: {state.request_code}")
        send_error_response(
            conn, f"Unknown request code: {
                state.request_code}")

    # Remove processed data from buffer and reset state
    state.buffer = state.buffer[state.expected_len:]
    state.reset_for_new_request()

# Main Server Loop


def main():
    # Create server instance
    server = MessageUServer(db)
    
    # Set the request handler
    server.handle_request = handle_request
    
    # Start server
    server.start()
    
    # Run event loop
    server.run()


# Entry point of script
if __name__ == "__main__":
    main()  # Calls the function only if we run the file directly
