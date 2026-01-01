"""
Client list handler for MessageU server.

Handles requests to retrieve the list of all registered clients,
excluding the requester themselves.
"""

from config import constants
from utils.responses import send_response, send_error_response


def handle_client_list(conn, client_id_bytes, db):
    """
    Handle sending list of all users to the requester except themselves.
    
    Args:
        conn: The client connection socket
        client_id_bytes: The requester's UUID as bytes
        db: DatabaseManager instance
    """
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

