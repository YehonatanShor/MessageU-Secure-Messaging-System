"""
Public key handler for MessageU server.

Handles requests to retrieve a client's public key for encryption purposes.
"""

from config import constants
from utils.responses import send_response, send_error_response


def handle_public_key_request(conn, client_id_bytes, payload, db):
    """
    Handle sending public key of requested user to requester.
    
    Args:
        conn: The client connection socket
        client_id_bytes: The requester's UUID as bytes
        payload: The target client's UUID (16 bytes)
        db: DatabaseManager instance
    """
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
            target_uuid_bytes + target_pub_key)
    else:
        send_error_response(conn, "Client not found.")


