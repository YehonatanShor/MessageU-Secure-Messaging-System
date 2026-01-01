"""
User deletion handler for MessageU server.

Handles requests to delete a user account and all associated data.
"""

from config import constants
from utils.responses import send_response, send_error_response


def handle_delete_user(conn, client_id_bytes, db):
    """
    Handle request to delete user.
    
    Args:
        conn: The client connection socket
        client_id_bytes: The user's UUID as bytes
        db: DatabaseManager instance
    """
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



