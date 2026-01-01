"""
Registration handler for MessageU server.

Handles user registration requests, including validation, UUID generation,
and database storage.
"""

import uuid
from config import constants
from utils.responses import send_error_response, send_registration_success


def handle_registration(conn, payload, db):
    """
    Handle user registration request.
    
    Args:
        conn: The client connection socket
        payload: Registration payload (username + public key)
        db: DatabaseManager instance
    """
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
                f"Registered new user '{username}' with UUID {new_uuid_bytes.hex()}")
            send_registration_success(conn, new_uuid_bytes)
        # If already exists, register_client will return False
        else:
            send_error_response(conn, "Username already exists.")

    except Exception as e:
        print(f"Error processing registration: {e}")
        send_error_response(conn, "Registration failed.")


