"""
Messaging handlers for MessageU server.

Handles sending messages between clients and retrieving waiting messages.
"""

import struct
from config import constants
from utils.responses import send_response, send_error_response


def handle_send_message(conn, client_id_bytes, payload, db):
    """
    Handle sending text message to another user.
    
    Args:
        conn: The client connection socket
        client_id_bytes: The sender's UUID as bytes
        payload: Message payload (target UUID + message type + content)
        db: DatabaseManager instance
    """
    # Authenticate sender
    if not db.client_exists(client_id_bytes):
        send_error_response(conn, "Authentication failed.")
        return

    # Update last seen
    db.update_last_seen(client_id_bytes)

    # Extract message
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
            f"Message {msg_id} saved for {db.get_client_name(target_id_bytes)} from {db.get_client_name(client_id_bytes)}")

        # Send client confirmation: TargetUUID (16) + MsgID (4)
        response_payload = target_id_bytes + struct.pack('!I', msg_id)
        send_response(conn, constants.RESPONSE_CODE_SEND_TEXT_MESSAGE, response_payload)

    except Exception as e:
        print(f"Error handling send_message: {e}")
        send_error_response(conn, "Invalid message format.")


def handle_pull_messages(conn, client_id_bytes, db):
    """
    Handle pulling waiting messages for a user.
    
    Args:
        conn: The client connection socket
        client_id_bytes: The requester's UUID as bytes
        db: DatabaseManager instance
    """
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
        f"Sending {len(messages)} messages to {db.get_client_name(client_id_bytes)}")
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



