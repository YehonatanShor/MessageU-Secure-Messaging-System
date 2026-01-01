# Import all protocol and configuration constants
from config import constants
# Import response building utilities
from utils.responses import send_error_response
# Import database manager
from database.manager import DatabaseManager
# Import network components
from network.server import MessageUServer
# Import request handlers
from handlers.registration import handle_registration
from handlers.client_list import handle_client_list
from handlers.public_key import handle_public_key_request
from handlers.messaging import handle_send_message, handle_pull_messages
from handlers.deletion import handle_delete_user

# Global DB instance
db = DatabaseManager(constants.DB_FILENAME)

# Main handler - matches users request to appropriate handling function


def handle_request(conn, state):

    # Extract payload
    payload = state.buffer[:state.expected_len]

    # Dispatch based on request code
    if state.request_code == constants.REQUEST_CODE_REGISTER:
        handle_registration(conn, payload, db)
    elif state.request_code == constants.REQUEST_CODE_CLIENTS_LIST:
        handle_client_list(conn, state.client_id, db)
    elif state.request_code == constants.REQUEST_CODE_PUBLIC_KEY:
        handle_public_key_request(conn, state.client_id, payload, db)
    elif state.request_code == constants.REQUEST_CODE_SEND_TEXT_MESSAGE:
        handle_send_message(conn, state.client_id, payload, db)
    elif state.request_code == constants.REQUEST_CODE_WAITING_MESSAGES:
        handle_pull_messages(conn, state.client_id, db)
    elif state.request_code == constants.REQUEST_CODE_DELETE_USER:
        handle_delete_user(conn, state.client_id, db)
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
