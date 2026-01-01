"""
Protocol and configuration constants for MessageU server.

This module contains all protocol definitions, message types, 
response codes, and configuration values.
"""

# ============================================================================
# Configuration
# ============================================================================

DEFAULT_PORT = 1357  # Default port if port file is missing or invalid
PORT_FILENAME = "myport.info"
DB_FILENAME = "defensive.db"

# ============================================================================
# Protocol Versions
# ============================================================================

CLIENT_VERSION = 2
SERVER_VERSION = 2

# ============================================================================
# Request Codes (from client to server)
# ============================================================================

REQUEST_CODE_REGISTER = 600
REQUEST_CODE_CLIENTS_LIST = 601
REQUEST_CODE_PUBLIC_KEY = 602
REQUEST_CODE_SEND_TEXT_MESSAGE = 603
REQUEST_CODE_WAITING_MESSAGES = 604
REQUEST_CODE_DELETE_USER = 605

# ============================================================================
# Response Codes (from server to client)
# ============================================================================

RESPONSE_CODE_REGISTER_SUCCESS = 2100
RESPONSE_CODE_DISPLAYING_CLIENTS_LIST = 2101
RESPONSE_CODE_SEND_PUBLIC_KEY = 2102
RESPONSE_CODE_SEND_TEXT_MESSAGE = 2103
RESPONSE_CODE_PULL_WAITING_MESSAGE = 2104
RESPONSE_CODE_DELETE_USER_SUCCESS = 2105
RESPONSE_CODE_GENERAL_ERROR = 9000

# ============================================================================
# Message Types (for payload of code 603)
# ============================================================================

MSG_TYPE_SYM_KEY_REQUEST = 1
MSG_TYPE_SYM_KEY_SEND = 2
MSG_TYPE_TEXT_MESSAGE = 3
MSG_TYPE_FILE = 4

# ============================================================================
# Protocol Sizes (in bytes)
# ============================================================================

CLIENT_UUID_SIZE = 16
CLIENT_VERSION_SIZE = 1
REQUEST_CODE_SIZE = 2
REQUEST_PAYLOAD_SIZE = 4
# ClientID(16) + Version(1) + Code(2) + PayloadSize(4)
REQUEST_HEADER_SIZE = 16 + 1 + 2 + 4
USERNAME_FIXED_SIZE = 255
PUBLIC_KEY_FIXED_SIZE = 160
REGISTRATION_PAYLOAD_SIZE = USERNAME_FIXED_SIZE + PUBLIC_KEY_FIXED_SIZE

SERVER_VERSION_SIZE = 1
RESPONSE_CODE_SIZE = 2
RESPONSE_PAYLOAD_SIZE = 4
RESPONSE_HEADER_SIZE = 1 + 2 + 4  # Version(1) + Code(2) + PayloadSize(4)

