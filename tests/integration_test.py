import socket
import struct
import time
import unittest
import os

# --- Server Configuration (Must match server.py) ---
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 1234  # As set in your myport.info (or 1357 default)

# Request Codes
REQUEST_REGISTER = 600
REQUEST_LIST = 601
REQUEST_PUB_KEY = 602
REQUEST_SEND_MSG = 603
REQUEST_PULL_MSGS = 604
REQUEST_DELETE = 605

# Message Types
MSG_TYPE_SYM_KEY_REQUEST = 1
MSG_TYPE_SYM_KEY_SEND = 2
MSG_TYPE_TEXT_MESSAGE = 3

# Sizes
HEADER_SIZE = 23 # 16(ID) + 1(Ver) + 2(Code) + 4(Size)
NAME_SIZE = 255
PUB_KEY_SIZE = 160

class MockClient:
    """A helper class to simulate a client behavior"""
    def __init__(self, name):
        self.name = name
        self.uuid = b'\x00' * 16 # Init with empty UUID
        self.dummy_pub_key = b'P' * PUB_KEY_SIZE # Mock public key
        self.socket = None
    
    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(2)
        self.socket.connect((SERVER_HOST, SERVER_PORT))

    def close(self):
        if self.socket:
            self.socket.close()

    def _send_request(self, code, payload):
        # Pack Header: ClientID(16), Ver(1), Code(2), Size(4)
        # Using Big-Endian (!) as per server
        header = struct.pack('!16sBHI', self.uuid, 2, code, len(payload))
        self.socket.sendall(header + payload)

    def _read_response(self):
        # Read Header: Ver(1), Code(2), Size(4)
        header_data = self.socket.recv(7) 
        if not header_data:
            raise Exception("Connection closed by server")
        ver, code, size = struct.unpack('!BHI', header_data)
        
        # Read Payload
        payload = b""
        while len(payload) < size:
            chunk = self.socket.recv(size - len(payload))
            if not chunk: break
            payload += chunk
        return code, payload

    def register(self):
        print(f"[*] Registering {self.name}...")
        payload = self.name.encode('utf-8').ljust(NAME_SIZE, b'\0') + self.dummy_pub_key
        self._send_request(REQUEST_REGISTER, payload)
        code, response = self._read_response()
        
        if code == 2100:
            self.uuid = response # Server returns the assigned UUID
            print(f"[+] {self.name} registered successfully. UUID: {self.uuid.hex()}")
            return True
        return False

    def get_user_list(self):
        print(f"[*] {self.name} requesting user list...")
        self._send_request(REQUEST_LIST, b"")
        code, payload = self._read_response()
        
        users = {}
        # Parse payload: chunks of 16 bytes (UUID) + 255 bytes (Name)
        chunk_size = 16 + 255
        for i in range(0, len(payload), chunk_size):
            u_uuid = payload[i:i+16]
            u_name = payload[i+16:i+16+255].decode('utf-8').strip('\0')
            users[u_name] = u_uuid
        return code, users

    def get_public_key(self, target_uuid):
        print(f"[*] {self.name} requesting public key for target...")
        self._send_request(REQUEST_PUB_KEY, target_uuid)
        code, payload = self._read_response()
        # Payload is TargetUUID(16) + PubKey(160)
        if code == 2102:
            return payload[16:] 
        return None

    def send_message(self, target_uuid, msg_type, content):
        print(f"[*] {self.name} sending message type {msg_type}...")
        # Payload: TargetUUID(16) + Type(1) + Size(4) + Content
        msg_payload = target_uuid + struct.pack('!BI', msg_type, len(content)) + content
        self._send_request(REQUEST_SEND_MSG, msg_payload)
        code, _ = self._read_response()
        return code

    def pull_messages(self):
        print(f"[*] {self.name} pulling messages...")
        self._send_request(REQUEST_PULL_MSGS, b"")
        code, payload = self._read_response()
        
        messages = []
        if code == 2104 and payload:
            offset = 0
            while offset < len(payload):
                # Format: FromUUID(16) + MsgID(4) + Type(1) + Size(4) + Content
                from_uuid = payload[offset : offset+16]
                offset += 16
                msg_id = struct.unpack('!I', payload[offset:offset+4])[0]
                offset += 4
                msg_type = struct.unpack('!B', payload[offset:offset+1])[0]
                offset += 1
                msg_size = struct.unpack('!I', payload[offset:offset+4])[0]
                offset += 4
                content = payload[offset : offset+msg_size]
                offset += msg_size
                
                messages.append({
                    "from": from_uuid,
                    "type": msg_type,
                    "content": content
                })
        return code, messages

    def delete_user(self):
        print(f"[*] Deleting user {self.name}...")
        self._send_request(REQUEST_DELETE, b"")
        code, _ = self._read_response()
        return code


class TestMessageUServer(unittest.TestCase):
    
    def setUp(self):
        # Clean DB before tests if possible, or use unique names
        # For simplicity, using unique names based on timestamp
        self.suffix = str(int(time.time()))

    def test_a_conflict_registration(self):
        print("\n--- TEST: Conflict Registration ---")
        name = f"ConflictUser_{self.suffix}"
        c1 = MockClient(name)
        c1.connect()
        self.assertTrue(c1.register(), "First registration should succeed")
        c1.close()

        # Try registering again with same name
        c2 = MockClient(name)
        c2.connect()
        print(f"[*] Attempting duplicate registration for {name}")
        
        # Manually sending register to check failure code
        payload = c2.name.encode('utf-8').ljust(NAME_SIZE, b'\0') + c2.dummy_pub_key
        c2._send_request(REQUEST_REGISTER, payload)
        code, _ = c2._read_response()
        
        # Server should return 9000 (General Error) for duplicate
        self.assertEqual(code, 9000, "Duplicate registration should fail")
        c2.close()

    def test_b_full_flow(self):
        print("\n--- TEST: End-to-End Flow (Alice -> Bob) ---")
        
        # 1. Register Alice and Bob
        alice = MockClient(f"Alice_{self.suffix}")
        bob = MockClient(f"Bob_{self.suffix}")
        
        alice.connect()
        alice.register()
        
        bob.connect()
        bob.register()

        # 2. Alice requests User List (to find Bob) (Code 601)
        code, users = alice.get_user_list()
        self.assertEqual(code, 2101)
        self.assertIn(f"Bob_{self.suffix}", users)
        bob_uuid = users[f"Bob_{self.suffix}"]

        # 3. Alice requests Bob's Public Key (Code 602)
        pub_key = alice.get_public_key(bob_uuid)
        self.assertIsNotNone(pub_key)
        self.assertEqual(len(pub_key), 160)

        # 4. Alice sends Symmetric Key to Bob (Code 603, Type 2)
        # Note: In real app, this key is encrypted with Bob's Public Key. 
        # Here we send dummy encrypted data.
        dummy_sym_key = b"ENCRYPTED_SYM_KEY_12345" 
        code = alice.send_message(bob_uuid, MSG_TYPE_SYM_KEY_SEND, dummy_sym_key)
        self.assertEqual(code, 2103) # Message Sent

        # 5. Bob pulls messages (Code 604)
        code, messages = bob.pull_messages()
        self.assertEqual(code, 2104)
        
        # Validate Bob received the Symmetric Key
        found_key = False
        for msg in messages:
            if msg['from'] == alice.uuid and msg['type'] == MSG_TYPE_SYM_KEY_SEND:
                self.assertEqual(msg['content'], dummy_sym_key)
                found_key = True
                print("[+] Bob received symmetric key from Alice")
        self.assertTrue(found_key, "Bob failed to receive symmetric key")

        # 6. Bob sends Text Message back to Alice (Code 603, Type 3)
        # Note: Real app encrypts this with the symmetric key.
        dummy_encrypted_text = b"This is a secret message!"
        bob.send_message(alice.uuid, MSG_TYPE_TEXT_MESSAGE, dummy_encrypted_text)

        # 7. Alice pulls messages
        code, messages = alice.pull_messages()
        
        # Validate Alice received the text
        found_text = False
        for msg in messages:
            if msg['from'] == bob.uuid and msg['type'] == MSG_TYPE_TEXT_MESSAGE:
                self.assertEqual(msg['content'], dummy_encrypted_text)
                found_text = True
                print("[+] Alice received text message from Bob")
        self.assertTrue(found_text, "Alice failed to receive text message")

        alice.close()
        bob.close()

    def test_c_delete_user(self):
        print("\n--- TEST: Delete User ---")
        user = MockClient(f"ToBeDeleted_{self.suffix}")
        user.connect()
        user.register()

        # Delete user (Code 605)
        code = user.delete_user()
        self.assertEqual(code, 2105, "Delete should return success code")

        # Verify deletion by trying to perform an action (e.g., Pull Messages)
        # Should fail authentication
        print("[*] Verifying deletion by attempting to pull messages...")
        user._send_request(REQUEST_PULL_MSGS, b"")
        code, _ = user._read_response()
        
        # Expecting 9000 (General Error / Auth Failed)
        self.assertEqual(code, 9000, "Deleted user should not be able to perform actions")
        user.close()

if __name__ == "__main__":
    unittest.main()