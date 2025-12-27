import socket
import struct
import time
import subprocess
import os

# Configuration
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 1234  # Based on myport.info
CLIENT_VERSION = 2;
REQUEST_CODE_REGISTER = 600;
RESPONSE_CODE_REGISTER_SUCCESS = 2100;

def run_test():
    print("[*] Starting Integration Test: Mock Client Registration")
    
    # Simulate a simple Registration Request (Code 1000)
    # Header format: ClientID (16 bytes), Version (1 byte), Code (2 bytes), PayloadSize (4 bytes)
    # Since it's a new client, ClientID is all zeros.
    client_id = b'\x00' * 16
    version = CLIENT_VERSION
    code = REQUEST_CODE_REGISTER  # Request Registration
    user_name = "MockUser".ljust(255, '\0').encode('ascii') # 255 bytes for name
    payload_size = len(user_name)

    # Pack into little-endian binary format
    header = struct.pack('<16sBHI', client_id, version, code, payload_size)
    request = header + user_name

    try:
        # Connect to Server
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((SERVER_HOST, SERVER_PORT))
            
            # Send Request
            s.sendall(request)
            
            # Receive Response Header (Version: 1 byte, Code: 2 bytes, PayloadSize: 4 bytes)
            response_header = s.recv(7)
            if len(response_header) < 7:
                print("[!] Error: Received incomplete header from server")
                return False
                
            res_version, res_code, res_payload_size = struct.unpack('<BHI', response_header)
            
            print(f"[*] Server Response - Code: {res_code}, Payload Size: {res_payload_size}")
            
            # Code 2100 means Registration Success in this protocol
            if res_code == RESPONSE_CODE_REGISTER_SUCCESS:
                print("[+] SUCCESS: Server handled registration request correctly.")
                return True
            else:
                print(f"[-] FAILED: Unexpected response code {res_code}")
                return False

    except Exception as e:
        print(f"[!] Connection Error: {e}")
        return False

if __name__ == "__main__":
    result = run_test()
    exit(0 if result else 1)