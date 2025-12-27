import socket
import struct
import time

# Configuration based on server.py
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 1234  # Based on server.py
CLIENT_VERSION = 2
REQUEST_CODE_REGISTER = 600
RESPONSE_CODE_REGISTER_SUCCESS = 2100
USERNAME_SIZE = 255
PUBLIC_KEY_SIZE = 160
# Total payload must be 415 bytes
REGISTRATION_PAYLOAD_SIZE = USERNAME_SIZE + PUBLIC_KEY_SIZE 

def run_test():
    print(f"[*] Starting Integration Test: Connecting to {SERVER_HOST}:{SERVER_PORT}")
    
    # Header: ClientID(16s), Version(B), Code(H), PayloadSize(I)
    # Using '!' for Big-Endian as per your server's struct.unpack('!BHI')
    client_id = b'\x00' * 16
    version = CLIENT_VERSION
    code = REQUEST_CODE_REGISTER
    
    # Prepare Payload: Name (255) + Dummy Public Key (160)
    user_name = "MockUser".ljust(USERNAME_SIZE, '\0').encode('utf-8')
    dummy_pub_key = b'\x11' * PUBLIC_KEY_SIZE
    payload = user_name + dummy_pub_key
    payload_size = len(payload)

    # Pack Header and build request
    header = struct.pack('!16sBHI', client_id, version, code, payload_size)
    request = header + payload

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect((SERVER_HOST, SERVER_PORT))
            s.sendall(request)
            
            # Receive Response Header: Version(1), Code(2), PayloadSize(4)
            response_header = s.recv(7)
            if len(response_header) < 7:
                return False
                
            res_version, res_code, res_payload_size = struct.unpack('!BHI', response_header)
            print(f"[*] Server Response - Code: {res_code}, Payload Size: {res_payload_size}")
            
            if res_code == RESPONSE_CODE_REGISTER_SUCCESS:
                print("[+] SUCCESS: Registration test passed.")
                return True
            else:
                # If failed, try to read error message from payload
                error_payload = s.recv(res_payload_size)
                print(f"[-] FAILED: Server returned code {res_code}. Message: {error_payload.decode('utf-8', 'ignore')}")
                return False

    except Exception as e:
        print(f"[!] Test Error: {e}")
        return False

if __name__ == "__main__":
    # Small delay to ensure server is ready in CI environment
    time.sleep(2)
    exit(0 if run_test() else 1)