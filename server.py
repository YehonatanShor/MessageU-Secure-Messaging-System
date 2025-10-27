import socket
# This is a test change

DEFAULT_PORT = 8080 #define DEFAULT_PORT
DEFAULT_BUFLEN = 1024 #define DEFAULT_BUFLEN
SERVERS_RESPONSE = "Hello from server, happy to bind with you!" #define SERVERS_RESPONSE

def main():
    
    try:
        # Create socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Set socket options to allow address reuse
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
     
        # Binding socket
        server_socket.bind(("", DEFAULT_PORT)) 

        # listening for incoming requests
        server_socket.listen()
        print(f"Server listening on port {DEFAULT_PORT}")
        
        # Keep the server running
        while True:
            print("Waiting for client connection...")
            
            # Accepting connection
            with server_socket.accept()[0] as client_socket: # Python's accept returns a (socket, address) tuple

                print(f"Client connected successfully!")

                # Receiving data from client
                client_message_bytes = client_socket.recv(DEFAULT_BUFLEN) # Python's recv returns a 'bytes' object
                
                # decode the bytes to a string to print it
                client_message_str = client_message_bytes.decode('utf-8')
                print(f"Received from client: {client_message_str}")

                # Sending reply to client
                client_socket.sendall(SERVERS_RESPONSE.encode('utf-8')) # Python's send/sendall requires a 'bytes' object, so we encode the string
                print("Reply sent back to client.\n\n\n")
            
    except KeyboardInterrupt:
        print("\nServer is shutting down.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        # Clean up and close socket
        if 'server_socket' in locals():
            server_socket.close()
            print("Listening socket closed.")

if __name__ == "__main__":
    main()