# defensive-programing

## Title: MessageU - Secure Messaging System

Description: A secure, encrypted client-server messaging application implementing a custom application-layer protocol. The system features a C++ multi-threaded client and a Python server, designed with a focus on Defensive Programming principles and cryptographic security.

## Key Features:

- **Hybrid E2EE Encryption:** Implements RSA (1024-bit) for key exchange and AES (CBC mode).
  - **Security Enhancement:** Includes per-message generation of a **cryptographically secure, random Initialization Vector (IV)** to prevent pattern detection attacks.
- **Custom Binary Protocol:** Designed and implemented a proprietary binary protocol over TCP/IP (Little-Endian/Big-Endian handling).
- **Cross-Language Architecture:** Interoperability between a C++17 client (using Boost.Asio) and a Python 3 server.
- **Persistent Storage:** Server-side data management using SQLite database.
- **Robust Functionality:** Supports user registration, file transfer, message queueing, and secure user deletion.
- **Defensive Coding:** Handles edge cases, buffer overflows protections, and rigorous input validation.

## Tech Stack:

Client: C++17, Boost.Asio (Networking), Crypto++ (Encryption), OOP.

Server: Python 3, Selectors API (I/O Multiplexing), SQLite3.

## How to Run:

The project requires separate compilation for the C++ Client and execution for the Python Server.

### 1. Prerequisites

Ensure you have the following installed and linked:

- **C++ Compiler:** GCC/G++ (C++17 standard)
- **Libraries (Client):** Boost.Asio, Crypto++
- **Python 3** (Server)

### 2. Server Setup (Python)

The server reads the desired port from `myport.info` (if present) or uses a default.

1. Navigate to the Server directory:

```bash
cd Server/
```

2. Run the server:

```bash
python3 server.py
```

### 3. Client Setup and Execution (C++)

1. Navigate to the Client directory:

```bash
cd Client/
```

2. **Compile the Client:** Use the following command. Note: Compilation flags and library paths (`-lWs2_32 -lpthread -lcryptopp`) must match your specific system configuration.

```bash
g++ main.cpp MessageUClient.cpp RSAWrapper.cpp Base64Wrapper.cpp AESWrapper.cpp -o main.exe -std=c++17 -lWs2_32 -lpthread -lcryptopp
```

3. **Execute the Client:**

```bash
./main.exe
```

_(Note: Ensure the `server.info` file is correctly configured in the Client directory with the server's IP and Port before execution.)_
