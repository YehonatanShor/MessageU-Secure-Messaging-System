# MessageU - Secure Messaging System

![Code Compilation Check](https://github.com/YehonatanShor/MessageU-Secure-Messaging-System/actions/workflows/check.yml/badge.svg)
![Latest Release](https://img.shields.io/github/v/release/YehonatanShor/MessageU-Secure-Messaging-System)

## Description

A secure, encrypted client-server messaging application implementing a custom application-layer protocol. The system features a C++ multi-threaded client and a Python server, designed with a focus on Defensive Programming principles and cryptographic security.

## Key Features:

- **Hybrid E2EE Encryption:** Implements RSA (1024-bit) for key exchange and AES (CBC mode).
- **Security Enhancement:** Includes per-message generation of a **cryptographically secure, random Initialization Vector (IV)** to prevent pattern detection attacks.
- **Custom Binary Protocol:** Designed and implemented a proprietary binary protocol over TCP/IP (Big-Endian handling).
- **Cross-Language Architecture:** Interoperability between a C++17 client (using Boost.Asio) and a Python 3.12 server.
- **Persistent Storage:** Server-side data management using SQLite database.
- **Robust Functionality:** Supports user registration, file transfer, message queueing, and secure user deletion.
- **Defensive Coding:** Handles edge cases, buffer overflow protections, and rigorous input validation.

## CI/CD & Automated Testing

This project implements a professional DevOps pipeline using **GitHub Actions**, ensuring code reliability through:

- **Continuous Integration (CI):** \* **Automated Compilation:** Cross-platform checks for the C++ Client (Windows/MinGW64).
  - **Static Code Analysis:** Automated linting with `flake8` to maintain PEP8 standards.
- **End-to-End Integration Tests:** A sophisticated Python suite that simulates multiple clients to verify:
  - **Full Protocol Flow:** Registration, user listing, and RSA public key exchange.
  - **Encrypted Messaging:** Validation of symmetric key transfer and E2EE message delivery.
  - **Edge Case Handling:** Verification of conflict handling (duplicate registrations) and user deletion logic.
- **Continuous Deployment (CD):** Automated release system that builds and publishes Windows executables upon tag creation (e.g., `v1.4`).

## Tech Stack:

- **Client:** C++17, Boost.Asio (Networking), Crypto++ (Encryption), OOP.
- **Server:** Python 3.12, Selectors API (I/O Multiplexing), SQLite3.

## How to Run:

### 1. Prerequisites

Ensure you have the following installed:

- **C++ Compiler:** GCC/G++ (C++17 standard)
- **Libraries (Client):** Boost.Asio, Crypto++
- **Python 3.12** (Server)

### 2. Server Setup

1. Navigate to the server directory:

```bash
  cd server
```

2. Run the server:

```bash
  `python server.py`
```

### 3. Client Setup

1. Navigate to the client directory:

```bash
  cd client/src
```

2. **Compile the Client:**

```bash
  g++ main.cpp MessageUClient.cpp RSAWrapper.cpp Base64Wrapper.cpp AESWrapper.cpp -o main.exe -std=c++17 -lWs2_32 -lpthread -lcryptopp -I../include
```

3. **Execute the Client:**

```bash
./main.exe
```

4. **Running Integration Tests**
   To verify the server logic locally:

- Ensure the server is running.

- From the root directory, run:

```bash
python tests/integration_test.py
```
