# MessageU - Secure Messaging System

![Code Compilation Check](https://github.com/YehonatanShor/MessageU-Secure-Messaging-System/actions/workflows/check.yml/badge.svg)
![Latest Release](https://img.shields.io/github/v/release/YehonatanShor/MessageU-Secure-Messaging-System)

## Description

A secure, encrypted client-server messaging application implementing a custom application-layer protocol. The system features a C++ multi-threaded client and a Python server, designed with a focus on Defensive Programming principles and cryptographic security.

## 🚀 Quick Start - Running the System

You don't need to install anything except Docker to see the server in action!

### 1. Run the Server (Instant Deployment)

The server is available as a pre-built image on Docker Hub. Run it with one command:

```bash
  docker run -d -p 1234:1234 --name msg-server yehonatanshor/messageu-server:latest
```

Note: The -d flag runs the server in the background.

### 2. View Server Logs (Live Monitoring)

To see the server activity (connected clients, encrypted messages, etc.) in real-time:

```bash
  docker logs -f msg-server
```

(Press Ctrl+C to exit the log view without stopping the server)

### 3. Run the Client

1. Download MessageUClient.exe from the [Latest Releases.](https://github.com/YehonatanShor/MessageU-Secure-Messaging-System/releases)

2. Ensure your server.info points to 127.0.0.1 1234.

3. Run MessageUClient.exe and start messaging!

### 4. Cleanup (Stop & Remove)

When you are done, run this command to stop the server and free up the port for next time:

```bash
  docker rm -f msg-server
```

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

- **Continuous Integration (CI):**

  - **Automated Compilation:** Cross-platform checks for the C++ Client (Windows/MinGW64).
  - **Static Code Analysis:** Automated linting with `flake8` to maintain PEP8 standards.
  - **Docker Build Verification:** Ensuring the Dockerfile remains functional on every update.

- **Continuous Deployment (CD):**
  - **Automated Distribution:** Builds and publishes Windows executables upon tag creation.
  - **Docker Hub Integration:** Automatically pushes the latest server image to Docker Hub for instant deployment.
  - **Edge Case Handling:** Verification of conflict handling (duplicate registrations) and user deletion logic.
- **End-to-End Integration Tests:** A sophisticated Python suite that simulates multiple clients to verify full protocol flow, key exchange, and E2EE delivery.

## Tech Stack:

- **Client:** C++17, Boost.Asio (Networking), Crypto++ (Encryption), OOP.
- **Server:** Python 3.12, Selectors API (I/O Multiplexing), SQLite3.

## How to Build & Test (For Developers)

### 1. Manual Server Setup

1. Navigate to the server directory:

```bash
  cd server
```

2. Run the server:

```bash
  python server.py
```

### 2. Client Compilation

1. Navigate to the client directory: cd client/src

```bash
  cd client/src
```

2. Compile:

```bash
  g++ main.cpp MessageUClient.cpp RSAWrapper.cpp Base64Wrapper.cpp AESWrapper.cpp network/connection.cpp network/protocol_handler.cpp -o main.exe -std=c++17 -lWs2_32 -lpthread -lcryptopp -I../include
```

### 3. Running Integration Tests

To verify the server logic locally:

1. Ensure the server is running.

2. From the root directory, run:

```bash
  python tests/integration_test.py
```

### 4. Local Docker Orchestration

To build and run the entire environment locally (including database persistence):

```bash
  docker-compose up --build
```
