# Research Paper: Risk and Vulnerability Assessment - MessageU Protocol

## Executive Summary

This document presents a security assessment of the MessageU protocol. Several critical vulnerabilities were identified regarding authentication, encryption implementation, and data storage.

## Vulnerability 1 - Lack of identity verification:

**Description:** The protocol relies solely on the request header to identify the user only by UUID, without the need for a password or digital signature. Therefore, it is easy to impersonate another user.

**Exploitation:** An attacker can connect to the server as a legitimate client and request a list of users to obtain the victim's UUID. Using the UUID, the attacker can impersonate the victim and perform actions on their behalf, like forging messages or stealing them.

**Remediation:** Enforce strict session validation implies that successful decryption of a message validates the sender's identity established during the handshake. A digital signature could also be considered, but this solution for each message is a very computationally intensive operation.

**Risk Score:**

- Damage Potential: 8
- Reproducibility: 10
- Exploitability: 9
- Affected Users: 10
- Overall: 9.2

## Vulnerability 2: Weak symmetric encryption

**Description:** The initial use of a fixed, zeroed initialization vector (IV) for AES-CBC encryption meant that encrypting the same text would always yield the same result. This could allow an attacker to detect patterns in the communication and compromise privacy.

**Exploitation:** The attacker listens to the network communication (sniffing). He sees that a certain encrypted sequence of bytes is repeated over and over again. The attacker builds a "dictionary" of common encrypted messages and thus can know the content of the conversation without deciphering the key.

**Remediation:** For each new message, a random IV must be generated. The IV should be prepended to the ciphertext. The receiving party will read the IV and use it for decryption.

**--- Remediation Status: FIXED (v1.1) ---**

**Fix Implementation:** The AESWrapper::encrypt function was modified to use CryptoPP::AutoSeededRandomPool to generate a cryptographically strong, random IV (16 bytes) for every new message. The IV is prepended to the ciphertext, adhering to the recommended remediation strategy. This prevents pattern detection and dictionary attacks.

**Risk Score (Original):** Overall: 6.3
**Risk Score (Current):** 0 (Mitigated)

## Vulnerability 3: DoS - Resource Exhaustion

**Description:** The server allows sending messages and files without any size or quantity restrictions.

**Exploitation:** An attacker can send files of infinite size to another user, filling the server's hard disk and causing it to crash.

**Remediation:** Set server limits: maximum size for a single message and maximum storage quota per user. Messages that exceed this limit will be rejected. Implement a Rate Limiting mechanism on the server side (e.g., Token Bucket algorithm) to restrict the number of requests per IP address within a specific time window. While this does not fully mitigate volumetric DDoS attacks (which require infrastructure-level protection), it effectively prevents single-source resource exhaustion attacks.

**Risk Score:**

- Damage Potential: 9
- Reproducibility: 10
- Exploitability: 8
- Overall: 9.0

## Vulnerability 4: Insecure Key Storage

**Description:** The client's private key is stored in the my.info file in a readable Base64 format, without encryption.

**Exploitation:** An attacker can spread a virus/trojan horse to the victim's computer, or physically access the computer while it is open. And copy the file my.info. Now the victim's private key is in his possession and he can decrypt any historical or future messages sent to the victim.

**Remediation:** Eliminate the usage of plain-text configuration files for sensitive key storage. Instead, utilize OS-level secure storage mechanisms (such as Windows Credential Manager via DPAPI or macOS Keychain). These native vaults encrypt data using the user's login credentials, ensuring that keys are inaccessible even if the file system is compromised by malware.

**Risk Score:**

- Damage Potential: 5
- Exploitability: 3
- Overall: 4.0

## Vulnerability 5: Metadata Leakage

**Description:** Although the message content is encrypted, the server is exposed to information about "who is talking to whom", when, and what the size of the messages is. This information is stored in the database openly and compromises user privacy in the event of a DB leak.

**Exploitation:** If the attacker manages to gain access/hack the server and download the defensive.db file, even without decrypting the messages, he is able to run a simple SQL query and obtain sensitive information such as a mapping of all the users' social/business connections.

**Remediation:** Using TLS (like SSL) for client-server communication to hide headers from network listeners. Additionally, encrypting sensitive columns in the database or avoiding long-term metadata logging.

**Risk Score:**

- Damage Potential: 5
- Exploitability: 3
- Overall: 4.0

## Vulnerability 6: Lack of Replay Protection

**Description:** The protocol does not include a mechanism to track message uniqueness, such as a monotonic counter, nonce, or timestamp within the encrypted payload.

**Exploitation:** An attacker can capture a valid encrypted packet from the network (e.g., a "Send Message" request) and re-transmit it to the server at a later time. Since the server does not track previously processed messages, it will treat the duplicate as a new, legitimate request and execute the action again (e.g., delivering the same message multiple times).

**Remediation:** Include a strictly increasing sequence number or a cryptographically secure nonce inside the encrypted part of every message. The server must maintain a state for each client and reject any message that contains a sequence number or nonce that has already been used or is out of order.

**Risk Score:**

- Damage Potential: 6
- Reproducibility: 10 (Extremely easy to capture and resend packets).
- Exploitability: 9 (Requires only basic network sniffing tools).
- Affected Users: 10 (All users are vulnerable by default).
- Overall: 8.75

## Vulnerability 7: Man-in-the-Middle (MitM) during Handshake

**Description:** The protocol lacks a mechanism for authenticating the server's identity during the initial public key exchange. There is no Certificate Authority (CA) or pre-shared root certificate to verify that the public key received by the client actually belongs to the intended server.

**Exploitation:** An attacker sitting between the client and the server (e.g., on a public Wi-Fi) can intercept the client's request for the server's public key. The attacker provides their own public key instead. The client, believing this is the server's key, encrypts the symmetric session key with it. The attacker decrypts it, re-encrypts it with the real server's key, and passes it on. From this point, the attacker can transparently read and modify all "encrypted" traffic.

**Remediation:** Implement industry-standard TLS (Transport Layer Security) for the underlying connection. If maintaining a custom protocol, implement a PKI (Public Key Infrastructure) where the server's public key is signed by a trusted third party, or use "Key Pinning" where the server's legitimate public key hash is hardcoded into the client.

**Risk Score:**

- Damage Potential: 10
- Reproducibility: 5
- Exploitability: 6
- Affected Users: 10
- Overall: 7.75

## Mitigated Vulnerabilities

### 1. SQL Injection:

**Risk:** Executing malicious SQL commands.

**Status:** MITIGATED.

**Mechanism:** The server uses parameterized queries (sqlite3 placeholders) for all database interactions, ensuring strictly typed input handling.
