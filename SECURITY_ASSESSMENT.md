# Research Paper: Risk and Vulnerability Assessment - MessageU Protocol

## Executive Summary

This document presents a security assessment of the MessageU protocol. Several critical vulnerabilities were identified regarding authentication, encryption implementation, and data storage.

## Vulnerability 1 - Lack of identity verification:

**Description:** The protocol relies solely on the request header to identify the user only by UUID, without the need for a password or digital signature. Therefore, it is easy to impersonate another user.

**Exploitation:** An attacker can connect to the server as a legitimate client and request a list of users to obtain the victim's UUID. Using the UUID, the attacker can impersonate the victim and perform actions on their behalf, like forging messages or stealing them.

**Remediation:** Using a digital signature. The client must sign each request using its private key. The server will verify the signature against the public key stored with it and verify that the sender is indeed the owner of the identity.

**Risk Score:**

- Damage Potential: 8
- Reproducibility: 10
- Exploitability: 9
- Affected Users: 10
- Overall: 9.2

## Vulnerability 2: Weak symmetric encryption

**Description:** The use of a fixed, zeroed initialization vector (IV) for AES-CBC encryption means that encrypting the same text will always yield the same result. Therefore, it is easy to detect patterns in the communication and compromise privacy.

**Exploitation:** The attacker listens to the network communication (sniffing). He sees that a certain encrypted sequence of bytes is repeated over and over again. The attacker builds a "dictionary" of common encrypted messages and thus can know the content of the conversation without deciphering the key.

**Remediation:** For each new message, a random IV must be generated. The IV should be prepended to the ciphertext. The receiving party will read the IV and use it for decryption.

**Risk Score:**

- Damage Potential: 4
- Reproducibility: 10
- Exploitability: 5
- Overall: 6.3

## Vulnerability 3: DoS - Resource Exhaustion

**Description:** The server allows sending messages and files without any size or quantity restrictions.

**Exploitation:** An attacker can send files of infinite size to another user, filling the server's hard disk and causing it to crash.

**Remediation:** Set server limits: maximum size for a single message and maximum storage quota per user. Messages that exceed this limit will be rejected.

**Risk Score:**

- Damage Potential: 9
- Reproducibility: 10
- Exploitability: 8
- Overall: 9.0

## Vulnerability 4: Insecure Key Storage

**Description:** The client's private key is stored in the my.info file in a readable Base64 format, without encryption.

**Exploitation:** An attacker can spread a virus/trojan horse to the victim's computer, or physically access the computer while it is open. And copy the file my.info. Now the victim's private key is in his possession and he can decrypt any historical or future messages sent to the victim.

**Remediation:** Instead of storing the private key as text, it should be encrypted. That is, the my.info file will only contain the encrypted version of the key.

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
