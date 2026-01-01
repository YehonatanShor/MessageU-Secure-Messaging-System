#pragma once

#include <string>
#include <vector>
#include "RSAWrapper.h"
#include "AESWrapper.h"

/**
 * Encryption and decryption operations.
 * 
 * This class provides high-level encryption/decryption operations
 * for RSA (asymmetric) and AES (symmetric) encryption.
 */
class Encryption {
public:
    /**
     * Generate a new AES symmetric key.
     * 
     * @return AES key as binary string (16 bytes)
     */
    static std::string generate_aes_key();
    
    /**
     * Encrypt data using RSA public key.
     * 
     * @param public_key_bin Public key in binary format
     * @param plaintext Data to encrypt
     * @return Encrypted data
     * @throws std::runtime_error if encryption fails
     */
    static std::string encrypt_rsa(
        const std::string& public_key_bin,
        const std::string& plaintext
    );
    
    /**
     * Decrypt data using RSA private key.
     * 
     * @param private_key RSAPrivateWrapper instance (non-const because decrypt is not const)
     * @param ciphertext Encrypted data
     * @return Decrypted data
     * @throws std::runtime_error if decryption fails
     */
    static std::string decrypt_rsa(
        RSAPrivateWrapper& private_key,
        const std::string& ciphertext
    );
    
    /**
     * Encrypt data using AES symmetric key.
     * 
     * @param key AES key (must be 16 bytes)
     * @param plaintext Data to encrypt
     * @return Encrypted data
     * @throws std::runtime_error if encryption fails
     */
    static std::string encrypt_aes(
        const std::string& key,
        const std::string& plaintext
    );
    
    /**
     * Encrypt data using AES symmetric key (with size parameter).
     * 
     * @param key AES key (must be 16 bytes)
     * @param plaintext Data to encrypt
     * @param size Size of plaintext in bytes
     * @return Encrypted data
     * @throws std::runtime_error if encryption fails
     */
    static std::string encrypt_aes(
        const std::string& key,
        const char* plaintext,
        size_t size
    );
    
    /**
     * Decrypt data using AES symmetric key.
     * 
     * @param key AES key (must be 16 bytes)
     * @param ciphertext Encrypted data
     * @return Decrypted data
     * @throws std::runtime_error if decryption fails
     */
    static std::string decrypt_aes(
        const std::string& key,
        const std::string& ciphertext
    );
    
    /**
     * Decrypt data using AES symmetric key (with size parameter).
     * 
     * @param key AES key (must be 16 bytes)
     * @param ciphertext Encrypted data
     * @param size Size of ciphertext in bytes
     * @return Decrypted data
     * @throws std::runtime_error if decryption fails
     */
    static std::string decrypt_aes(
        const std::string& key,
        const char* ciphertext,
        size_t size
    );
};

