#pragma once

#include <string>
#include <memory>
#include "RSAWrapper.h"

/**
 * Key manager for RSA key pair generation and management.
 * 
 * This class handles RSA key pair generation, encoding/decoding,
 * and provides access to public and private keys.
 */
class KeyManager {
public:
    /**
     * Generate a new RSA key pair.
     * 
     * @return Unique pointer to RSAPrivateWrapper containing the key pair
     */
    static std::unique_ptr<RSAPrivateWrapper> generate_rsa_keypair();
    
    /**
     * Load RSA private key from Base64 encoded string.
     * 
     * @param private_key_b64 Base64 encoded private key
     * @return Unique pointer to RSAPrivateWrapper
     */
    static std::unique_ptr<RSAPrivateWrapper> load_private_key_from_base64(
        const std::string& private_key_b64
    );
    
    /**
     * Get public key in binary format from private key.
     * 
     * @param private_key RSAPrivateWrapper instance
     * @return Public key as binary string
     */
    static std::string get_public_key_binary(
        const RSAPrivateWrapper& private_key
    );
    
    /**
     * Encode private key to Base64 for storage.
     * 
     * @param private_key RSAPrivateWrapper instance
     * @return Base64 encoded private key
     */
    static std::string encode_private_key_to_base64(
        const RSAPrivateWrapper& private_key
    );
};



