#include "crypto/encryption.h"
#include <stdexcept>

std::string Encryption::generate_aes_key() {
    unsigned char key[AESWrapper::DEFAULT_KEYLENGTH];
    AESWrapper::GenerateKey(key, sizeof(key));
    return std::string((char*)key, sizeof(key));
}

std::string Encryption::encrypt_rsa(
    const std::string& public_key_bin,
    const std::string& plaintext) {
    
    try {
        RSAPublicWrapper pub(public_key_bin);
        return pub.encrypt(plaintext);
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("RSA encryption failed: ") + e.what());
    }
}

std::string Encryption::decrypt_rsa(
    RSAPrivateWrapper& private_key,
    const std::string& ciphertext) {
    
    try {
        return private_key.decrypt(ciphertext);
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("RSA decryption failed: ") + e.what());
    }
}

std::string Encryption::encrypt_aes(
    const std::string& key,
    const std::string& plaintext) {
    
    if (key.size() != AESWrapper::DEFAULT_KEYLENGTH) {
        throw std::runtime_error("AES key must be 16 bytes");
    }
    
    try {
        AESWrapper aes((unsigned char*)key.data(), key.size());
        return aes.encrypt(plaintext.c_str(), plaintext.size());
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("AES encryption failed: ") + e.what());
    }
}

std::string Encryption::encrypt_aes(
    const std::string& key,
    const char* plaintext,
    size_t size) {
    
    if (key.size() != AESWrapper::DEFAULT_KEYLENGTH) {
        throw std::runtime_error("AES key must be 16 bytes");
    }
    
    try {
        AESWrapper aes((unsigned char*)key.data(), key.size());
        return aes.encrypt(plaintext, size);
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("AES encryption failed: ") + e.what());
    }
}

std::string Encryption::decrypt_aes(
    const std::string& key,
    const std::string& ciphertext) {
    
    if (key.size() != AESWrapper::DEFAULT_KEYLENGTH) {
        throw std::runtime_error("AES key must be 16 bytes");
    }
    
    try {
        AESWrapper aes((unsigned char*)key.data(), key.size());
        return aes.decrypt(ciphertext.data(), ciphertext.size());
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("AES decryption failed: ") + e.what());
    }
}

std::string Encryption::decrypt_aes(
    const std::string& key,
    const char* ciphertext,
    size_t size) {
    
    if (key.size() != AESWrapper::DEFAULT_KEYLENGTH) {
        throw std::runtime_error("AES key must be 16 bytes");
    }
    
    try {
        AESWrapper aes((unsigned char*)key.data(), key.size());
        return aes.decrypt(ciphertext, size);
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("AES decryption failed: ") + e.what());
    }
}

