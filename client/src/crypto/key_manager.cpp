#include "crypto/key_manager.h"
#include "Base64Wrapper.h"

std::unique_ptr<RSAPrivateWrapper> KeyManager::generate_rsa_keypair() {
    return std::make_unique<RSAPrivateWrapper>();
}

std::unique_ptr<RSAPrivateWrapper> KeyManager::load_private_key_from_base64(
    const std::string& private_key_b64) {
    
    std::string private_key_bin = Base64Wrapper::decode(private_key_b64);
    return std::make_unique<RSAPrivateWrapper>(private_key_bin);
}

std::string KeyManager::get_public_key_binary(
    const RSAPrivateWrapper& private_key) {
    
    return private_key.getPublicKey();
}

std::string KeyManager::encode_private_key_to_base64(
    const RSAPrivateWrapper& private_key) {
    
    return Base64Wrapper::encode(private_key.getPrivateKey());
}



