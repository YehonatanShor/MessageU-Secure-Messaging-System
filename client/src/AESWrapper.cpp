#include "AESWrapper.h"
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <stdexcept>
#include <immintrin.h>	// _rdrand32_step

// Generates a random key of specified length (16 bytes) using RDRAND 
unsigned char* AESWrapper::GenerateKey(unsigned char* buffer, unsigned int length)
{
    CryptoPP::AutoSeededRandomPool rng; // create a secure random number generator
    rng.GenerateBlock(buffer, length); // fill the buffer with random bytes
    return buffer;
}

// Default constructor that generates a random key
AESWrapper::AESWrapper()
{
	GenerateKey(_key, DEFAULT_KEYLENGTH);
}

// Constructor that accepts a user-provided key
AESWrapper::AESWrapper(const unsigned char* key, unsigned int length)
{
	if (length != DEFAULT_KEYLENGTH)
		throw std::length_error("key length must be 16 bytes");
	memcpy_s(_key, DEFAULT_KEYLENGTH, key, length);
}

AESWrapper::~AESWrapper()
{
}

// Getter for the key
const unsigned char* AESWrapper::getKey() const 
{ 
	return _key; 
}

// Encrypts plaintext of given length and returns ciphertext
std::string AESWrapper::encrypt(const char* plain, unsigned int length)
{
    // Create random IV
    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(iv, sizeof(iv));

    std::string ciphertext;

    try {
		// Setting AES encryption in CBC mode - key and random IV
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption e;
        e.SetKeyWithIV(_key, DEFAULT_KEYLENGTH, iv);

        // Performing encryption
        CryptoPP::StringSource ss(reinterpret_cast<const CryptoPP::byte*>(plain), length, true, 
            new CryptoPP::StreamTransformationFilter(e,
                new CryptoPP::StringSink(ciphertext)
            )
        );
    }
    catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("AES Encrypt failed: " + std::string(e.what()));
    }

	// Concatenating IV with Ciphertext and returning the result
    std::string result;
    result.append(reinterpret_cast<const char*>(iv), sizeof(iv));
    result.append(ciphertext);

    return result;
}

// Decrypts ciphertext of given length and returns plaintext
std::string AESWrapper::decrypt(const char* encrypted, unsigned int length)
{
    // Validation check: the message must be at least as long as the IV
    if (length < CryptoPP::AES::BLOCKSIZE) {
        throw std::runtime_error("Error: Ciphertext too short to contain IV");
    }

    // Extracting IV from first 16 bytes
    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
    std::memcpy(iv, encrypted, CryptoPP::AES::BLOCKSIZE);

    // Extracting the ciphertext (everything after the IV)
    const char* ciphertext_start = encrypted + CryptoPP::AES::BLOCKSIZE;
    unsigned int ciphertext_length = length - CryptoPP::AES::BLOCKSIZE;

    std::string decrypted;

    try {
        // Setting up decryption with the key and extracted IV
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption d;
        d.SetKeyWithIV(_key, DEFAULT_KEYLENGTH, iv);

        // Performing decryption
        CryptoPP::StringSource ss(reinterpret_cast<const CryptoPP::byte*>(ciphertext_start), ciphertext_length, true, 
            new CryptoPP::StreamTransformationFilter(d,
                new CryptoPP::StringSink(decrypted)
            )
        );
    }
    catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("AES Decrypt failed: " + std::string(e.what()));
    }

    return decrypted;
}