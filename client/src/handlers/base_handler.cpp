#include "handlers/base_handler.h"
#include "MessageUClient.h"
#include "protocol/constants.h"
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>

BaseHandler::BaseHandler(
    Connection* connection,
    MessageUClient::MyInfo* my_info,
    bool* is_registered,
    std::map<std::string, ClientInfo>* client_db
) : connection_(connection), my_info_(my_info), is_registered_(is_registered), client_db_(client_db) {
}

std::string BaseHandler::find_uuid_by_name(const std::string& name) {
    // Loop through our global map (g_client_db)
    for (const auto& pair : *client_db_) {
        if (pair.second.username == name) {
            // Return converted UUID from hex ASCII to binary
            return hex_ascii_to_binary(pair.first);
        }
    }
    return ""; // If loop finishes without finding a match, return empty string
}

std::string BaseHandler::find_name_by_uuid(const std::string& uuid_bin) {
    std::string hex = binary_to_hex_ascii(uuid_bin);

    // If found uuid in our local DB, return the name
    if (client_db_->count(hex)) {
        return (*client_db_)[hex].username;
    }
    // If uuid not in our local DB, check if it's our own uuid
    if (hex == my_info_->uuid_hex) {
        return my_info_->name;
    }
    return "Unknown"; // If loop finishes without finding a match return Unknown
}

std::string BaseHandler::binary_to_hex_ascii(const std::string& bin_uuid) {
    std::string hex;
    CryptoPP::StringSource ss(bin_uuid, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hex), true));
    return hex;
}

std::string BaseHandler::hex_ascii_to_binary(const std::string& hex) {
    std::string bin;
    CryptoPP::StringSource ss(hex, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(bin)));
    return bin;
}

