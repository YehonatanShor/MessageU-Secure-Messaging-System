#include "handlers/public_key_handler.h"
#include "protocol/constants.h"
#include "network/protocol_handler.h"
#include "ui/menu.h"
#include <iostream>
#include <string>

using namespace Protocol;

void PublicKeyHandler::handle() {
    // Check if user is registered
    if (!*is_registered_) {
        Menu::show_error("Not registered.");
        return;
    }

    // Get target username from user
    Menu::show_prompt("Enter username to get public key: ");
    std::string target_username;
    std::getline(std::cin, target_username);
    if (target_username.empty()) return;

    // Find the targets UUID in local RAM DB (g_client_db)
    std::string target_uuid_bin = find_uuid_by_name(target_username);
    if (target_uuid_bin.empty()) {
        Menu::show_error("User not found in local list.");
        return;
    }

    // Build request using ProtocolHandler
    auto request = ProtocolHandler::build_public_key_request(my_info_->uuid_bin, target_uuid_bin);

    // Send request to server
    Menu::show_info("Requesting public key...");
    connection_->send(request);

    // Read server response Header
    auto response_header = connection_->receive(RESPONSE_HEADER_SIZE);

    // Parse response header
    auto [r_code, r_size] = ProtocolHandler::parse_response_header(response_header);

    // Read server response payload
    std::vector<char> response_payload;
    if (r_size > 0) {
        response_payload = connection_->receive(r_size);
    }

    // Process response payload
    if (r_code == RESPONSE_CODE_SEND_PUBLIC_KEY) {
        // Extract UUID and public key from payload
        std::string uuid_bin(response_payload.data(), CLIENT_UUID_SIZE);
        std::string pub_key(response_payload.data() + CLIENT_UUID_SIZE, PUBLIC_KEY_FIXED_SIZE);
        std::string hex = binary_to_hex_ascii(uuid_bin);
        
        (*client_db_)[hex].public_key = pub_key;
        Menu::show_success("Public key received for " + (*client_db_)[hex].username);
    } 
    // Got error from server
    else {
        std::string error_msg(response_payload.begin(), response_payload.end());
        Menu::show_error("Server responded with an error: " + error_msg);
    }
}

