#include "handlers/registration_handler.h"
#include "protocol/constants.h"
#include "network/protocol_handler.h"
#include "crypto/key_manager.h"
#include "storage/client_storage.h"
#include "ui/menu.h"
#include <iostream>
#include <string>

using namespace Protocol;

void RegistrationHandler::handle(std::function<bool()> is_user_registered_func, std::function<void()> load_my_info_func) {
    // Check if my.info file already exists
    if (is_user_registered_func()) {
        Menu::show_error("User already registered!");
        return;
    }

    // Get username from user
    Menu::show_prompt("Enter username: ");
    std::string username;
    std::getline(std::cin, username);
    if (username.empty()) {
        Menu::show_error("Username cannot be empty.");
        return;
    }
    if (username.length() > USERNAME_FIXED_SIZE) {
        Menu::show_error("Username too long.");
        return;
    }

    // Generate new RSA keys - asimmetric key pair
    Menu::show_info("Generating RSA keys (this may take a moment)...");
    my_info_->keys = KeyManager::generate_rsa_keypair();
    std::string public_key_bin = KeyManager::get_public_key_binary(*my_info_->keys);
    std::string private_key_b64 = KeyManager::encode_private_key_to_base64(*my_info_->keys);

    // Build request using ProtocolHandler
    auto request = ProtocolHandler::build_registration_request(username, public_key_bin);

    // Send request to server
    Menu::show_info("Sending registration request to server...");
    connection_->send(request);

    // Read server response Header
    auto response_header = connection_->receive(RESPONSE_HEADER_SIZE);

    // Parse response header
    auto [response_code, response_size] = ProtocolHandler::parse_response_header(response_header);

    // Read server response payload
    std::vector<char> response_payload;
    if (response_size > 0) {
        response_payload = connection_->receive(response_size);
    }

    // Process response
    if (response_code == RESPONSE_CODE_REGISTER_SUCCESS) {
        // Parse registration response
        std::string uuid_bin = ProtocolHandler::parse_registration_response(response_payload);
        // Convert binary UUID to ASCII Hex
        std::string uuid_hex = binary_to_hex_ascii(uuid_bin);
        
        Menu::show_success("Registration successful! Your UUID is: " + uuid_hex);

        // Save users info to my.info file
        ClientStorage::save_client_data(username, uuid_hex, private_key_b64);

        // Load info into RAM for current session
        load_my_info_func();
    } 
    // Got error from server
    else {
        std::string error_msg(response_payload.begin(), response_payload.end());
        Menu::show_error("Server responded with an error: " + error_msg);
    }
}

