#include "handlers/deletion_handler.h"
#include "protocol/constants.h"
#include "network/protocol_handler.h"
#include "storage/client_storage.h"
#include "ui/menu.h"
#include <iostream>
#include <string>

using namespace Protocol;

void DeletionHandler::handle() {
    // 1. Check if registered
    if (!*is_registered_) {
        Menu::show_error("Not registered. Nothing to delete.");
        return;
    }

    Menu::show_prompt("WARNING: This will delete your account and all data. Are you sure? (y/n): ");
    std::string confirm;
    std::getline(std::cin, confirm);
    if (confirm != "y" && confirm != "Y") {
        Menu::show_info("Operation cancelled.");
        return;
    }

    // 2. Build request using ProtocolHandler
    auto request = ProtocolHandler::build_delete_user_request(my_info_->uuid_bin);

    // 3. Send request
    Menu::show_info("Sending delete request to server...");
    try {
        connection_->send(request);
    } catch (const std::exception& e) {
        Menu::show_error("Network error: " + std::string(e.what()));
        return;
    }

    // 4. Read Response Header
    std::vector<char> response_header;
    try {
        response_header = connection_->receive(RESPONSE_HEADER_SIZE);
    } catch (...) {
        Menu::show_error("Error reading server response.");
        return;
    }

    // Parse header
    auto [r_code, r_size] = ProtocolHandler::parse_response_header(response_header);

    // Read payload if exists (usually error message)
    std::vector<char> r_payload;
    if (r_size > 0) {
        r_payload = connection_->receive(r_size);
    }

    // 5. Process result
    if (r_code == RESPONSE_CODE_DELETE_USER_SUCCESS) {
        Menu::show_success("Server deleted user successfully.");
        
        // Delete local file
        if (ClientStorage::delete_client_data()) {
            Menu::show_success("Deleted local file: " + std::string(MY_INFO_FILE));
        }

        // Reset RAM state
        *is_registered_ = false;
        my_info_->name = "";
        my_info_->uuid_hex = "";
        my_info_->uuid_bin = "";
        my_info_->keys.reset(); // Free RSA keys
        
        Menu::show_success("User deleted successfully from client memory.");
    } 
    else {
        std::string error_msg(r_payload.begin(), r_payload.end());
        Menu::show_error("Server failed to delete user: " + error_msg);
    }
}

