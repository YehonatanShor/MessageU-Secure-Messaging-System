#include "handlers/client_list_handler.h"
#include "protocol/constants.h"
#include "network/protocol_handler.h"
#include "ui/menu.h"
#include <vector>
#include <utility>

using namespace Protocol;

void ClientListHandler::handle() {
    // Check if user is registered
    if (!*is_registered_) {
        Menu::show_error("Not registered.");
        return;
    }

    // Build request using ProtocolHandler
    auto request = ProtocolHandler::build_client_list_request(my_info_->uuid_bin);

    // Send request to server
    Menu::show_info("Requesting client list from server...");
    connection_->send(request);

    // Read server response Header
    auto response_header = connection_->receive(RESPONSE_HEADER_SIZE);

    // Parse response header
    auto [r_code, r_size] = ProtocolHandler::parse_response_header(response_header);
    
    // Read response payload
    std::vector<char> r_payload;
    if (r_size > 0) {
        r_payload = connection_->receive(r_size);
    }

    // Process response payload
    if (r_code == RESPONSE_CODE_DISPLAYING_CLIENTS_LIST) {
        client_db_->clear(); // Clear the old list
        
        // Each entry is 16 (UUID) + 255 (Username) = 271 bytes
        const size_t entry_size = CLIENT_UUID_SIZE + USERNAME_FIXED_SIZE;

        std::vector<std::pair<std::string, std::string>> clients;
        
        // Loop through payload, one client at a time
        for (size_t i = 0; i < r_size; i += entry_size) {
            // Extract UUID and username from payload
            std::string uuid_bin(r_payload.data() + i, CLIENT_UUID_SIZE);
            std::string name_raw(r_payload.data() + i + CLIENT_UUID_SIZE, USERNAME_FIXED_SIZE);
            
            std::string name = name_raw.c_str(); // Trim nulls
            std::string uuid_hex = binary_to_hex_ascii(uuid_bin);
            
            clients.push_back({name, uuid_hex});
            (*client_db_)[uuid_hex].username = name;
        }
        
        Menu::show_client_list(clients);
    } 
    // Got error from server
    else {
        std::string error_msg(r_payload.begin(), r_payload.end());
        Menu::show_error("Server responded with an error: " + error_msg);
    }
}

