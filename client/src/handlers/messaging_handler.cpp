#include "handlers/messaging_handler.h"
#include "protocol/constants.h"
#include "network/protocol_handler.h"
#include "crypto/encryption.h"
#include "storage/file_manager.h"
#include "ui/menu.h"
#include <iostream>
#include <filesystem>
#include <algorithm>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

using namespace Protocol;

void MessagingHandler::handle_pull_messages() {
    // Check if user is registered
    if (!*is_registered_) {
        Menu::show_error("Not registered.");
        return;
    }

    // Build request using ProtocolHandler
    auto request = ProtocolHandler::build_waiting_messages_request(my_info_->uuid_bin);

    // Send request to server
    Menu::show_info("Checking for messages...");
    connection_->send(request);

    // Read server response Header
    auto response_header = connection_->receive(RESPONSE_HEADER_SIZE);

    // Parse response header
    auto [r_code, total_payload_size] = ProtocolHandler::parse_response_header(response_header);

    // Check validity of response code
    if (r_code != RESPONSE_CODE_PULL_WAITING_MESSAGE) {
        Menu::show_error("Error getting messages.");
        return;
    }

    // Check if there are new messages
    if (total_payload_size == 0) {
        Menu::show_no_messages();
        return;
    }

    Menu::show_messages_header();
    
    // Read all payload at once
    std::vector<char> total_payload;
    if (total_payload_size > 0) {
        total_payload = connection_->receive(total_payload_size);
    }
    
    // Keep track of how many bytes we've processed from the payload
    size_t processed = 0; 

    // Loop until we have processed all the waiting messages one by one
    while (processed < total_payload_size) {
        
        // Extract header for *one* message (25 bytes: FromUUID(16) + MsgID(4) + Type(1) + ContentSize(4) )
        size_t msg_header_size = CLIENT_UUID_SIZE + RESPONSE_MSG_ID_SIZE + RESPONSE_MSG_TYPE_SIZE + RESPONSE_MSG_SIZE;
        if (processed + msg_header_size > total_payload_size) {
            break; // Not enough data
        }
        
        std::vector<char> msg_head(total_payload.begin() + processed, total_payload.begin() + processed + msg_header_size);
        processed += msg_header_size;

        // Extract message header parts 
        std::string from_uuid(msg_head.data(), CLIENT_UUID_SIZE);
        uint32_t msg_id = ntohl(*reinterpret_cast<uint32_t*>(msg_head.data() + CLIENT_UUID_SIZE));
        uint8_t msg_type = msg_head[CLIENT_UUID_SIZE + RESPONSE_MSG_ID_SIZE];
        uint32_t content_size = ntohl(*reinterpret_cast<uint32_t*>(msg_head.data() + CLIENT_UUID_SIZE + RESPONSE_MSG_ID_SIZE + RESPONSE_MSG_TYPE_SIZE));

        // Extract message content
        if (processed + content_size > total_payload_size) {
            break; // Not enough data
        }
        std::vector<char> content(total_payload.begin() + processed, total_payload.begin() + processed + content_size);
        processed += content_size;
        std::string content_str(content.begin(), content.end());

        // Print message to console
        std::string from_name = find_name_by_uuid(from_uuid);

        switch (msg_type) {

            // Case 1 - Request Symmetric Key
            case MSG_TYPE_SYM_KEY_REQUEST:
                Menu::show_message(from_name, "Request for symmetric key", true);
                break;
            // Case 2 - Send Symmetric Key
            case MSG_TYPE_SYM_KEY_SEND:
                try {
                    // Decrypt symmetric key using our private key
                    std::string sym_key = Encryption::decrypt_rsa(*my_info_->keys, content_str);
                    // Save symmetric key in RAM DB for this user
                    (*client_db_)[binary_to_hex_ascii(from_uuid)].symmetric_key = sym_key;
                    Menu::show_success("Symmetric key received.");
                } catch (...) { Menu::show_error("Error decrypting key."); }
                break;
                 
            case MSG_TYPE_TEXT_MESSAGE: // Case 3 - send text Message
            case MSG_TYPE_FILE:         // Case 4 - File Transfer
            {
                // Decrypt content using symmetric key
                std::string sym_key = (*client_db_)[binary_to_hex_ascii(from_uuid)].symmetric_key;

                // Make sure we have symmetric key
                if (sym_key.empty()) {
                    Menu::show_no_key();
                } else {
                    try {
                        // Decrypt the message content using the stored AES key
                        std::string decrypted = Encryption::decrypt_aes(sym_key, content_str.data(), content_str.size());

                        // Print text message to console
                        if (msg_type == MSG_TYPE_TEXT_MESSAGE) {
                            Menu::show_message(from_name, decrypted, true);
                        } else {
                            // Save file to temp directory
                            std::filesystem::path temp_dir = std::filesystem::temp_directory_path();
                            std::filesystem::path file_path = temp_dir / ("msg_" + std::to_string(msg_id) + ".tmp");
                            // Write binary data to temp file
                            FileManager::write_file_binary(file_path.string(), decrypted);
                            Menu::show_file_saved(file_path.string());
                        }
                    } catch (...) { Menu::show_decryption_failed(); }
                }
                break;
            }
        }
        std::cout << "\n\n----<EOM>----\n\n";
    }
}

void MessagingHandler::handle_send_message(const std::string& menu_choice) {
    // Check if user is registered
    if (!*is_registered_) {
        Menu::show_error("Not registered.");
        return;
    }

    // Get target username from user
    Menu::show_prompt("Recipient username: ");
    std::string target_username;
    std::getline(std::cin, target_username);
    if (target_username.empty()) return;

    // Find the targets UUID in our local RAM DB (g_client_db)
    std::string target_uuid_bin = find_uuid_by_name(target_username);
    if (target_uuid_bin.empty()) {
        Menu::show_error("User not found in local client list!");
        return;
    }
    std::string target_hex = binary_to_hex_ascii(target_uuid_bin);

    // Prepare message content based on user choice
    uint8_t msg_type = 0;
    std::string msg_content;

    // Logic for 151: Request Symmetric Key
    if (menu_choice == "151") {
        msg_type = MSG_TYPE_SYM_KEY_REQUEST;
    }
    // Logic for 152: Send Symmetric Key
    else if (menu_choice == "152") {
        msg_type = MSG_TYPE_SYM_KEY_SEND;

        // Check if we have the targets public key
        if ((*client_db_)[target_hex].public_key.empty()) {
            Menu::show_error("You don't have the public key for '" + target_username + "'.");
            return;
        }

        // Generate a new symmetric key (AES key)
        std::string key_bin = Encryption::generate_aes_key();
        
        // Encrypt the symmetric key using the targets public key
        try {
            msg_content = Encryption::encrypt_rsa((*client_db_)[target_hex].public_key, key_bin);
            // Save this symmetric key in our RAM DB for this user
            (*client_db_)[target_hex].symmetric_key = key_bin;
            Menu::show_success("Generated and sent a new symmetric key to " + target_username + ".");
        } catch (...) { return; }
    }
    // Logic for sending messages - 150 (Text) or 153 (File)
    else {
        // Check for symmetric key
        std::string key = (*client_db_)[target_hex].symmetric_key;
        if (key.empty()) {
            Menu::show_error("You don't have a symmetric key for '" + target_username + "'.");
            return;
        }
        
        std::string data_to_encrypt;

        // Text Message (150)
        if (menu_choice == "150") {
            msg_type = MSG_TYPE_TEXT_MESSAGE;
            Menu::show_prompt("Message: ");
            std::getline(std::cin, data_to_encrypt);
        }
        // File Transfer (153) 
        else {
            msg_type = MSG_TYPE_FILE;
            Menu::show_prompt("File path: ");
            std::string file_path;
            std::getline(std::cin, file_path);
            file_path.erase(std::remove(file_path.begin(), file_path.end(), '\"'), file_path.end()); // Remove potential surrounding quotes
            try { data_to_encrypt = FileManager::read_file_binary(file_path); } 
            catch (...) { Menu::show_error("File error!"); return; }
        }

        // Encrypt the data (text or file content)
        try {
            msg_content = Encryption::encrypt_aes(key, data_to_encrypt);
        } catch (...) { return; }
    }

    // Build request using ProtocolHandler
    auto request = ProtocolHandler::build_send_message_request(
        my_info_->uuid_bin, target_uuid_bin, msg_type, msg_content);

    // Send request to server
    Menu::show_info("Sending...");
    connection_->send(request);

    // Read server response Header
    auto res_head = connection_->receive(RESPONSE_HEADER_SIZE);
    
    // Parse response header
    auto [r_code, r_size] = ProtocolHandler::parse_response_header(res_head);

    // Read server response payload
    std::vector<char> res_payload;
    if (r_size > 0) {
        res_payload = connection_->receive(r_size);
    }

    // If everything went well and message was sent
    if (r_code == RESPONSE_CODE_SEND_TEXT_MESSAGE) {
        Menu::show_success("Sent successfully.");
    } 
    // Got error from server
    else {
        std::string error_msg(res_payload.begin(), res_payload.end());
        Menu::show_error("Server responded with an error: " + error_msg);
    }
}

