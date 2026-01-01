#include "MessageUClient.h"
#include "protocol/constants.h"
#include "network/connection.h"
#include "network/protocol_handler.h"
#include "crypto/key_manager.h"
#include "crypto/encryption.h"
#include "storage/file_manager.h"
#include "storage/client_storage.h"
#include <iostream>
#include <filesystem>
#include <algorithm>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>

using namespace Protocol;  // Import protocol constants into current scope


    // Helper functions, not part of MessageUClient class

// Convert binary UUID to ASCII Hex
std::string binary_to_hex_ascii(const std::string& bin_uuid)
{
    std::string hex;
    CryptoPP::StringSource ss(bin_uuid, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hex), true));
    return hex;
}

// Convert ASCII Hex UUID to binary
std::string hex_ascii_to_binary(const std::string& hex)
{
    std::string bin;
    CryptoPP::StringSource ss(hex, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(bin)));
    return bin;
}

    // Implement functions of MessageUClient class

MessageUClient::MessageUClient() : connection_(std::make_unique<Connection>()) {
    // Try to load info on startup
    load_my_info();
}

MessageUClient::~MessageUClient() {
    close();
}

// Set up connection
void MessageUClient::connect() {
    try {
        // Load server info from file
        auto server_info = ClientStorage::load_server_info();
        std::cout << "Connecting to " << server_info.host << ":" << server_info.port << "..." << std::endl;
        connection_->connect(server_info.host, server_info.port);
        std::cout << "Connected successfully.\n";
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("Connection failed: ") + e.what());
    }
}

// Close socket connection
void MessageUClient::close() {
    if (connection_) {
        connection_->close();
    }
}

// Display menu to user
void MessageUClient::show_menu() 
{
    std::cout << "\nMessageU client at your service.\n\n"
              << "110) Register\n"
              << "120) Request for clients list\n"
              << "130) Request for public key\n"
              << "140) Request for waiting messages\n"
              << "150) Send a text message\n"
              << "151) Send a request for symmetric key\n"
              << "152) Send your symmetric key\n"
              << "153) Send a file\n"
              << "154) Delete user\n"
              << "0) Exit client\n"
              << "?\n";
}

// Checks if the my.info file exists
bool MessageUClient::is_user_registered()
{
    return ClientStorage::is_client_registered();
}

// Attempts to load client info from my.info file into RAM
void MessageUClient::load_my_info() {
    auto client_data = ClientStorage::load_client_data();
    if (!client_data) {
        return; // Not registered
    }

    // Load info into RAM
    g_my_info.name = client_data->username;
    g_my_info.uuid_hex = client_data->uuid_hex;
    g_my_info.uuid_bin = hex_ascii_to_binary(client_data->uuid_hex);
    g_my_info.keys = std::move(client_data->private_key);
    
    g_is_registered = true;
    std::cout << "Welcome, " << g_my_info.name << "!" << std::endl;
}

// Searches RAM client DB for a user's binary uuid by their name
std::string MessageUClient::find_uuid_by_name(const std::string& name) {
    // Loop through our global map (g_client_db)
    for (const auto& pair : g_client_db) {
        if (pair.second.username == name) {
            // Return converted UUID from hex ASCII to binary
            return hex_ascii_to_binary(pair.first);
        }
    }
    return ""; // If loop finishes without finding a match, return empty string
}

// Searches RAM client DB for a user's name by their binary UUID
std::string MessageUClient::find_name_by_uuid(const std::string& uuid_bin) {
    std::string hex = binary_to_hex_ascii(uuid_bin);

    // If found uuid in our local DB, return the name
    if (g_client_db.count(hex)) {
        return g_client_db[hex].username;
    }
    // If uuid not in our local DB, check if it's our own uuid
    if (hex == g_my_info.uuid_hex) {
        return g_my_info.name;
    }
    return "Unknown"; // If loop finishes without finding a match return Unknown
}

    // Implementat menu options

// Handles entire registration process of user (input 110/ request code 600)
void MessageUClient::handle_registration()
{
    // Check if my.info file already exists
    if (is_user_registered()) {
        std::cerr << "Error: User already registered!\n";
        return;
    }

    // Get username from user
    std::cout << "Enter username: ";
    std::string username;
    std::getline(std::cin, username);
    if (username.empty()) {
        std::cerr << "Error: Username cannot be empty.\n";
        return;
    }
    if (username.length() > USERNAME_FIXED_SIZE) {
        std::cerr << "Error: Username too long.\n";
        return;
    }

    // Generate new RSA keys - asimmetric key pair
    std::cout << "Generating RSA keys (this may take a moment)...\n";
    g_my_info.keys = KeyManager::generate_rsa_keypair();
    std::string public_key_bin = KeyManager::get_public_key_binary(*g_my_info.keys);
    std::string private_key_b64 = KeyManager::encode_private_key_to_base64(*g_my_info.keys);

    // Build request using ProtocolHandler
    auto request = ProtocolHandler::build_registration_request(username, public_key_bin);

    // Send request to server
    std::cout << "Sending registration request to server..." << std::endl;
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
        
        std::cout << "Registration successful! Your UUID is: " << uuid_hex << std::endl;

        // Save users info to my.info file
        ClientStorage::save_client_data(username, uuid_hex, private_key_b64);

        // Load info into RAM for current session
        load_my_info();
    } 
    // Got error from server
    else {
        std::string error_msg(response_payload.begin(), response_payload.end());
        std::cerr << "Server responded with an error: " << error_msg << std::endl;
    }
}

// Handles reques for client list (input 120/ request code 601)
void MessageUClient::handle_client_list()
{
    // Check if user is registered
    if (!g_is_registered) {
        std::cerr << "Error: Not registered.\n";
        return;
    }

    // Build request using ProtocolHandler
    auto request = ProtocolHandler::build_client_list_request(g_my_info.uuid_bin);

    // Send request to server
    std::cout << "Requesting client list from server..." << std::endl;
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

        std::cout << "\n--- Registered Clients ---" << std::endl;
        g_client_db.clear(); // Clear the old list
        
        // Each entry is 16 (UUID) + 255 (Username) = 271 bytes
        const size_t entry_size = CLIENT_UUID_SIZE + USERNAME_FIXED_SIZE;

        // Loop through payload, one client at a time
        for (size_t i = 0; i < r_size; i += entry_size) {
            // Extract UUID and username from payload
            std::string uuid_bin(r_payload.data() + i, CLIENT_UUID_SIZE);
            std::string name_raw(r_payload.data() + i + CLIENT_UUID_SIZE, USERNAME_FIXED_SIZE);
            
            std::string name = name_raw.c_str(); // Trim nulls
            std::string uuid_hex = binary_to_hex_ascii(uuid_bin);
            
            // Print to screen
            std::cout << "Name: " << name << "\nUUID: " << uuid_hex << "\n---\n";
            g_client_db[uuid_hex].username = name;
        }
    } 
    // Got error from server
    else {
        std::string error_msg(r_payload.begin(), r_payload.end());
        std::cerr << "Server responded with an error: " << error_msg << "\n";
    }
}

//Handles requesting another users public key (input 130/ request code 602)
void MessageUClient::handle_request_public_key()
{
    // Check if user is registered
    if (!g_is_registered) { std::cerr << "Error: Not registered.\n"; return; }

    // Get target username from user
    std::cout << "Enter username to get public key: ";
    std::string target_username;
    std::getline(std::cin, target_username);
    if (target_username.empty()) return;

    // Find the targets UUID in local RAM DB (g_client_db)
    std::string target_uuid_bin = find_uuid_by_name(target_username);
    if (target_uuid_bin.empty()) {
        std::cerr << "User not found in local list.\n";
        return;
    }

    // Build request using ProtocolHandler
    auto request = ProtocolHandler::build_public_key_request(g_my_info.uuid_bin, target_uuid_bin);

    // Send request to server
    std::cout << "Requesting public key...\n";
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
        
        g_client_db[hex].public_key = pub_key;
        std::cout << "Public key received for " << g_client_db[hex].username << "\n";
    } 
    // Got error from server
    else {
        std::string error_msg(response_payload.begin(), response_payload.end());
        std::cerr << "Server responded with an error: " << error_msg << std::endl;
    }
}

// Handles pulling waiting messages from  server (input 140/ request code 604)
void MessageUClient::handle_pull_messages()
{
    // Check if user is registered
    if (!g_is_registered) { std::cerr << "Error: Not registered.\n"; return; }

    // Build request using ProtocolHandler
    auto request = ProtocolHandler::build_waiting_messages_request(g_my_info.uuid_bin);

    // Send request to server
    std::cout << "Checking for messages...\n";
    connection_->send(request);

    // Read server response Header
    auto response_header = connection_->receive(RESPONSE_HEADER_SIZE);

    // Parse response header
    auto [r_code, total_payload_size] = ProtocolHandler::parse_response_header(response_header);

    // Check validity of response code
    if (r_code != RESPONSE_CODE_PULL_WAITING_MESSAGE) {
        std::cout << "Error getting messages.\n";
        return;
    }

    // Check if there are new messages
    if (total_payload_size == 0) {
        std::cout << "No new messages.\n";
        return;
    }

    std::cout << "\n--- Messages ---\n";
    
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
        std::cout << "From: " << find_name_by_uuid(from_uuid) << "\nContent:\n";

        switch (msg_type) {

            // Case 1 - Request Symmetric Key
            case MSG_TYPE_SYM_KEY_REQUEST:
                std::cout << "Request for symmetric key\n";
                break;
            // Case 2 - Send Symmetric Key
            case MSG_TYPE_SYM_KEY_SEND:
                try {
                    // Decrypt symmetric key using our private key
                    std::string sym_key = Encryption::decrypt_rsa(*g_my_info.keys, content_str);
                    // Save symmetric key in RAM DB for this user
                    g_client_db[binary_to_hex_ascii(from_uuid)].symmetric_key = sym_key;
                    std::cout << "Symmetric key received.\n";
                } catch (...) { std::cout << "Error decrypting key.\n"; }
                break;
                 
            case MSG_TYPE_TEXT_MESSAGE: // Case 3 - send text Message
            case MSG_TYPE_FILE:         // Case 4 - File Transfer
            {
                // Decrypt content using symmetric key
                std::string sym_key = g_client_db[binary_to_hex_ascii(from_uuid)].symmetric_key;

                // Make sure we have symmetric key
                if (sym_key.empty()) std::cout << "Can't decrypt (no key)\n";
                else {
                    try {
                        // Decrypt the message content using the stored AES key
                        std::string decrypted = Encryption::decrypt_aes(sym_key, content_str.data(), content_str.size());

                        // Print text message to console
                        if (msg_type == MSG_TYPE_TEXT_MESSAGE) std::cout << decrypted << "\n";

                        // Save file to temp directory
                        else {
                            std::filesystem::path temp_dir = std::filesystem::temp_directory_path();
                            std::filesystem::path file_path = temp_dir / ("msg_" + std::to_string(msg_id) + ".tmp");
                            // Write binary data to temp file
                            FileManager::write_file_binary(file_path.string(), decrypted);
                            std::cout << "File saved in path: " << file_path << "\n";
                        }
                    } catch (...) { std::cout << "Decryption failed.\n"; }
                }
                break;
            }
        }
        std::cout << "\n";
        std::cout << "\n";
        std::cout << "----<EOM>----\n\n";
    }
}

// Handles users choice and calls the appropriate function (inpput 150, 151, 152, 153 / request code 603)
void MessageUClient::handle_send_message_options(const std::string& menu_choice)
{
    // Check if user is registered
    if (!g_is_registered) { std::cerr << "Error: Not registered.\n"; return; }

    // Get target username from user
    std::cout << "Recipient username: ";
    std::string target_username;
    std::getline(std::cin, target_username);
    if (target_username.empty()) return;

    // Find the targets UUID in our local RAM DB (g_client_db)
    std::string target_uuid_bin = find_uuid_by_name(target_username);
    if (target_uuid_bin.empty()) {
        std::cerr << "User not found in local client list!\n";
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
        if (g_client_db[target_hex].public_key.empty()) {
            std::cerr << "Error: You don't have the public key for '" << target_username << "'.\n";
            return;
        }

        // Generate a new symmetric key (AES key)
        std::string key_bin = Encryption::generate_aes_key();
        
        // Encrypt the symmetric key using the targets public key
        try {
            msg_content = Encryption::encrypt_rsa(g_client_db[target_hex].public_key, key_bin);
            // Save this symmetric key in our RAM DB for this user
            g_client_db[target_hex].symmetric_key = key_bin;
            std::cout << "Generated and sent a new symmetric key to " << target_username << ".\n";
        } catch (...) { return; }
    }
    // Logic for sending messages - 150 (Text) or 153 (File)
    else {
        // Check for symmetric key
        std::string key = g_client_db[target_hex].symmetric_key;
        if (key.empty()) { std::cerr << "Error: You don't have a symmetric key for '" << target_username << "'.\n";
            return;
     }
        
        std::string data_to_encrypt;

        // Text Message (150)
        if (menu_choice == "150") {
            msg_type = MSG_TYPE_TEXT_MESSAGE;
            std::cout << "Message: ";
            std::getline(std::cin, data_to_encrypt);
        }
        // File Transfer (153) 
        else {
            msg_type = MSG_TYPE_FILE;
            std::cout << "File path: ";
            std::string file_path;
            std::getline(std::cin, file_path);
            file_path.erase(std::remove(file_path.begin(), file_path.end(), '\"'), file_path.end()); // Remove potential surrounding quotes
            try { data_to_encrypt = FileManager::read_file_binary(file_path); } 
            catch (...) { std::cerr << "File error! \n"; return; }
        }

        // Encrypt the data (text or file content)
        try {
            msg_content = Encryption::encrypt_aes(key, data_to_encrypt);
        } catch (...) { return; }
    }

    // Build request using ProtocolHandler
    auto request = ProtocolHandler::build_send_message_request(
        g_my_info.uuid_bin, target_uuid_bin, msg_type, msg_content);

    // Send request to server
    std::cout << "Sending...\n";
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
        std::cout << "Sent successfully.\n";
    } 
    // Got error from server
    else {
        std::string error_msg(res_payload.begin(), res_payload.end());
        std::cerr << "Server responded with an error: " << error_msg << std::endl;
    }
}

// Handles deleting user from server and client (input 154 / request code 605)
void MessageUClient::handle_delete_user()
{
    // 1. Check if registered
    if (!g_is_registered) {
        std::cerr << "Error: Not registered. Nothing to delete.\n";
        return;
    }

    std::cout << "WARNING: This will delete your account and all data. Are you sure? (y/n): ";
    std::string confirm;
    std::getline(std::cin, confirm);
    if (confirm != "y" && confirm != "Y") {
        std::cout << "Operation cancelled.\n";
        return;
    }

    // 2. Build request using ProtocolHandler
    auto request = ProtocolHandler::build_delete_user_request(g_my_info.uuid_bin);

    // 3. Send request
    std::cout << "Sending delete request to server...\n";
    try {
        connection_->send(request);
    } catch (const std::exception& e) {
        std::cerr << "Network error: " << e.what() << "\n";
        return;
    }

    // 4. Read Response Header
    std::vector<char> response_header;
    try {
        response_header = connection_->receive(RESPONSE_HEADER_SIZE);
    } catch (...) {
        std::cerr << "Error reading server response.\n";
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
        std::cout << "Server deleted user successfully.\n";
        
        // Delete local file
        if (ClientStorage::delete_client_data()) {
            std::cout << "Deleted local file: " << MY_INFO_FILE << "\n";
        }

        // Reset RAM state
        g_is_registered = false;
        g_my_info.name = "";
        g_my_info.uuid_hex = "";
        g_my_info.uuid_bin = "";
        g_my_info.keys.reset(); // Free RSA keys
        
        std::cout << "User deleted successfully from client memory.\n";
    } 
    else {
        std::string error_msg(r_payload.begin(), r_payload.end());
        std::cerr << "Server failed to delete user: " << error_msg << "\n";
    }
}

