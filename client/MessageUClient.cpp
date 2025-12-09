#include "MessageUClient.h"
#include "Base64Wrapper.h"
#include "AESWrapper.h"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>

#if defined(_WIN32)
#include <winsock2.h> // For htonl, ntohl
#endif

// --- Configuration File ---
const std::string MY_INFO_FILE = "my.info";
const std::string SERVER_INFO_FILE = "server.info";

// --- Protocol Constants ---
const size_t CLIENT_VERSION_SIZE = 1;
const size_t CLIENT_UUID_SIZE = 16;
const size_t REQUEST_CODE_SIZE = 2;
const size_t REQUEST_PAYLOAD_SIZE = 4;
const size_t USERNAME_FIXED_SIZE = 255;
const size_t PUBLIC_KEY_FIXED_SIZE = 160;
const size_t REQUEST_HEADER_SIZE = 16 + 1 + 2 + 4;

// Request Codes
const uint8_t CLIENT_VERSION = 2;
const uint16_t REQUEST_CODE_REGISTER = 600;
const uint16_t REQUEST_CODE_CLIENTS_LIST = 601;
const uint16_t REQUEST_CODE_PUBLIC_KEY = 602;
const uint16_t REQUEST_CODE_SEND_MESSAGE = 603;
const uint16_t REQUEST_CODE_WAITING_MESSAGES = 604;
const uint16_t REQUEST_CODE_DELETE_USER = 605;

// Response Codes
const uint16_t RESPONSE_CODE_REGISTER_SUCCESS = 2100;
const uint16_t RESPONSE_CODE_DISPLAYING_CLIENTS_LIST = 2101;
const uint16_t RESPONSE_CODE_SEND_PUBLIC_KEY = 2102;
const uint16_t RESPONSE_CODE_SEND_TEXT_MESSAGE = 2103;
const uint16_t RESPONSE_CODE_PULL_WAITING_MESSAGE = 2104;
const uint16_t RESPONSE_CODE_DELETE_USER_SUCCESS = 2105;
const uint16_t RESPONSE_CODE_GENERAL_ERROR = 9000;

// Server Header Sizes
const size_t SERVER_VERSION_SIZE = 1;
const size_t RESPONSE_CODE_SIZE = 2;
const size_t RESPONSE_PAYLOAD_SIZE = 4;
const size_t RESPONSE_HEADER_SIZE = 1 + 2 + 4; 
const size_t RESPONSE_MSG_ID_SIZE = 4; 
const size_t RESPONSE_MSG_TYPE_SIZE = 1;
const size_t RESPONSE_MSG_SIZE = 4; 

// Message Types
const uint8_t MSG_TYPE_SYM_KEY_REQUEST = 1;
const uint8_t MSG_TYPE_SYM_KEY_SEND = 2;
const uint8_t MSG_TYPE_TEXT_MESSAGE = 3;
const uint8_t MSG_TYPE_FILE = 4;

// Protocol Strings, part of menu options
const std::string SEND_SYMMETRIC_KEY_REQUEST_STR = "151";
const std::string SEND_SYMMETRIC_KEY_STR = "152";
const std::string SEND_TEXT_MESSAGE_STR = "150";
const std::string SEND_FILE_STR = "153";


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

// Reads an entire file into a string (binary safe)
std::string read_file_content(const std::string& filepath)
{
    std::ifstream file(filepath, std::ios::binary); // Open in binary
    if (!file) {
        throw std::runtime_error("Cannot open file: " + filepath);
    }
    // Read the whole file into a string
    return std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

    // Implement functions of MessageUClient class

MessageUClient::MessageUClient() : p_socket(p_io_context), p_resolver(p_io_context) {
    // Try to load info on startup
    load_my_info();
}

MessageUClient::~MessageUClient() {
    close();
}

// Set up Boost.Asio connection
void MessageUClient::connect() {
    try {
        // Load server info from file
        auto server_info = load_server_info();
        std::cout << "Connecting to " << server_info.first << ":" << server_info.second << "..." << std::endl;
        boost::asio::connect(p_socket, p_resolver.resolve(server_info.first, server_info.second));
        std::cout << "Connected successfully.\n";
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("Connection failed: ") + e.what());
    }
}

// Close socket connection
void MessageUClient::close() {
    if (p_socket.is_open()) p_socket.close();
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
    std::ifstream f(MY_INFO_FILE);
    return f.good();
}

// Attempts to load client info from my.info file into RAM
void MessageUClient::load_my_info() {
    std::ifstream f(MY_INFO_FILE);
    if (!f.good()) return; // Not registered

    std::string name, uuid_hex, private_key_b64, line;
    std::getline(f, name);
    std::getline(f, uuid_hex);

    // Read the rest of the file (potentially multi-line) for the Base64 key
    while (std::getline(f, line)) {
        private_key_b64 += line;
    }
    f.close();

    // Check if any fields are empty
    if (name.empty() || uuid_hex.empty() || private_key_b64.empty()) {
        std::cerr << "Error: " << MY_INFO_FILE << " is corrupt or incomplete.\n";
        return;
    }

    // Load info into RAM
    g_my_info.name = name;
    g_my_info.uuid_hex = uuid_hex;
    g_my_info.uuid_bin = hex_ascii_to_binary(uuid_hex);
    // Using unique_ptr handles memory automatically
    g_my_info.keys = std::make_unique<RSAPrivateWrapper>(Base64Wrapper::decode(private_key_b64));
    
    g_is_registered = true;
    std::cout << "Welcome, " << g_my_info.name << "!" << std::endl;
}

// Loads server host and port from server.info file
std::pair<std::string, std::string> MessageUClient::load_server_info() {
    // check if file exists and open it
    std::ifstream f(SERVER_INFO_FILE);
    if (!f.is_open()) {
        throw std::runtime_error("Error: Could not open " + SERVER_INFO_FILE);
    }

    // read first line
    std::string line;
    if (std::getline(f, line)) {
        size_t colon_pos = line.find(':'); // Find the colon separator
        
        // check if the content of file is valid
        if (colon_pos == std::string::npos || colon_pos == 0 || colon_pos == line.length() - 1) {
            throw std::runtime_error("Invalid format in " + SERVER_INFO_FILE);
        }
        // Returns host and port
        return { line.substr(0, colon_pos), line.substr(colon_pos + 1) }; 
    }
    throw std::runtime_error(SERVER_INFO_FILE + " is empty.");
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
    g_my_info.keys = std::make_unique<RSAPrivateWrapper>();
    std::string public_key_bin = g_my_info.keys->getPublicKey();
    std::string private_key_b64 = Base64Wrapper::encode(g_my_info.keys->getPrivateKey());

    // Build complete request (Header + Payload) 
    std::vector<char> complete_request; // Allocated on heap for dynamic size
    uint32_t request_payload_size = USERNAME_FIXED_SIZE + PUBLIC_KEY_FIXED_SIZE;
    complete_request.reserve(REQUEST_HEADER_SIZE + request_payload_size); // Pre-allocate memory

    // Build header parts
    uint8_t client_version = CLIENT_VERSION;
    uint16_t request_code = htons(REQUEST_CODE_REGISTER);
    uint32_t reg_payload_size = htonl(request_payload_size);

    // Add header parts to complete_request
    complete_request.insert(complete_request.end(), CLIENT_UUID_SIZE, 0); // Add 16 null bytes as a placeholder for the ClientID
    complete_request.insert(complete_request.end(), (char*)&client_version, (char*)&client_version + sizeof(client_version));
    complete_request.insert(complete_request.end(), (char*)&request_code, (char*)&request_code + sizeof(request_code));
    complete_request.insert(complete_request.end(), (char*)&reg_payload_size, (char*)&reg_payload_size + sizeof(reg_payload_size));
    
    // Build payload parts
    char username_payload[USERNAME_FIXED_SIZE] = {0}; // Allocate on stack for efficiency, fills with 255 null bytes
    std::memcpy(username_payload, username.c_str(), username.length());

    char public_key_payload[PUBLIC_KEY_FIXED_SIZE] = {0}; // Allocate on stack for efficiency, fills with 160 null bytes
    size_t key_copy_size = std::min((size_t)PUBLIC_KEY_FIXED_SIZE, public_key_bin.length());
    std::memcpy(public_key_payload, public_key_bin.c_str(), key_copy_size);

    // Add payload parts to complete_request
    complete_request.insert(complete_request.end(), username_payload, username_payload + USERNAME_FIXED_SIZE);
    complete_request.insert(complete_request.end(), public_key_payload, public_key_payload + PUBLIC_KEY_FIXED_SIZE);

    // Send request to server
    std::cout << "Sending registration request to server..." << std::endl;
    boost::asio::write(p_socket, boost::asio::buffer(complete_request));

    // Read server response Header
    char response_header[RESPONSE_HEADER_SIZE];
    boost::asio::read(p_socket, boost::asio::buffer(response_header, RESPONSE_HEADER_SIZE));

    // Extract response code and payload size from header
    uint16_t response_code;
    uint32_t response_size;
    std::memcpy(&response_code, response_header + SERVER_VERSION_SIZE, RESPONSE_CODE_SIZE);
    std::memcpy(&response_size, response_header + SERVER_VERSION_SIZE + RESPONSE_CODE_SIZE, RESPONSE_PAYLOAD_SIZE);
    response_code = ntohs(response_code);
    response_size = ntohl(response_size);

    // 8. Read server response payload
    std::vector<char> response_payload(response_size);
    if (response_size > 0) {
        boost::asio::read(p_socket, boost::asio::buffer(response_payload));
    }

    // Process response
    if (response_code == RESPONSE_CODE_REGISTER_SUCCESS) {

        // Validate payload size
        if (response_size != CLIENT_UUID_SIZE) {
            std::cerr << "Error: Invalid UUID size.\n";
            return;
        }

        // Extract UUID from payload
        std::string uuid_bin(response_payload.begin(), response_payload.end());
        // Convert binary UUID to ASCII Hex
        std::string uuid_hex = binary_to_hex_ascii(uuid_bin);
        
        std::cout << "Registration successful! Your UUID is: " << uuid_hex << std::endl;

        // Save users info to my.info file
        std::ofstream outfile(MY_INFO_FILE);
        outfile << username << "\n" << uuid_hex << "\n" << private_key_b64;
        outfile.close();

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

    // Build request header (23 bytes), no payload
    char request_header[REQUEST_HEADER_SIZE];

    // Build header parts
    uint16_t request_code = htons(REQUEST_CODE_CLIENTS_LIST);
    uint32_t request_payload_size = htonl(0);

    //Add header parts to request_header
    std::memcpy(request_header, g_my_info.uuid_bin.data(), CLIENT_UUID_SIZE); // insert UUID - 16 bytes
    request_header[CLIENT_UUID_SIZE] = CLIENT_VERSION; // insert clients Version - 1 byte
    std::memcpy(request_header + CLIENT_UUID_SIZE + CLIENT_VERSION_SIZE, &request_code, sizeof(request_code)); // insert Code - 2 bytes
    std::memcpy(request_header + CLIENT_UUID_SIZE + CLIENT_VERSION_SIZE + REQUEST_CODE_SIZE, &request_payload_size, sizeof(request_payload_size)); // insert Payload Size - 4 bytes

    // Send request to server
    std::cout << "Requesting client list from server..." << std::endl;
    boost::asio::write(p_socket, boost::asio::buffer(request_header, REQUEST_HEADER_SIZE));

    // Read server response Header
    char response_header[RESPONSE_HEADER_SIZE];
    boost::asio::read(p_socket, boost::asio::buffer(response_header, RESPONSE_HEADER_SIZE));

    // Extract response hcode and payload size from header
    uint16_t r_code;
    uint32_t r_size;
    std::memcpy(&r_code, response_header + SERVER_VERSION_SIZE, RESPONSE_CODE_SIZE);
    std::memcpy(&r_size, response_header + SERVER_VERSION_SIZE + RESPONSE_CODE_SIZE, RESPONSE_PAYLOAD_SIZE);
    r_code = ntohs(r_code);
    r_size = ntohl(r_size);
    
    // Read response payload
    std::vector<char> r_payload(r_size);
    if (r_size > 0) boost::asio::read(p_socket, boost::asio::buffer(r_payload));

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

    // Build complete request (Header + Payload)
    std::vector<char> request;
    request.reserve(REQUEST_HEADER_SIZE + target_uuid_bin.length());
    
    // Build header
    uint8_t client_version = CLIENT_VERSION;
    uint16_t request_code = htons(REQUEST_CODE_PUBLIC_KEY);
    uint32_t req_payload_size = htonl(target_uuid_bin.length()); // Payload is the 16-byte UUID

    // Add header parts
    request.insert(request.end(), g_my_info.uuid_bin.begin(), g_my_info.uuid_bin.end()); // Our UUID
    request.insert(request.end(), (char*)&client_version, (char*)&client_version + sizeof(client_version));
    request.insert(request.end(), (char*)&request_code, (char*)&request_code + sizeof(request_code));
    request.insert(request.end(), (char*)&req_payload_size, (char*)&req_payload_size + sizeof(req_payload_size));
    
    // Add payload (targets UUID)
    request.insert(request.end(), target_uuid_bin.begin(), target_uuid_bin.end());

    // Send request to server
    std::cout << "Requesting public key...\n";
    boost::asio::write(p_socket, boost::asio::buffer(request));

    // Read server response Header
    char response_header[RESPONSE_HEADER_SIZE];
    boost::asio::read(p_socket, boost::asio::buffer(response_header, RESPONSE_HEADER_SIZE));

    // Extract response code and payload size from header
    uint16_t r_code;
    uint32_t r_size;
    std::memcpy(&r_code, response_header + SERVER_VERSION_SIZE, RESPONSE_CODE_SIZE);
    std::memcpy(&r_size, response_header + SERVER_VERSION_SIZE + RESPONSE_CODE_SIZE, RESPONSE_PAYLOAD_SIZE);
    r_code = ntohs(r_code);
    r_size = ntohl(r_size);

    // Read server response payload
    std::vector<char> response_payload(r_size);
    if (r_size > 0) boost::asio::read(p_socket, boost::asio::buffer(response_payload));

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

    // Build request header (21 bytes), no payload
    char request_header[REQUEST_HEADER_SIZE];

    // Build header parts
    uint16_t client_code = htons(REQUEST_CODE_WAITING_MESSAGES);
    uint32_t request_payload_size = htonl(0);

    // Add header parts to request_header
    std::memcpy(request_header, g_my_info.uuid_bin.data(), CLIENT_UUID_SIZE); // insert ClientID - 16 bytes
    request_header[CLIENT_UUID_SIZE] = CLIENT_VERSION; // insert client Version - 1 byte
    std::memcpy(request_header + CLIENT_UUID_SIZE + CLIENT_VERSION_SIZE, &client_code, sizeof(client_code)); // insert request Code - 2 bytes
    std::memcpy(request_header + CLIENT_UUID_SIZE + CLIENT_VERSION_SIZE + REQUEST_CODE_SIZE, &request_payload_size, sizeof(request_payload_size)); // insert Payload Size (0) - 4 bytes

    // Send request to server
    std::cout << "Checking for messages...\n";
    boost::asio::write(p_socket, boost::asio::buffer(request_header, REQUEST_HEADER_SIZE));

    // Read server response Header
    char response_header[RESPONSE_HEADER_SIZE];
    boost::asio::read(p_socket, boost::asio::buffer(response_header, RESPONSE_HEADER_SIZE));

    // Extract response code and payload size from header
    uint16_t r_code;
    uint32_t total_payload_size;
    std::memcpy(&r_code, response_header + SERVER_VERSION_SIZE, RESPONSE_CODE_SIZE);
    std::memcpy(&total_payload_size, response_header + SERVER_VERSION_SIZE + RESPONSE_CODE_SIZE, RESPONSE_PAYLOAD_SIZE);
    r_code = ntohs(r_code);
    total_payload_size = ntohl(total_payload_size);

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
    
    // Keep track of how many bytes we've processed from the payload
    size_t processed = 0; 

    // Loop until we have processed all the waiting messages one by one
    while (processed < total_payload_size) {
        
        // Read header for *one* message (25 bytes: FromUUID(16) + MsgID(4) + Type(1) + ContentSize(4) )
        char msg_head[CLIENT_UUID_SIZE + RESPONSE_MSG_ID_SIZE + RESPONSE_MSG_TYPE_SIZE + RESPONSE_MSG_SIZE];
        boost::asio::read(p_socket, boost::asio::buffer(msg_head, sizeof(msg_head)));
        processed += sizeof(msg_head);

        // Extract message header parts 
        std::string from_uuid(msg_head, CLIENT_UUID_SIZE);
        uint32_t msg_id = ntohl(*reinterpret_cast<uint32_t*>(msg_head + CLIENT_UUID_SIZE));
        uint8_t msg_type = msg_head[CLIENT_UUID_SIZE + RESPONSE_MSG_ID_SIZE];
        uint32_t content_size = ntohl(*reinterpret_cast<uint32_t*>(msg_head + CLIENT_UUID_SIZE + RESPONSE_MSG_ID_SIZE + RESPONSE_MSG_TYPE_SIZE));

        // Read message content
        std::vector<char> content(content_size);
        if (content_size > 0) boost::asio::read(p_socket, boost::asio::buffer(content));
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
                    std::string sym_key = g_my_info.keys->decrypt(content_str);
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
                        AESWrapper aes((unsigned char*)sym_key.data(), sym_key.size());
                        std::string decrypted = aes.decrypt(content_str.data(), content_str.size());

                        // Print text message to console
                        if (msg_type == MSG_TYPE_TEXT_MESSAGE) std::cout << decrypted << "\n";

                        // Save file to temp directory
                        else {
                            auto path = std::filesystem::temp_directory_path() / ("msg_" + std::to_string(msg_id) + ".tmp");
                            // Write binary data to temp file
                            std::ofstream f(path, std::ios::binary);
                            f.write(decrypted.data(), decrypted.size());
                            std::cout << "File saved in path: " << path << "\n";
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
        unsigned char key[AESWrapper::DEFAULT_KEYLENGTH];
        AESWrapper::GenerateKey(key, sizeof(key));
        std::string key_bin((char*)key, sizeof(key));
        
        // Encrypt the symmetric key using the targets public key
        try {
            RSAPublicWrapper pub(g_client_db[target_hex].public_key);
            msg_content = pub.encrypt(key_bin);
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
            try { data_to_encrypt = read_file_content(file_path); } 
            catch (...) { std::cerr << "File error! \n"; return; }
        }

        // Encrypt the data (text or file content)
        try {
            AESWrapper aes((unsigned char*)key.data(), key.size());
            msg_content = aes.encrypt(data_to_encrypt.c_str(), data_to_encrypt.size());
        } catch (...) { return; }
    }

    // Build complete payload 
    std::vector<char> msg_payload;
    uint32_t msg_size = htonl(msg_content.length());
    
    // Add payload parts to msg_payload
    msg_payload.insert(msg_payload.end(), target_uuid_bin.begin(), target_uuid_bin.end()); // 16 bytes Target UUID
    msg_payload.push_back(msg_type); // 1 byte Message Type
    msg_payload.insert(msg_payload.end(), (char*)&msg_size, (char*)&msg_size + sizeof(msg_size)); // 4 bytes Content Size
    msg_payload.insert(msg_payload.end(), msg_content.begin(), msg_content.end()); // N bytes Content

    // Build complete request (Header + Payload)
    std::vector<char> request;

    // Build header
    uint8_t client_version = CLIENT_VERSION;
    uint16_t request_code = htons(REQUEST_CODE_SEND_MESSAGE);
    uint32_t request_payload_size = htonl(msg_payload.size());

    // Add header parts to request
    request.insert(request.end(), g_my_info.uuid_bin.begin(), g_my_info.uuid_bin.end()); // Our UUID
    request.insert(request.end(), (char*)&client_version, (char*)&client_version + sizeof(client_version));
    request.insert(request.end(), (char*)&request_code, (char*)&request_code + sizeof(request_code));
    request.insert(request.end(), (char*)&request_payload_size, (char*)&request_payload_size + sizeof(request_payload_size));
    
    // Add complete payload to request
    request.insert(request.end(), msg_payload.begin(), msg_payload.end());

    // Send request to server
    std::cout << "Sending...\n";
    boost::asio::write(p_socket, boost::asio::buffer(request));

    // Read server response Header
    char res_head[RESPONSE_HEADER_SIZE];
    boost::asio::read(p_socket, boost::asio::buffer(res_head, RESPONSE_HEADER_SIZE));
    
    // Extract response code and payload size from header
    uint16_t r_code;
    uint32_t r_size;
    std::memcpy(&r_code, res_head + SERVER_VERSION_SIZE, 2);
    std::memcpy(&r_size, res_head + SERVER_VERSION_SIZE + 2, 4);
    r_code = ntohs(r_code);
    r_size = ntohl(r_size);

    // Read and server response payload
    std::vector<char> res_payload(r_size);
    if (r_size > 0) boost::asio::read(p_socket, boost::asio::buffer(res_payload));

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

    // 2. Build Request Header (Only header, no payload needed)
    char request_header[REQUEST_HEADER_SIZE];
    uint16_t request_code = htons(REQUEST_CODE_DELETE_USER);
    uint32_t request_payload_size = htonl(0); // No payload

    // Fill header
    std::memcpy(request_header, g_my_info.uuid_bin.data(), CLIENT_UUID_SIZE);
    request_header[CLIENT_UUID_SIZE] = CLIENT_VERSION;
    std::memcpy(request_header + CLIENT_UUID_SIZE + CLIENT_VERSION_SIZE, &request_code, sizeof(request_code));
    std::memcpy(request_header + CLIENT_UUID_SIZE + CLIENT_VERSION_SIZE + REQUEST_CODE_SIZE, &request_payload_size, sizeof(request_payload_size));

    // 3. Send request
    std::cout << "Sending delete request to server...\n";
    try {
        boost::asio::write(p_socket, boost::asio::buffer(request_header, REQUEST_HEADER_SIZE));
    } catch (const std::exception& e) {
        std::cerr << "Network error: " << e.what() << "\n";
        return;
    }

    // 4. Read Response Header
    char response_header[RESPONSE_HEADER_SIZE];
    try {
        boost::asio::read(p_socket, boost::asio::buffer(response_header, RESPONSE_HEADER_SIZE));
    } catch (...) {
        std::cerr << "Error reading server response.\n";
        return;
    }

    // Parse header
    uint16_t r_code;
    uint32_t r_size;
    std::memcpy(&r_code, response_header + SERVER_VERSION_SIZE, RESPONSE_CODE_SIZE);
    std::memcpy(&r_size, response_header + SERVER_VERSION_SIZE + RESPONSE_CODE_SIZE, RESPONSE_PAYLOAD_SIZE);
    r_code = ntohs(r_code);
    r_size = ntohl(r_size);

    // Read payload if exists (usually error message)
    std::vector<char> r_payload(r_size);
    if (r_size > 0) {
        boost::asio::read(p_socket, boost::asio::buffer(r_payload));
    }

    // 5. Process result
    if (r_code == RESPONSE_CODE_DELETE_USER_SUCCESS) {
        std::cout << "Server deleted user successfully.\n";
        
        // Delete local file
        if (std::filesystem::exists(MY_INFO_FILE)) {
            std::filesystem::remove(MY_INFO_FILE);
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

