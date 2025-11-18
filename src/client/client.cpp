// command in terminal: cd C:\Users\User\Documents\Yehonatan\open-university\defensive-programing\MessageU1\src\client
// Compile command:    g++ client.cpp RSAWrapper.cpp Base64Wrapper.cpp AESWrapper.cpp -o client.exe -std=c++17 -lWs2_32 -lpthread -lcryptopp
// Run command:        client.exe

#if defined(_WIN32)
#include <winsock2.h> // For htonl, ntohl
#endif

#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <map>
#include <boost/asio.hpp>
#include <filesystem>
#include <cstdint>      
#include <algorithm>
#include <memory>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>

#include "RSAWrapper.h"     // For asimmetric key crypto and generation
#include "Base64Wrapper.h"  // For saving private key
#include "AESWrapper.h"  // For symmetric key crypto

using boost::asio::ip::tcp;

// --- Configuration File ---
const std::string MY_INFO_FILE = "my.info";
const std::string SERVER_INFO_FILE = "server.info";

// --- Protocol Constants ---
// Users menu code
const std::string REGISTER_STR = "110";
const std::string CLIENTS_LIST_STR = "120";
const std::string REQUEST_PUBLIC_KEY_STR = "130";
const std::string REQUEST_WAITING_MESSAGES_STR = "140";
const std::string SEND_TEXT_MESSAGE_STR = "150";
const std::string SEND_SYMMETRIC_KEY_REQUEST_STR = "151";
const std::string SEND_SYMMETRIC_KEY_STR = "152";
const std::string SEND_FILE_STR = "153";
const std::string EXIT_CLIENT_STR = "0";

// Client request code from server 
const uint8_t  CLIENT_VERSION = 2;
const uint16_t REQUEST_CODE_REGISTER = 600;
const uint16_t REQUEST_CODE_CLIENTS_LIST = 601;
const uint16_t REQUEST_CODE_PUBLIC_KEY = 602;
const uint16_t REQUEST_CODE_SEND_MESSAGE = 603;
const uint16_t REQUEST_CODE_WAITING_MESSAGES = 604;

// Message Types (for payload of code 603)
const uint8_t MSG_TYPE_SYM_KEY_REQUEST = 1;
const uint8_t MSG_TYPE_SYM_KEY_SEND = 2;
const uint8_t MSG_TYPE_TEXT_MESSAGE = 3;
const uint8_t MSG_TYPE_FILE = 4;

// Payload structure for code 603 - Send Message (size in bytes)
const size_t MSG_TARGET_ID_SIZE = 16;
const size_t MSG_TYPE_SIZE = 1;
const size_t MSG_CONTENT_SIZE_FIELD_SIZE = 4;
const size_t MSG_HEADER_SIZE = MSG_TARGET_ID_SIZE + MSG_TYPE_SIZE + MSG_CONTENT_SIZE_FIELD_SIZE;

//  Clients request Header and Payload structure (size in bytes)
const size_t CLIENT_UUID_SIZE = 16;
const size_t CLIENT_VERSION_SIZE = 1;
const size_t REQUEST_CODE_SIZE = 2;
const size_t REQUEST_PAYLOAD_SIZE = 4;
const size_t USERNAME_FIXED_SIZE = 255;
const size_t PUBLIC_KEY_FIXED_SIZE = 160;
const size_t REQUEST_HEADER_SIZE = 16 + 1 + 2 + 4; // ClientID(16) + Version(1) + Code(2) + PayloadSize(4)

// Server response code to client
//const uint8_t  SERVER_VERSION = 2; - not used in code, but server uses version 2
const uint16_t RESPONSE_CODE_REGISTER_SUCCESS = 2100;
const uint16_t RESPONSE_CODE_DISPLAYING_CLIENTS_LIST = 2101;
const uint16_t RESPONSE_CODE_SEND_PUBLIC_KEY = 2102;
const uint16_t RESPONSE_CODE_SEND_TEXT_MESSAGE = 2103;
const uint16_t RESPONSE_CODE_PULL_WAITING_MESSAGE = 2104;
const uint16_t RESPONSE_CODE_GENERAL_ERROR = 9000;

// Servers response Header structure (size in bytes)
const size_t SERVER_VERSION_SIZE = 1;
const size_t RESPONSE_CODE_SIZE = 2;
const size_t RESPONSE_PAYLOAD_SIZE = 4;
const size_t RESPONSE_HEADER_SIZE = 1 + 2 + 4; // Version(1) + Code(2) + PayloadSize(4)

// Client-side RAM Storage
struct ClientInfo {
    std::string username;
    std::string public_key;
    std::string symmetric_key;
};

// Store clients info in RAM
std::map<std::string, ClientInfo> g_client_db; 

// Holds info about *this* client, loaded from my.info file
struct MyInfo {
    std::string name;
    std::string uuid_hex;
    std::string uuid_bin; // 16-byte binary version of the UUID
    std::unique_ptr<RSAPrivateWrapper> keys; // Smart pointer to manage RSA keys memory
} g_my_info;

bool g_is_registered = false; // Flag to indicate if we are registered

void show_menu() 
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
              << "0) Exit client\n"
              << "?\n";
}

// Checks if the my.info file exists
bool is_user_registered()
{
    std::ifstream f(MY_INFO_FILE);
    return f.good();
}

// Convert binary UUID to ASCII Hex
std::string binary_to_hex_ascii(const std::string& bin_uuid)
{
    std::string hex;
    CryptoPP::StringSource ss(bin_uuid, true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(hex),
            true // uppercase
        )
    );
    return hex;
}

// Convert ASCII Hex UUID to binary
std::string hex_ascii_to_binary(const std::string& hex)
{
    std::string bin;
    CryptoPP::StringSource ss(hex, true,
        new CryptoPP::HexDecoder(
            new CryptoPP::StringSink(bin)
        )
    );
    return bin;
}

// Trim whitespace from both ends of a string
std::string trim_str(const std::string& s) {
    auto start = std::find_if_not(s.begin(), s.end(), [](unsigned char c){ return std::isspace(c); });
    auto end = std::find_if_not(s.rbegin(), s.rend(), [](unsigned char c){ return std::isspace(c); }).base();
    return (start < end ? std::string(start, end) : std::string());
}

// Trim null characters from a fixed-size buffer
std::string trim_buf(const char* buffer, size_t length)
{
    // Finds the first null character and returns a string up to that point
    const char* end = (const char*)std::memchr(buffer, 0, length);
    return end ? std::string(buffer, end) : std::string(buffer, length);
}

// Searches the in-RAM client DB for a user's name by their binary UUID.
std::string find_name_by_uuid(const std::string& uuid_bin)
{
    std::string uuid_hex = binary_to_hex_ascii(uuid_bin);
    auto user = g_client_db.find(uuid_hex);
    // If found uuid in our local DB, return the name
    if (user != g_client_db.end())
    {
        return user->second.username;
    }
    // If uuid not in our local DB, check if it's our own uuid
    if (uuid_hex == g_my_info.uuid_hex)
    {
        return g_my_info.name;
    }
    // If the loop finishes without finding a match return Unknown
    return "Unknown";
}

//  Searches the in-RAM client DB for a user's uuid by their name
std::string find_uuid_by_name(const std::string& name)
{
    // Loop through our global map (g_client_db)
    for (const auto& pair : g_client_db) 
    {
        // If found name in our local DB, return the uuid
        if (pair.second.username == name)
        {
            // Convert UUID from hex ASCII to binary and return it
            return hex_ascii_to_binary(pair.first);
        }
    }
    // If the loop finishes without finding a match return an empty string
    return "";
}

// Attempts to load client info from my.info into RAM
bool load_my_info()
{
    std::ifstream f(MY_INFO_FILE);
    if (!f.good()) {
        return false; // Not registered
    }

    try {
        std::string name, uuid_hex, private_key_b64;
        std::getline(f, name);
        std::getline(f, uuid_hex);
        
        // Read the rest of the file (potentially multi-line) for the Base64 key
        std::string line;
        while (std::getline(f, line)) {
            private_key_b64 += line;
        }
        f.close();

        // Check if any field is empty
        if (name.empty() || uuid_hex.empty() || private_key_b64.empty()) {
            std::cerr << "Error: " << MY_INFO_FILE << " is corrupt or incomplete.\n";
            return false;
        }

        // Load into in-RAM
        g_my_info.name = name;
        g_my_info.uuid_hex = uuid_hex;
        g_my_info.uuid_bin = hex_ascii_to_binary(uuid_hex);
        g_my_info.keys = std::make_unique<RSAPrivateWrapper>(Base64Wrapper::decode(private_key_b64));
        
        g_is_registered = true;
        std::cout << "Welcome back, " << g_my_info.name << "!" << std::endl;
        return true;
    }
    // Catch any exceptions from key loading
    catch (std::exception& e) {
        std::cerr << "Error loading " << MY_INFO_FILE << ": " << e.what() << "\n";
        return false;
    }
}

// Reads an entire file into a string (binary safe)
std::string read_file_content(const std::string& filepath)
{
    std::ifstream file(filepath, std::ios::binary); // Open in binary mode!
    if (!file) {
        throw std::runtime_error("Cannot open file: " + filepath);
    }
    // Read the whole file into a string
    return std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

//Handles the entire registration process (Code 110/600)
void handle_registration(tcp::socket& s)
{
    // 1. Check if my.info file already exists
    if (is_user_registered()) {
        std::cerr << "Error: User already registered!\n";
        return;
    }

    // 2. Get username from user
    std::cout << "Enter username: ";
    std::string username;
    std::getline(std::cin, username);
    if (username.empty()) { // check if username is empty
        std::cerr << "Error: Username cannot be empty.\n";
        return;
    }
    if (username.length() > USERNAME_FIXED_SIZE) { // check if username is too long - more than 255 chars
        std::cerr << "Error: Username too long (max " << USERNAME_FIXED_SIZE << " chars).\n";
        return;
    }

    // 3. Generate new RSA keys - asimmetric key pair
    std::cout << "Generating RSA keys (this may take a moment)..." << std::endl;
    RSAPrivateWrapper my_keys;
    std::string public_key_bin = my_keys.getPublicKey();
    std::string private_key_bin = my_keys.getPrivateKey();
    std::string private_key_b64 = Base64Wrapper::encode(private_key_bin); // Save private key in Base64

    // 4. Build the full request (Header + Payload)
    uint32_t request_payload_size = USERNAME_FIXED_SIZE + PUBLIC_KEY_FIXED_SIZE;
    std::vector<char> complete_request; // Allocated on heap for dynamic size
    complete_request.reserve(REQUEST_HEADER_SIZE + request_payload_size); // Pre-allocate memory

    // 4a. Build header
    uint8_t client_version = CLIENT_VERSION;
    uint16_t request_code = htons(REQUEST_CODE_REGISTER);
    uint32_t reg_payload_size = htonl(request_payload_size);

    // 4b. Add header parts to complete_request
    complete_request.insert(complete_request.end(), CLIENT_UUID_SIZE, 0); // Add 16 null bytes as a placeholder for the ClientID
    complete_request.insert(complete_request.end(), (char*)&client_version, (char*)&client_version + sizeof(client_version));
    complete_request.insert(complete_request.end(), (char*)&request_code, (char*)&request_code + sizeof(request_code));
    complete_request.insert(complete_request.end(), (char*)&reg_payload_size, (char*)&reg_payload_size + sizeof(reg_payload_size));
    
    // 4c. Build payload
    char username_payload[USERNAME_FIXED_SIZE] = {0}; // Allocate on stack for efficiency, fills with 255 null bytes
    std::memcpy(username_payload, username.c_str(), username.length());

    char public_key_payload[PUBLIC_KEY_FIXED_SIZE] = {0}; // Allocate on stack for efficiency, fills with 160 null bytes
    size_t key_copy_size = std::min((size_t)PUBLIC_KEY_FIXED_SIZE, public_key_bin.length());
    std::memcpy(public_key_payload, public_key_bin.c_str(), key_copy_size);

    // 4d. Add payload parts to complete_request
    complete_request.insert(complete_request.end(), username_payload, username_payload + USERNAME_FIXED_SIZE);
    complete_request.insert(complete_request.end(), public_key_payload, public_key_payload + PUBLIC_KEY_FIXED_SIZE);

    // 5. Send request to server
    std::cout << "Sending registration request to server..." << std::endl;
    boost::asio::write(s, boost::asio::buffer(complete_request));

    // 6. Wait for server response (Header)
    char response_header[RESPONSE_HEADER_SIZE]; // Allocate on stack for efficiency
    boost::asio::read(s, boost::asio::buffer(response_header, RESPONSE_HEADER_SIZE));

    // 7. Parse response header
    uint16_t response_code; // to hold response code from server
    uint32_t response_payload_size; // to hold payload size from server
    std::memcpy(&response_code, response_header + SERVER_VERSION_SIZE, RESPONSE_CODE_SIZE);
    std::memcpy(&response_payload_size, response_header + SERVER_VERSION_SIZE + RESPONSE_CODE_SIZE, RESPONSE_PAYLOAD_SIZE);
    response_code = ntohs(response_code); 
    response_payload_size = ntohl(response_payload_size);

    // 8. Read response payload
    std::vector<char> response_payload(response_payload_size); // Allocate on heap for dynamic size
    boost::asio::read(s, boost::asio::buffer(response_payload));

    // 9. Process response
    if (response_code == RESPONSE_CODE_REGISTER_SUCCESS)
    {
        // 9a. Validate payload size
        if (response_payload_size != CLIENT_UUID_SIZE) {
            std::cerr << "Error: Server sent invalid UUID size.\n";
            return;
        }
        
        // 9b. Convert binary UUID to ASCII Hex
        std::string uuid_bin(response_payload.begin(), response_payload.end());
        std::string uuid_hex = binary_to_hex_ascii(uuid_bin);
        
        std::cout << "Registration successful! Your UUID is: " << uuid_hex << std::endl; // Print the UUID for debugging

        // 9c. Save to my.info
        std::ofstream outfile(MY_INFO_FILE);
        outfile << username << "\n"; // Line 1: Username
        outfile << uuid_hex << "\n"; // Line 2: UUID (as ASCII Hex)
        outfile << private_key_b64; // Line 3: Private Key (Base64)
        outfile.close();

        // 9d. Load info into RAM for current session
        std::cout << "Loading info into session..." << std::endl;
        load_my_info();
    }
    else // Got error from server
    {
        std::string error_msg(response_payload.begin(), response_payload.end());
        std::cerr << "Server responded with an error: " << error_msg << std::endl;
    }
}

// Handles requesting the client list (Code 120/601)
void handle_client_list(tcp::socket& s)
{
    // 1. Check if user is registered
    if (!g_is_registered) {
        std::cerr << "Error: You must be registered to request the client list.\n";
        return;
    }

    // 2. Build the request header (23 bytes)
    char request_header[REQUEST_HEADER_SIZE]; // Allocate on stack for efficiency

    // 3. Add header parts (*must* send our UUID so the server knows who is asking)
    uint16_t request_code = htons(REQUEST_CODE_CLIENTS_LIST);
    uint32_t request_payload_size = htonl(0);
    std::memcpy(request_header, g_my_info.uuid_bin.data(), CLIENT_UUID_SIZE); // insert UUID - 16 bytes
    request_header[CLIENT_UUID_SIZE] = CLIENT_VERSION; // insert clients Version - 1 byte
    std::memcpy(request_header + CLIENT_UUID_SIZE + CLIENT_VERSION_SIZE, &request_code, sizeof(request_code)); // insert Code - 2 bytes
    std::memcpy(request_header + CLIENT_UUID_SIZE + CLIENT_VERSION_SIZE + REQUEST_CODE_SIZE, &request_payload_size, sizeof(request_payload_size)); // insert Payload Size - 4 bytes

    // 4. Send request (no payload)
    std::cout << "Requesting client list from server..." << std::endl;
    boost::asio::write(s, boost::asio::buffer(request_header, REQUEST_HEADER_SIZE));

    // 5. Wait for server response (Header)
    char response_header[RESPONSE_HEADER_SIZE]; // Allocate buffer on stack for efficiency
    boost::asio::read(s, boost::asio::buffer(response_header, RESPONSE_HEADER_SIZE));

    // 6. Parse response header
    uint16_t response_code;
    uint32_t response_payload_size;
    std::memcpy(&response_code, response_header + SERVER_VERSION_SIZE, RESPONSE_CODE_SIZE);
    std::memcpy(&response_payload_size, response_header + SERVER_VERSION_SIZE + RESPONSE_CODE_SIZE, RESPONSE_PAYLOAD_SIZE);
    response_code = ntohs(response_code);
    response_payload_size = ntohl(response_payload_size);
    
    // 7. Read response payload
    std::vector<char> response_payload(response_payload_size);

    if (response_payload_size > 0) {
        boost::asio::read(s, boost::asio::buffer(response_payload));
    }

    // 8. Process response payload
    if (response_code == RESPONSE_CODE_DISPLAYING_CLIENTS_LIST)
    {
        std::cout << "\n--- Registered Clients ---" << std::endl;
        g_client_db.clear(); // Clear the old list
        
        const size_t entry_size = CLIENT_UUID_SIZE + USERNAME_FIXED_SIZE;
        if (response_payload_size % entry_size != 0) {
            std::cerr << "Error: Server sent a corrupt client list.\n";
            return;
        }

        // 8a. Loop through the payload, one client at a time
        for (size_t i = 0; i < response_payload_size; i += entry_size)
        {
            const char* entry_ptr = response_payload.data() + i;
            
            std::string uuid_bin(entry_ptr, CLIENT_UUID_SIZE);
            std::string uuid_hex = binary_to_hex_ascii(uuid_bin);
            
            // Trim null bytes from the fixed-size name field
            std::string name = trim_buf(entry_ptr + CLIENT_UUID_SIZE, USERNAME_FIXED_SIZE);

            // Print to screen
            std::cout << "Name: " << name << "\nUUID: " << uuid_hex << "\n---\n";
            
            // Save to our RAM database (will get the public key in step 130)
            g_client_db[uuid_hex].username = name;
        }
    }
    else // Got error from server
    {
        std::string error_msg(response_payload.begin(), response_payload.end());
        std::cerr << "Server responded with an error: " << error_msg << std::endl;
    }
}

//Handles requesting another client's public key (Code 130/602)
void handle_request_public_key(tcp::socket& s)
{
    // 1. Check if user is registered
    if (!g_is_registered) {
        std::cerr << "Error: You must be registered to perform this action.\n";
        return;
    }

    // 2. Get target username from user
    std::cout << "Enter username to get their public key: ";
    std::string target_username;
    std::getline(std::cin, target_username);
    if (target_username.empty()) return;

    // 3. Find the target's UUID in our local RAM DB (g_client_db)
    std::string target_uuid_bin = find_uuid_by_name(target_username);
    if (target_uuid_bin.empty())
    {
        std::cerr << "Error: User '" << target_username << "' not found in your local client list.\n";
        std::cerr << "Try running option 120 (Request for clients list) first.\n";
        return;
    }

    // 4. Build the full request (Header + Payload)
    std::vector<char> complete_request; // Allocate on heap for dynamic size
    complete_request.reserve(REQUEST_HEADER_SIZE + target_uuid_bin.length());

     // 4a. Build header
    uint8_t client_version = CLIENT_VERSION;
    uint16_t request_code = htons(REQUEST_CODE_PUBLIC_KEY);
    uint32_t req_payload_size = htonl(target_uuid_bin.length()); // Payload is the 16-byte UUID

    // 4b. Add header parts
    complete_request.insert(complete_request.end(), g_my_info.uuid_bin.begin(), g_my_info.uuid_bin.end()); // Our UUID
    complete_request.insert(complete_request.end(), (char*)&client_version, (char*)&client_version + sizeof(client_version));
    complete_request.insert(complete_request.end(), (char*)&request_code, (char*)&request_code + sizeof(request_code));
    complete_request.insert(complete_request.end(), (char*)&req_payload_size, (char*)&req_payload_size + sizeof(req_payload_size));
    
    // 4c. Add payload (target's UUID)
    complete_request.insert(complete_request.end(), target_uuid_bin.begin(), target_uuid_bin.end());

    // 5. Send request
    std::cout << "Requesting public key for " << target_username << "..." << std::endl;
    boost::asio::write(s, boost::asio::buffer(complete_request));

    // 6. Wait for server response (Header)
    char response_header[RESPONSE_HEADER_SIZE]; // Allocate on stack for efficiency
    boost::asio::read(s, boost::asio::buffer(response_header, RESPONSE_HEADER_SIZE));

    // 7. Parse response header
    uint16_t response_code;
    uint32_t response_payload_size;
    std::memcpy(&response_code, response_header + SERVER_VERSION_SIZE, RESPONSE_CODE_SIZE);
    std::memcpy(&response_payload_size, response_header + SERVER_VERSION_SIZE + RESPONSE_CODE_SIZE, RESPONSE_PAYLOAD_SIZE);
    response_code = ntohs(response_code);
    response_payload_size = ntohl(response_payload_size);

    // 8. Read response payload
    std::vector<char> response_payload(response_payload_size); // Allocate on heap for dynamic size
    if (response_payload_size > 0) {
        boost::asio::read(s, boost::asio::buffer(response_payload));
    }

    // 9. Process response
    if (response_code == RESPONSE_CODE_SEND_PUBLIC_KEY)
    {
        // Expected payload: Target's UUID (16) + Target's Public Key (160)
        const size_t expected_size = CLIENT_UUID_SIZE + PUBLIC_KEY_FIXED_SIZE;
        if (response_payload_size != expected_size) {
            std::cerr << "Error: Server sent a corrupt public key payload.\n";
            return;
        }

        // 9a. Extract data
        std::string target_uuid_bin(response_payload.data(), CLIENT_UUID_SIZE);
        std::string target_pub_key(response_payload.data() + CLIENT_UUID_SIZE, PUBLIC_KEY_FIXED_SIZE);
        
        std::string target_uuid_hex = binary_to_hex_ascii(target_uuid_bin);

        // 9b. Store the public key in our in-RAM database
        g_client_db[target_uuid_hex].public_key = target_pub_key;
        
        std::cout << "Successfully received and stored public key for:\n";
        std::cout << "Name: " << g_client_db[target_uuid_hex].username << "\n";
        std::cout << "UUID: " << target_uuid_hex << "\n";
    }
    else // Got error from server
    {
        std::string error_msg(response_payload.begin(), response_payload.end());
        std::cerr << "Server responded with an error: " << error_msg << std::endl;
    }
}

// Handler users choice and calls the appropriate function (options 150, 151, 152, 153 / 603)
void handle_send_message_options(tcp::socket& s, const std::string& menu_choice)
{
    // 1. Check if user is registered
    if (!g_is_registered) {
        std::cerr << "Error: You must be registered to perform this action.\n";
        return;
    }

    // 2. Get target username from user
    std::cout << "Enter username of the recipient: ";
    std::string target_username;
    std::getline(std::cin, target_username);
    if (target_username.empty()) return;

    // 3. Find the target's UUID in our local in-RAM DB (g_client_db)
    std::string target_uuid_bin = find_uuid_by_name(target_username);
    if (target_uuid_bin.empty())
    {
        std::cerr << "Error: User '" << target_username << "' not found in your local client list.\n";
        std::cerr << "Try running option 120 (Request for clients list) first.\n";
        return;
    }
    std::string target_uuid_hex = binary_to_hex_ascii(target_uuid_bin);

    // 4. Prepare message content based on user choice
    uint8_t message_type = 0;
    std::string message_content; // This will be the *encrypted* content

    // 5. Logic for 151: Request Symmetric Key
    if (menu_choice == SEND_SYMMETRIC_KEY_REQUEST_STR)
    {
        message_type = MSG_TYPE_SYM_KEY_REQUEST;
    }
    // 6. Logic for 152: Send Symmetric Key
    else if (menu_choice == SEND_SYMMETRIC_KEY_STR)
    {
        message_type = MSG_TYPE_SYM_KEY_SEND;
        
        // 6a. Check if we have the target's public key
        if (g_client_db[target_uuid_hex].public_key.empty()) {
            std::cerr << "Error: You don't have the public key for '" << target_username << "'.\n";
            std::cerr << "Try running option 130 to get their key first.\n";
            return;
        }

        // 6b. Generate a new symmetric key (AES key)
        unsigned char aes_key_bytes[AESWrapper::DEFAULT_KEYLENGTH];
        AESWrapper::GenerateKey(aes_key_bytes, AESWrapper::DEFAULT_KEYLENGTH);
        std::string aes_key_bin((char*)aes_key_bytes, AESWrapper::DEFAULT_KEYLENGTH);

        // 6c. Encrypt the *symmetric* key using the *target's public* key
        try {
            RSAPublicWrapper target_public_key(g_client_db[target_uuid_hex].public_key);
            message_content = target_public_key.encrypt(aes_key_bin); // Encrypt the AES key
        } catch (std::exception& e) {
            std::cerr << "Error encrypting symmetric key: " << e.what() << "\n";
            return;
        }

        // 6d. Save this symmetric key in our RAM DB for *this user*
        g_client_db[target_uuid_hex].symmetric_key = aes_key_bin;
        std::cout << "Generated and sent a new symmetric key to " << target_username << ".\n";
    }
    // 7. Logic for sending messages - 150 (Text) or 153 (File)
    else if (menu_choice == SEND_TEXT_MESSAGE_STR || menu_choice == SEND_FILE_STR)
    {
        // 7a. Check for symmetric key
        std::string sym_key = g_client_db[target_uuid_hex].symmetric_key;
        if (sym_key.empty()) {
            std::cerr << "Error: You don't have a symmetric key for '" << target_username << "'.\n";
            return;
        }

        std::string data_to_encrypt;

        // 7b. Text Message (150)
        if (menu_choice == SEND_TEXT_MESSAGE_STR) { 
            message_type = MSG_TYPE_TEXT_MESSAGE;
            std::cout << "Enter your message: ";
            std::getline(std::cin, data_to_encrypt);
            if (data_to_encrypt.empty()) return;
        }
        // 7c. File Transfer (153)
        else {
            message_type = MSG_TYPE_FILE;
            std::cout << "Enter full file path: ";
            std::string filepath;
            std::getline(std::cin, filepath);
            // Remove potential quotes around path (common when dragging files to terminal)
            filepath.erase(std::remove(filepath.begin(), filepath.end(), '\"'), filepath.end());

            try {
                data_to_encrypt = read_file_content(filepath);
                std::cout << "Read " << data_to_encrypt.size() << " bytes from file.\n";
            } 
            catch (std::exception& e) {
                std::cerr << "Error: " << e.what() << "\n"; // Prints "found not file" equivalent
                return;
            }
        }

        // 7d. Encrypt the data (text or file content)
        try {
            AESWrapper aes_encryptor((unsigned char*)sym_key.c_str(), sym_key.length());
            message_content = aes_encryptor.encrypt(data_to_encrypt.c_str(), data_to_encrypt.length());
        } 
        catch (std::exception& e) {
            std::cerr << "Error encrypting: " << e.what() << "\n";
            return;
        }
    }

    // 8. Build the inner payload (for request 603)
    std::vector<char> message_payload; // Allocate on heap for dynamic size
    uint32_t msg_size = htonl(message_content.length());

    message_payload.insert(message_payload.end(), target_uuid_bin.begin(), target_uuid_bin.end()); // 16 bytes Target UUID
    message_payload.push_back(message_type); // 1 byte Message Type
    message_payload.insert(message_payload.end(), (char*)&msg_size, (char*)&msg_size + sizeof(msg_size)); // 4 bytes Content Size
    message_payload.insert(message_payload.end(), message_content.begin(), message_content.end()); // N bytes Content

    // 9. Build the full request (Header + Payload)
    std::vector<char>  complete_request; // Allocate on heap for dynamic size
    
    // 9a. Build header
    uint8_t client_version = CLIENT_VERSION;
    uint16_t request_code = htons(REQUEST_CODE_SEND_MESSAGE); // Code 603
    uint32_t request_payload_size = htonl(message_payload.size());

    // 9b. Add header parts
    complete_request.insert(complete_request.end(), g_my_info.uuid_bin.begin(), g_my_info.uuid_bin.end()); // Our UUID
    complete_request.insert(complete_request.end(), (char*)&client_version, (char*)&client_version + sizeof(client_version));
    complete_request.insert(complete_request.end(), (char*)&request_code, (char*)&request_code + sizeof(request_code));
    complete_request.insert(complete_request.end(), (char*)&request_payload_size, (char*)&request_payload_size + sizeof(request_payload_size));
    
    // 9c. Add inner payload part
    complete_request.insert(complete_request.end(), message_payload.begin(), message_payload.end());

    // 10. Send request
    std::cout << "Sending message to server..." << std::endl;
    boost::asio::write(s, boost::asio::buffer(complete_request));

    // 11. Wait for server response (Header)
    char response_header[RESPONSE_HEADER_SIZE]; // מוקצה על ה-Stack
    boost::asio::read(s, boost::asio::buffer(response_header, RESPONSE_HEADER_SIZE));

    // 12. Parse response header
    uint16_t response_code;
    uint32_t response_payload_size;
    std::memcpy(&response_code, response_header + SERVER_VERSION_SIZE, RESPONSE_CODE_SIZE);
    std::memcpy(&response_payload_size, response_header + SERVER_VERSION_SIZE + RESPONSE_CODE_SIZE, RESPONSE_PAYLOAD_SIZE);
    response_code = ntohs(response_code);
    response_payload_size = ntohl(response_payload_size);

    // 13. Read response payload
    std::vector<char> response_payload(response_payload_size);
    if (response_payload_size > 0) {
        boost::asio::read(s, boost::asio::buffer(response_payload));
    }

    // 14. Process response
    if (response_code == RESPONSE_CODE_SEND_TEXT_MESSAGE)
    {
        // 14a. Expected payload: Target's UUID (16) + Message ID (4)
        if (response_payload_size != CLIENT_UUID_SIZE + sizeof(uint32_t)) {
            std::cerr << "Error: Server sent a corrupt message confirmation.\n";
            return;
        }

        uint32_t message_id;
        std::memcpy(&message_id, response_payload.data() + CLIENT_UUID_SIZE, sizeof(uint32_t));
        message_id = ntohl(message_id);

        std::cout << "Server confirmed message sent. Message ID: " << message_id << "\n";
    }
    else // Got error from server
    {
        std::string error_msg(response_payload.begin(), response_payload.end());
        std::cerr << "Server responded with an error: " << error_msg << std::endl;
    }
}

// Handles pulling waiting messages from the server (Code 140/604)
void handle_pull_messages(tcp::socket& s)
{
    // 1. Check if user is registered
    if (!g_is_registered) {
        std::cerr << "Error: You must be registered to perform this action.\n";
        return;
    }

    // 2. Build request header (23 bytes, no payload)
    char request_header[REQUEST_HEADER_SIZE]; // Allocate on stack for efficiency
    uint16_t client_code = htons(REQUEST_CODE_WAITING_MESSAGES);
    uint32_t request_payload_size = htonl(0); 
    
    // 2a. Add header parts to request_header
    std::memcpy(request_header, g_my_info.uuid_bin.data(), CLIENT_UUID_SIZE); // insert ClientID - 16 bytes
    request_header[CLIENT_UUID_SIZE] = CLIENT_VERSION; // insert client Version - 1 byte
    std::memcpy(request_header + CLIENT_UUID_SIZE + CLIENT_VERSION_SIZE, &client_code, sizeof(client_code)); // insert request Code - 2 bytes
    std::memcpy(request_header + CLIENT_UUID_SIZE + CLIENT_VERSION_SIZE + REQUEST_CODE_SIZE, &request_payload_size, sizeof(request_payload_size)); // insert Payload Size (0) - 4 bytes

    // 3. Send request
    std::cout << "Requesting waiting messages from server..." << std::endl;
    boost::asio::write(s, boost::asio::buffer(request_header, REQUEST_HEADER_SIZE));

    // 4. Wait for server response (Header)
    char response_header[RESPONSE_HEADER_SIZE]; // Allocate on stack for efficiency
    boost::asio::read(s, boost::asio::buffer(response_header, RESPONSE_HEADER_SIZE));

    // 5. Parse response header
    uint16_t response_code;
    uint32_t total_payload_size; // Total size of *all* messages combined
    std::memcpy(&response_code, response_header + SERVER_VERSION_SIZE, RESPONSE_CODE_SIZE);
    std::memcpy(&total_payload_size, response_header + SERVER_VERSION_SIZE + RESPONSE_CODE_SIZE, RESPONSE_PAYLOAD_SIZE);
    response_code = ntohs(response_code);
    total_payload_size = ntohl(total_payload_size);

    // 6. Process response
    if (response_code != RESPONSE_CODE_PULL_WAITING_MESSAGE)
    {
        // 6a. Handle error response (which might have its own payload)
        std::vector<char> error_payload(total_payload_size);
        if (total_payload_size > 0) {
            boost::asio::read(s, boost::asio::buffer(error_payload));
        }
        std::string error_msg(error_payload.begin(), error_payload.end());
        std::cerr << "Server responded with an error: " << error_msg << std::endl;
        return;
    }

    // 7. check if there are any messages
    if (total_payload_size == 0) {
        std::cout << "You have no new messages.\n";
        return;
    }
    
    std::cout << "\n--- Received Messages ---" << std::endl;
    
    // 8. Loop until we have processed all the bytes the server promised
    size_t bytes_processed = 0;
    while (bytes_processed < total_payload_size)
    {
        // 8a. Read the header for *one* message
        // Header format (25 bytes): FromUUID(16) + MsgID(4) + Type(1) + ContentSize(4)
        const size_t SINGLE_MSG_HEADER_SIZE = CLIENT_UUID_SIZE + sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint32_t);
        char single_msg_header[SINGLE_MSG_HEADER_SIZE]; // Allocation on stack for efficiency
        
        // 8b. Blocking read from socket for header only
        boost::asio::read(s, boost::asio::buffer(single_msg_header, SINGLE_MSG_HEADER_SIZE));
        bytes_processed += SINGLE_MSG_HEADER_SIZE; // Count these 25 bytes

        // 8c. Parse the single message header
        size_t cursor = 0; // Cursor to track our position in the header
        std::string from_uuid_bin(single_msg_header + cursor, CLIENT_UUID_SIZE);
        cursor += CLIENT_UUID_SIZE;

        uint32_t msg_id;
        std::memcpy(&msg_id, single_msg_header + cursor, sizeof(uint32_t));
        msg_id = ntohl(msg_id);
        cursor += sizeof(uint32_t);

        uint8_t msg_type = single_msg_header[cursor];
        cursor += sizeof(uint8_t);

        uint32_t msg_content_size;
        std::memcpy(&msg_content_size, single_msg_header + cursor, sizeof(uint32_t));
        msg_content_size = ntohl(msg_content_size);
        
        // 8d. Read the message content (exactly the size required)
        std::vector<char> msg_content(msg_content_size); // Allocate on heap for dynamic size
        if (msg_content_size > 0) {
            boost::asio::read(s, boost::asio::buffer(msg_content));
        }
        bytes_processed += msg_content_size; // Count these N bytes
        
        std::string msg_content_str(msg_content.begin(), msg_content.end());

        // 8e. Display the message
        std::cout << "From: " << find_name_by_uuid(from_uuid_bin) << "\n";
        std::cout << "Content:\n";

        // 8f. Handle based on message type
        switch (msg_type)
        {
            case MSG_TYPE_SYM_KEY_REQUEST: // Type 1 - Request Symmetric Key
                std::cout << "Request for symmetric key\n";
                break;
            
            case MSG_TYPE_SYM_KEY_SEND: // Type 2 - Send Symmetric Key
            {
                std::cout << "Symmetric key received.\n";
                try {
                    // Decrypt the symmetric key using our *private* key
                    std::string decrypted_sym_key = g_my_info.keys->decrypt(msg_content_str);
                    // Store it in our in-RAM DB
                    std::string from_uuid_hex = binary_to_hex_ascii(from_uuid_bin);
                    g_client_db[from_uuid_hex].symmetric_key = decrypted_sym_key;
                } 
                catch (std::exception& e) {
                    std::cout << "Error decrypting symmetric key\n";
                }
                break;
            }
            
            case MSG_TYPE_TEXT_MESSAGE: // Type 3 - send text Message
            case MSG_TYPE_FILE: // Type 4 - File Transfer
            {
                // Find the symmetric key we have for this sender
                std::string from_uuid_hex = binary_to_hex_ascii(from_uuid_bin);
                std::string sym_key = g_client_db[from_uuid_hex].symmetric_key;

                if (sym_key.empty()) {
                    std::cout << "can't decrypt message (no symmetric key)\n";
                } 
                else {
                    try {
                        // Decrypt the message content using the stored AES key
                        AESWrapper aes((unsigned char*)sym_key.c_str(), sym_key.length());
                        std::string decrypted = aes.decrypt(msg_content_str.c_str(), msg_content_str.length());

                        // if text message print to console
                        if (msg_type == MSG_TYPE_TEXT_MESSAGE) {
                            std::cout << decrypted << "\n";
                        } 
                        // else - if file if file save to temp file
                        else {
                            auto temp_path = std::filesystem::temp_directory_path() / ("msg_" + std::to_string(msg_id) + ".tmp");
                            // Write binary data to temp file
                            std::ofstream outfile(temp_path, std::ios::binary);
                            outfile.write(decrypted.data(), decrypted.size());
                            outfile.close();
                            std::cout << "File received! Saved to: " << temp_path << "\n";
                        }
                    } 
                    catch (std::exception&) {
                        std::cout << "can't decrypt message\n";
                    }
                }
                break;
            }
            default:
                std::cout << "Unknown message type.\n";
        }
        std::cout << ".\n";
        std::cout << ".\n";
        std::cout << "----<EOM>----\n\n";
    }
}

// Loads server host and port from server.info file
std::pair<std::string, std::string> load_server_info()
{
    std::ifstream server_file(SERVER_INFO_FILE); // try to open file
    if (!server_file.is_open()) {
        throw std::runtime_error("Error: Could not open " + SERVER_INFO_FILE);
    }
    std::string line;
    if (std::getline(server_file, line)) { // read first line
        size_t colon_pos = line.find(':'); // Find the colon separator

        if (colon_pos == std::string::npos || colon_pos == 0 || colon_pos == line.length() - 1) { // check if the content of file is valid
            throw std::runtime_error("Invalid format in " + SERVER_INFO_FILE);
        }
        return { line.substr(0, colon_pos), line.substr(colon_pos + 1) }; // Return host and port
    }
    throw std::runtime_error(SERVER_INFO_FILE + " is empty."); // if file is empty
}

int main()
{
    std::string host;
    std::string port;

    try 
    {
        // 1. Load my.info *before* anything else
        load_my_info(); 

        // 2. Load server info from file
        auto server_info = load_server_info();
        host = server_info.first; 
        port = server_info.second;
    }
    // catch errors from loading server info
    catch (std::exception& e) 
    {
        std::cerr << e.what() << std::endl;
        return 1;
    }
   
    std::cout << "Connecting to " << host << ":" << port << "..." << std::endl;

    try
    {
        // 3. Set up Boost.Asio connection
        boost::asio::io_context io_context;
        tcp::socket s(io_context);
        tcp::resolver resolver(io_context);
        boost::asio::connect(s, resolver.resolve(host, port));
        
        std::cout << "Connected successfully." << std::endl;

        // 4. Main Menu Loop
        std::string users_choice;
        while (true)
        {
            // 4a. Display menu and get user input
            show_menu();
            std::getline(std::cin, users_choice);
            users_choice = trim_str(users_choice); // Trim whitespace
            
            // 4b. Handle user choice
            if (users_choice == EXIT_CLIENT_STR) {
                break; // Exit loop
            }
            else if (users_choice == REGISTER_STR) {
                handle_registration(s);
                continue;
            }
            else if (users_choice == CLIENTS_LIST_STR)
            {
                handle_client_list(s);
                continue;
            }
            else if (users_choice == REQUEST_PUBLIC_KEY_STR)
            {
                handle_request_public_key(s);
                continue;
            }
            else if (users_choice == REQUEST_WAITING_MESSAGES_STR)
            {
                handle_pull_messages(s);
                continue;
            }
            else if (users_choice == SEND_TEXT_MESSAGE_STR || users_choice == SEND_SYMMETRIC_KEY_REQUEST_STR || users_choice == SEND_SYMMETRIC_KEY_STR || users_choice == SEND_FILE_STR)
            {
                handle_send_message_options(s, users_choice);
                continue;
            }
            else // Other menu options will go here
            {
                std::cout << "Invalid option. Please try again.\n"; // unrecognized input
            }
        }

        // 5. Clean up and exit
        s.close();
        std::cout << "Disconnected from server." << std::endl;
    }
    // catch any exceptions from main thread
    catch (std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
    }

    return 0; // end of program
}