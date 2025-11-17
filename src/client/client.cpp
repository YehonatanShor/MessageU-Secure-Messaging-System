// command in terminal: cd C:\Users\User\Documents\Yehonatan\open-university\defensive-programing\MessageU1\src\client
// Compile command:    g++ client.cpp RSAWrapper.cpp Base64Wrapper.cpp AESWrapper.cpp -o client.exe -std=c++17 -lWs2_32 -lpthread -lcryptopp
// Run command:        client.exe

#if defined(_WIN32)
#include <winsock2.h> // For htonl, ntohl
#endif

#include <iostream>
#include <string>
#include <fstream>      // For file I/O
#include <vector>
#include <map>
#include <boost/asio.hpp>
#include <filesystem>
#include <cstdint>      
#include <algorithm>    // For std::min
#include <cryptopp/hex.h>   // For hex encoding
#include <cryptopp/filters.h> // --- ADDED ---: Required for StringSource
#include <cryptopp/files.h>   // --- ADDED ---: Required for StringSink

#include "RSAWrapper.h"     // For asimmetric key crypto and generation
#include "Base64Wrapper.h"  // For saving private key
#include "AESWrapper.h"  // For symmetric key crypto

using boost::asio::ip::tcp;

// --- Configuration File ---
const std::string MY_INFO_FILE = "my.info";
const std::string SERVER_INFO_FILE = "server.info";

// --- Protocol Constants ---
/* users menu code
const uint16_t REGISTER = 110;
const uint16_t CLIENTS_LIST = 120;
const uint16_t REQUEST_PUBLIC_KEY = 130;        
const uint16_t REQUEST_WAITING_MESSAGES = 140;
const uint16_t SEND_TEXT_MESSAGE = 150; 
const uint16_t SEND_SYMMETRIC_KEY_REQUEST = 151;
const uint16_t SEND_SYMMETRIC_KEY = 152;
const uint16_t EXIT_CLIENT = 0;
*/

// client request code from server 
const uint8_t  CLIENT_VERSION = 2;
const uint16_t REQUEST_CODE_REGISTER = 600;
const uint16_t REQUEST_CODE_CLIENTS_LIST = 601;
const uint16_t REQUEST_CODE_PUBLIC_KEY = 602;
const uint16_t REQUEST_CODE_SEND_TEXT_MESSAGE = 603;
const uint16_t REQUEST_CODE_WAITING_MESSAGES = 604;

// Message Types (for payload of code 603)
const uint8_t MSG_TYPE_SYM_KEY_REQUEST = 1;
const uint8_t MSG_TYPE_SYM_KEY_SEND = 2;
const uint8_t MSG_TYPE_TEXT_MESSAGE = 3;
const uint8_t MSG_TYPE_FILE = 4;

// size in bytes
const size_t CLIENT_UUID_SIZE = 16;
const size_t CLIENT_VERSION_SIZE = 1;
const size_t REQUEST_CODE_SIZE = 2;
const size_t REQUEST_PAYLOAD_SIZE = 4;
const size_t USERNAME_FIXED_SIZE = 255;
const size_t PUBLIC_KEY_FIXED_SIZE = 160;
const size_t REQUEST_HEADER_SIZE = 16 + 1 + 2 + 4; // ClientID(16) + Version(1) + Code(2) + PayloadSize(4)

// Payload structure for code 603 (Send Message)
const size_t MSG_TARGET_ID_SIZE = CLIENT_UUID_SIZE; // 16 bytes
const size_t MSG_TYPE_SIZE = 1; // 1 byte
const size_t MSG_CONTENT_SIZE_FIELD_SIZE = 4; // 4 bytes
const size_t MSG_HEADER_SIZE = MSG_TARGET_ID_SIZE + MSG_TYPE_SIZE + MSG_CONTENT_SIZE_FIELD_SIZE;

// server response code to client
const uint8_t  SERVER_VERSION = 2;
const uint16_t RESPONSE_CODE_REGISTER_SUCCESS = 2100;
const uint16_t RESPONSE_CODE_DISPLAYING_CLIENTS_LIST = 2101;
const uint16_t RESPONSE_CODE_SEND_PUBLIC_KEY = 2102;
const uint16_t RESPONSE_CODE_SEND_TEXT_MESSAGE = 2103;
const uint16_t RESPONSE_CODE_PULL_WAITING_MESSAGE = 2104;
const uint16_t RESPONSE_CODE_GENERAL_ERROR = 9000;

// size in bytes
const size_t SERVER_VERSION_SIZE = 1;
const size_t RESPONSE_CODE_SIZE = 2;
const size_t RESPONSE_PAYLOAD_SIZE = 4;
const size_t RESPONSE_HEADER_SIZE = 1 + 2 + 4; // Version(1) + Code(2) + PayloadSize(4)

// Client-side RAM Storage
struct ClientInfo {
    std::string username;
    // std::string uuid; // stored as hex ASCII
    std::string public_key;
    std::string symmetric_key; // For later
};
std::map<std::string, ClientInfo> g_client_db; // store clients info by UUID, key is UUID in hex ASCII

// Holds info about *this* client, loaded from my.info
struct MyInfo {
    std::string name;
    std::string uuid_hex;
    std::string uuid_bin; // 16-byte binary version of the UUID
    RSAPrivateWrapper* keys = nullptr; // Pointer to our keys
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

//convert binary UUID to ASCII Hex
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

// Helper function to trim whitespace from both ends of a string
std::string trim(const std::string& s) {
    auto start = std::find_if_not(s.begin(), s.end(), [](unsigned char c){ return std::isspace(c); });
    auto end = std::find_if_not(s.rbegin(), s.rend(), [](unsigned char c){ return std::isspace(c); }).base();
    return (start < end ? std::string(start, end) : std::string());
}

std::string trim_nulls(const char* buffer, size_t length)
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
    if (user != g_client_db.end())
    {
        return user->second.username;
    }
    // If UUID not in our local DB, check if it's our own UUID
    if (uuid_hex == g_my_info.uuid_hex)
    {
        return g_my_info.name;
    }
    return "Unknown";
}

//  Searches the in-RAM client DB for a user's UUID by their name
std::string find_uuid_by_name(const std::string& name)
{
    // Loop through our global map (g_client_db)
    // 'pair' will be one entry, e.g., <"UUID_HEX_STRING", ClientInfo_Object>
    for (const auto& pair : g_client_db) 
    {
        // Check if the username in the map matches the name we're looking for
        if (pair.second.username == name)
        {
            // if found, convert the UUID from hex ASCII to binary and return it
            return hex_ascii_to_binary(pair.first);
        }
    }
    // If the loop finishes without finding a match
    return ""; // Return an empty string
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
        
        // Read the rest of the file for the (potentially multi-line) Base64 key
        std::string line;
        while (std::getline(f, line)) {
            private_key_b64 += line;
        }
        f.close();

        if (name.empty() || uuid_hex.empty() || private_key_b64.empty()) {
            std::cerr << "Error: " << MY_INFO_FILE << " is corrupt or incomplete.\n";
            return false;
        }

        // Load into RAM
        g_my_info.name = name;
        g_my_info.uuid_hex = uuid_hex;
        g_my_info.uuid_bin = hex_ascii_to_binary(uuid_hex);
        g_my_info.keys = new RSAPrivateWrapper(Base64Wrapper::decode(private_key_b64));
        
        g_is_registered = true;
        std::cout << "Welcome back, " << g_my_info.name << "!" << std::endl;
        return true;
    }
    catch (std::exception& e) {
        std::cerr << "Error loading " << MY_INFO_FILE << ": " << e.what() << "\n";
        return false;
    }
}

//Handles the entire registration process
void handle_registration(tcp::socket& s)
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
    if (username.empty()) { // check if username is empty
        std::cerr << "Error: Username cannot be empty.\n";
        return;
    }
    if (username.length() > USERNAME_FIXED_SIZE) { // check if username is too long - more than 255 chars
        std::cerr << "Error: Username too long (max " << USERNAME_FIXED_SIZE << " chars).\n";
        return;
    }

    // Generate new RSA keys - asimmetric key pair
    std::cout << "Generating RSA keys (this may take a moment)..." << std::endl;
    RSAPrivateWrapper my_keys;
    std::string public_key_bin = my_keys.getPublicKey();
    std::string private_key_bin = my_keys.getPrivateKey();
    std::string private_key_b64 = Base64Wrapper::encode(private_key_bin); // Save private key in Base64

    // Create a 255-byte buffer for the username and copy the username into it
    std::vector<char> username_payload(USERNAME_FIXED_SIZE, 0); // Fills with 255 null bytes
    std::memcpy(username_payload.data(), username.c_str(), username.length());

    // Create a 160-byte buffer for the public key
    std::vector<char> public_key_payload(PUBLIC_KEY_FIXED_SIZE, 0); // Fills with 160 null bytes
    size_t key_copy_size = std::min((size_t)PUBLIC_KEY_FIXED_SIZE, public_key_bin.length());
    std::memcpy(public_key_payload.data(), public_key_bin.c_str(), key_copy_size);

    // Build the full request (Header + Payload)
    uint32_t payload_size = USERNAME_FIXED_SIZE + PUBLIC_KEY_FIXED_SIZE;
    
    std::vector<char> request_buffer; // Final request buffer
    request_buffer.reserve(REQUEST_HEADER_SIZE + payload_size); // Pre-allocate memory

    uint8_t version = CLIENT_VERSION;
    uint16_t code = htons(REQUEST_CODE_REGISTER); // Convert to network byte order
    uint32_t reg_payload_size = htonl(payload_size); // Convert to network byte order

    // Add header parts
    request_buffer.insert(request_buffer.end(), CLIENT_UUID_SIZE, 0); // Add 16 null bytes as a placeholder for the ClientID
    request_buffer.insert(request_buffer.end(), (char*)&version, (char*)&version + sizeof(version));
    request_buffer.insert(request_buffer.end(), (char*)&code, (char*)&code + sizeof(code));
    request_buffer.insert(request_buffer.end(), (char*)&reg_payload_size, (char*)&reg_payload_size + sizeof(reg_payload_size));
    
    // Add payload parts
    request_buffer.insert(request_buffer.end(), username_payload.begin(), username_payload.end());
    request_buffer.insert(request_buffer.end(), public_key_payload.begin(), public_key_payload.end());

    // Send request
    std::cout << "Sending registration request to server..." << std::endl;
    boost::asio::write(s, boost::asio::buffer(request_buffer));

    // Wait for server response (Header)
    std::vector<char> response_header(RESPONSE_HEADER_SIZE);
    boost::asio::read(s, boost::asio::buffer(response_header));

    // Parse response header
    uint16_t response_code; // to hold response code from server
    uint32_t response_payload_size; // to hold payload size from server
    
    std::memcpy(&response_code, response_header.data() + SERVER_VERSION_SIZE, RESPONSE_CODE_SIZE);
    std::memcpy(&response_payload_size, response_header.data() + SERVER_VERSION_SIZE + RESPONSE_CODE_SIZE, RESPONSE_PAYLOAD_SIZE);
    
    // Convert from network byte order
    response_code = ntohs(response_code); 
    response_payload_size = ntohl(response_payload_size);

    // Read response payload
    std::vector<char> response_payload(response_payload_size);
    boost::asio::read(s, boost::asio::buffer(response_payload));

    // Process response
    if (response_code == RESPONSE_CODE_REGISTER_SUCCESS)
    {
        if (response_payload_size != CLIENT_UUID_SIZE) {
            std::cerr << "Error: Server sent invalid UUID size.\n";
            return;
        }
        
        // 11. Convert binary UUID to ASCII Hex
        std::string uuid_bin(response_payload.begin(), response_payload.end());
        std::string uuid_hex = binary_to_hex_ascii(uuid_bin);
        
        std::cout << "Registration successful! Your UUID is: " << uuid_hex << std::endl; // Print the UUID for debugging

        // 12. Save to my.info
        std::ofstream outfile(MY_INFO_FILE);
        outfile << username << "\n";      // Line 1: Username
        outfile << uuid_hex << "\n";        // Line 2: UUID (as ASCII Hex)
        outfile << private_key_b64;     // Line 3: Private Key (Base64)
        outfile.close();

        // 13. Load info into RAM for current session
        std::cout << "Loading info into session..." << std::endl;
        load_my_info();
    }
    else if (response_code == REQUEST_CODE_CLIENTS_LIST)
    {
        std::cerr << "Server reported an error with no details.\n";
    }
    else if (response_code == RESPONSE_CODE_GENERAL_ERROR)
    {
        std::cerr << "Server reported an error.\n";
    }
    else // Got an error from the server
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
    std::vector<char> request_buffer;
    request_buffer.reserve(REQUEST_HEADER_SIZE);

    uint8_t version = CLIENT_VERSION;
    uint16_t code = htons(REQUEST_CODE_CLIENTS_LIST);
    uint32_t net_payload_size = htonl(0); // Payload size is 0

    // Add header parts
    // We *must* send our UUID so the server knows who is asking
    request_buffer.insert(request_buffer.end(), g_my_info.uuid_bin.begin(), g_my_info.uuid_bin.end());
    request_buffer.insert(request_buffer.end(), (char*)&version, (char*)&version + sizeof(version));
    request_buffer.insert(request_buffer.end(), (char*)&code, (char*)&code + sizeof(code));
    request_buffer.insert(request_buffer.end(), (char*)&net_payload_size, (char*)&net_payload_size + sizeof(net_payload_size));
    
    // 3. Send request (no payload)
    std::cout << "Requesting client list from server..." << std::endl;
    boost::asio::write(s, boost::asio::buffer(request_buffer));

    // 4. Wait for server response (Header)
    std::vector<char> response_header(RESPONSE_HEADER_SIZE);
    boost::asio::read(s, boost::asio::buffer(response_header));

    // 5. Parse response header
    uint16_t response_code;
    uint32_t response_payload_size;
    std::memcpy(&response_code, response_header.data() + SERVER_VERSION_SIZE, RESPONSE_CODE_SIZE);
    std::memcpy(&response_payload_size, response_header.data() + SERVER_VERSION_SIZE + RESPONSE_CODE_SIZE, RESPONSE_PAYLOAD_SIZE);
    response_code = ntohs(response_code);
    response_payload_size = ntohl(response_payload_size);
    
    // 6. Read response payload
    std::vector<char> response_payload(response_payload_size);
    if (response_payload_size > 0) {
        boost::asio::read(s, boost::asio::buffer(response_payload));
    }

    // 7. Process response
    if (response_code == RESPONSE_CODE_DISPLAYING_CLIENTS_LIST)
    {
        std::cout << "\n--- Registered Clients ---" << std::endl;
        g_client_db.clear(); // Clear the old list
        
        const size_t entry_size = CLIENT_UUID_SIZE + USERNAME_FIXED_SIZE;
        if (response_payload_size % entry_size != 0) {
            std::cerr << "Error: Server sent a corrupt client list.\n";
            return;
        }

        // Loop through the payload, one client at a time
        for (size_t i = 0; i < response_payload_size; i += entry_size)
        {
            const char* entry_ptr = response_payload.data() + i;
            
            std::string uuid_bin(entry_ptr, CLIENT_UUID_SIZE);
            std::string uuid_hex = binary_to_hex_ascii(uuid_bin);
            
            // Trim null bytes from the fixed-size name field
            std::string name = trim_nulls(entry_ptr + CLIENT_UUID_SIZE, USERNAME_FIXED_SIZE);

            // Print to screen
            std::cout << "Name: " << name << "\nUUID: " << uuid_hex << "\n---\n";
            
            // Save to our in-RAM database
            g_client_db[uuid_hex].username = name;
            // (We will get the public key in step 130)
        }
    }
    else
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

    // 4. Build the request header (23 bytes)
    std::vector<char> request_buffer;
    request_buffer.reserve(REQUEST_HEADER_SIZE + target_uuid_bin.length());

    uint8_t version = CLIENT_VERSION;
    uint16_t code = htons(REQUEST_CODE_PUBLIC_KEY); // Code 602
    uint32_t net_payload_size = htonl(target_uuid_bin.length()); // Payload is the 16-byte UUID

    // Add header parts
    request_buffer.insert(request_buffer.end(), g_my_info.uuid_bin.begin(), g_my_info.uuid_bin.end()); // Our UUID
    request_buffer.insert(request_buffer.end(), (char*)&version, (char*)&version + sizeof(version));
    request_buffer.insert(request_buffer.end(), (char*)&code, (char*)&code + sizeof(code));
    request_buffer.insert(request_buffer.end(), (char*)&net_payload_size, (char*)&net_payload_size + sizeof(net_payload_size));
    
    // 5. Add payload (the target's UUID)
    request_buffer.insert(request_buffer.end(), target_uuid_bin.begin(), target_uuid_bin.end());

    // 6. Send request
    std::cout << "Requesting public key for " << target_username << "..." << std::endl;
    boost::asio::write(s, boost::asio::buffer(request_buffer));

    // 7. Wait for server response (Header)
    std::vector<char> response_header(RESPONSE_HEADER_SIZE);
    boost::asio::read(s, boost::asio::buffer(response_header));

    // 8. Parse response header
    uint16_t response_code;
    uint32_t response_payload_size;
    std::memcpy(&response_code, response_header.data() + SERVER_VERSION_SIZE, RESPONSE_CODE_SIZE);
    std::memcpy(&response_payload_size, response_header.data() + SERVER_VERSION_SIZE + RESPONSE_CODE_SIZE, RESPONSE_PAYLOAD_SIZE);
    response_code = ntohs(response_code);
    response_payload_size = ntohl(response_payload_size);

    // 9. Read response payload
    std::vector<char> response_payload(response_payload_size);
    if (response_payload_size > 0) {
        boost::asio::read(s, boost::asio::buffer(response_payload));
    }

    // 10. Process response
    if (response_code == RESPONSE_CODE_SEND_PUBLIC_KEY)
    {
        // Expected payload: Target's UUID (16) + Target's Public Key (160)
        const size_t expected_size = CLIENT_UUID_SIZE + PUBLIC_KEY_FIXED_SIZE;
        if (response_payload_size != expected_size) {
            std::cerr << "Error: Server sent a corrupt public key payload.\n";
            return;
        }

        // Extract data
        std::string target_uuid_bin(response_payload.data(), CLIENT_UUID_SIZE);
        std::string target_pub_key(response_payload.data() + CLIENT_UUID_SIZE, PUBLIC_KEY_FIXED_SIZE);
        
        std::string target_uuid_hex = binary_to_hex_ascii(target_uuid_bin);

        // 11. Store the public key in our in-RAM database
        g_client_db[target_uuid_hex].public_key = target_pub_key;
        
        std::cout << "Successfully received and stored public key for:\n";
        std::cout << "Name: " << g_client_db[target_uuid_hex].username << "\n";
        std::cout << "UUID: " << target_uuid_hex << "\n";
        //std::cout << "public key: " << Base64Wrapper::encode(target_pub_key) << "\n"; // Print public key in Base64 for readability
    }
    else
    {
        std::string error_msg(response_payload.begin(), response_payload.end());
        std::cerr << "Server responded with an error: " << error_msg << std::endl;
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

// Main handler for options 150, 151, 152 - gets the target user and calls the appropriate function
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

    // 3. Find the target's UUID in our local RAM DB (g_client_db)
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

    // --- Logic for 151: Request Symmetric Key ---
    if (menu_choice == "151")
    {
        message_type = MSG_TYPE_SYM_KEY_REQUEST;
        // message_content remains empty, as requested
    }
    // --- Logic for 152: Send Symmetric Key ---
    else if (menu_choice == "152")
    {
        message_type = MSG_TYPE_SYM_KEY_SEND;
        
        // 4a. Check if we have the target's public key
        if (g_client_db[target_uuid_hex].public_key.empty()) {
            std::cerr << "Error: You don't have the public key for '" << target_username << "'.\n";
            std::cerr << "Try running option 130 to get their key first.\n";
            return;
        }

        // 4b. Generate a new symmetric key (AES key)
        unsigned char aes_key_bytes[AESWrapper::DEFAULT_KEYLENGTH];
        AESWrapper::GenerateKey(aes_key_bytes, AESWrapper::DEFAULT_KEYLENGTH);
        std::string aes_key_bin((char*)aes_key_bytes, AESWrapper::DEFAULT_KEYLENGTH);

        // 4c. Encrypt the *symmetric* key using the *target's public* key
        try {
            RSAPublicWrapper target_public_key(g_client_db[target_uuid_hex].public_key);
            message_content = target_public_key.encrypt(aes_key_bin); // Encrypt the AES key
        } catch (std::exception& e) {
            std::cerr << "Error encrypting symmetric key: " << e.what() << "\n";
            return;
        }

        // 4d. Save this symmetric key in our RAM DB for *this user*
        g_client_db[target_uuid_hex].symmetric_key = aes_key_bin;
        std::cout << "Generated and sent a new symmetric key to " << target_username << ".\n";
    }
    // --- Logic for 150 (Text) AND 153 (File) ---
    else if (menu_choice == "150" || menu_choice == "153")
    {
        // 4a. Check for symmetric key
        std::string sym_key = g_client_db[target_uuid_hex].symmetric_key;
        if (sym_key.empty()) {
            std::cerr << "Error: You don't have a symmetric key for '" << target_username << "'.\n";
            return;
        }

        std::string data_to_encrypt;

        if (menu_choice == "150") { // Text Message
            message_type = MSG_TYPE_TEXT_MESSAGE;
            std::cout << "Enter your message: ";
            std::getline(std::cin, data_to_encrypt);
            if (data_to_encrypt.empty()) return;
        }
        else { // File Transfer (153)
            message_type = MSG_TYPE_FILE;
            std::cout << "Enter full file path: ";
            std::string filepath;
            std::getline(std::cin, filepath);
            // Remove potential quotes around path (common when dragging files to terminal)
            filepath.erase(std::remove(filepath.begin(), filepath.end(), '\"'), filepath.end());

            try {
                data_to_encrypt = read_file_content(filepath);
                std::cout << "Read " << data_to_encrypt.size() << " bytes from file.\n";
            } catch (std::exception& e) {
                std::cerr << "Error: " << e.what() << "\n"; // Prints "found not file" equivalent
                return;
            }
        }

        // 4c. Encrypt the data (text or file content)
        try {
            AESWrapper aes_encryptor((unsigned char*)sym_key.c_str(), sym_key.length());
            message_content = aes_encryptor.encrypt(data_to_encrypt.c_str(), data_to_encrypt.length());
        } catch (std::exception& e) {
            std::cerr << "Error encrypting: " << e.what() << "\n";
            return;
        }
    }

    // 5. Build the inner payload (for request 603)
    std::vector<char> message_payload;
    uint32_t content_size_net = htonl(message_content.length());

    message_payload.insert(message_payload.end(), target_uuid_bin.begin(), target_uuid_bin.end()); // 16 bytes Target UUID
    message_payload.push_back(message_type); // 1 byte Message Type
    message_payload.insert(message_payload.end(), (char*)&content_size_net, (char*)&content_size_net + sizeof(content_size_net)); // 4 bytes Content Size
    message_payload.insert(message_payload.end(), message_content.begin(), message_content.end()); // N bytes Content

    // 6. Build the full request (Header + Payload)
    std::vector<char> request_buffer;
    uint8_t version = CLIENT_VERSION;
    uint16_t code = htons(REQUEST_CODE_SEND_TEXT_MESSAGE); // Code 603
    uint32_t net_payload_size = htonl(message_payload.size());

    // Add header parts
    request_buffer.insert(request_buffer.end(), g_my_info.uuid_bin.begin(), g_my_info.uuid_bin.end()); // Our UUID
    request_buffer.insert(request_buffer.end(), (char*)&version, (char*)&version + sizeof(version));
    request_buffer.insert(request_buffer.end(), (char*)&code, (char*)&code + sizeof(code));
    request_buffer.insert(request_buffer.end(), (char*)&net_payload_size, (char*)&net_payload_size + sizeof(net_payload_size));
    
    // Add payload part
    request_buffer.insert(request_buffer.end(), message_payload.begin(), message_payload.end());

    // 7. Send request
    std::cout << "Sending message to server..." << std::endl;
    boost::asio::write(s, boost::asio::buffer(request_buffer));

    // 8. Wait for server response (Header)
    std::vector<char> response_header(RESPONSE_HEADER_SIZE);
    boost::asio::read(s, boost::asio::buffer(response_header));

    // 9. Parse response header
    uint16_t response_code;
    uint32_t response_payload_size;
    std::memcpy(&response_code, response_header.data() + SERVER_VERSION_SIZE, RESPONSE_CODE_SIZE);
    std::memcpy(&response_payload_size, response_header.data() + SERVER_VERSION_SIZE + RESPONSE_CODE_SIZE, RESPONSE_PAYLOAD_SIZE);
    response_code = ntohs(response_code);
    response_payload_size = ntohl(response_payload_size);

    // 10. Read response payload
    std::vector<char> response_payload(response_payload_size);
    if (response_payload_size > 0) {
        boost::asio::read(s, boost::asio::buffer(response_payload));
    }

    // 11. Process response
    if (response_code == RESPONSE_CODE_SEND_TEXT_MESSAGE)
    {
        // Expected payload: Target's UUID (16) + Message ID (4)
        if (response_payload_size != CLIENT_UUID_SIZE + sizeof(uint32_t)) {
            std::cerr << "Error: Server sent a corrupt message confirmation.\n";
            return;
        }

        uint32_t message_id;
        std::memcpy(&message_id, response_payload.data() + CLIENT_UUID_SIZE, sizeof(uint32_t));
        message_id = ntohl(message_id);

        std::cout << "Server confirmed message sent. Message ID: " << message_id << "\n";
    }
    else
    {
        std::string error_msg(response_payload.begin(), response_payload.end());
        std::cerr << "Server responded with an error: " << error_msg << std::endl;
    }
}

// client.cpp

void handle_pull_messages(tcp::socket& s)
{
    // 1. Check if user is registered
    if (!g_is_registered) {
        std::cerr << "Error: You must be registered to perform this action.\n";
        return;
    }

    // 2. Build the request header (23 bytes, no payload)
    // Using manual buffer instead of vector for efficiency
    char request_buffer[REQUEST_HEADER_SIZE];
    
    // 16 bytes UUID
    std::memcpy(request_buffer, g_my_info.uuid_bin.data(), CLIENT_UUID_SIZE);
    // 1 byte - client version
    request_buffer[CLIENT_UUID_SIZE] = CLIENT_VERSION;
    // 2 bytes - Request Code (604)
    uint16_t request_code = htons(REQUEST_CODE_WAITING_MESSAGES); // Code 604
    std::memcpy(request_buffer + CLIENT_UUID_SIZE + 1, &request_code, sizeof(uint16_t));
    // 4 bytes - payload size (0)
    uint32_t request_payload_size = htonl(0); // Payload size is 0
    std::memcpy(request_buffer + CLIENT_UUID_SIZE + 1 + 2, &request_payload_size, sizeof(uint32_t));

     // 3. Send request
    std::cout << "Requesting waiting messages from server..." << std::endl;
    boost::asio::write(s, boost::asio::buffer(request_buffer, REQUEST_HEADER_SIZE));


    // 4. Wait for server response (Header)
    char response_header[RESPONSE_HEADER_SIZE];
    boost::asio::read(s, boost::asio::buffer(response_header, RESPONSE_HEADER_SIZE));

    // 5. Parse response header
    uint16_t response_code;
    uint32_t total_payload_size; // total size of all messages payloads
    std::memcpy(&response_code, response_header + SERVER_VERSION_SIZE, RESPONSE_CODE_SIZE);
    std::memcpy(&total_payload_size, response_header + SERVER_VERSION_SIZE + RESPONSE_CODE_SIZE, RESPONSE_PAYLOAD_SIZE);
    response_code = ntohs(response_code);
    total_payload_size = ntohl(total_payload_size);

    // check that response code is correct
    if (response_code != RESPONSE_CODE_PULL_WAITING_MESSAGE) {
        std::cerr << "Server responded with an error (Wrong Code " << response_code << ")\n";
        return;
    }

    if (total_payload_size == 0) {
        std::cout << "You have no new messages.\n";
        return;
    }

    std::cout << "\n--- Received Messages ---" << std::endl;
    
    size_t bytes_processed = 0;
    // 6. Process response messages one by one until we reach total payload size
    while (bytes_processed < total_payload_size)
    {
        // 6a. read header of a single message
        // size of header: 16 + 4 + 1 + 4 = 25 bytes (FromUUID + MsgID + Type + Size)
        const size_t SINGLE_MSG_HEADER_SIZE = CLIENT_UUID_SIZE + 4 + 1 + 4;
        char msg_header[SINGLE_MSG_HEADER_SIZE];
        
        // Blocking read from socket for header only
        boost::asio::read(s, boost::asio::buffer(msg_header, SINGLE_MSG_HEADER_SIZE));
        bytes_processed += SINGLE_MSG_HEADER_SIZE;

        // 6b.Parse the message header
        size_t cursor = 0;
        std::string from_uuid_bin(msg_header + cursor, CLIENT_UUID_SIZE);
        cursor += CLIENT_UUID_SIZE;

        uint32_t msg_id;
        std::memcpy(&msg_id, msg_header + cursor, sizeof(uint32_t));
        msg_id = ntohl(msg_id);
        cursor += sizeof(uint32_t);

        uint8_t msg_type = msg_header[cursor];
        cursor += sizeof(uint8_t);

        uint32_t msg_content_size;
        std::memcpy(&msg_content_size, msg_header + cursor, sizeof(uint32_t));
        msg_content_size = ntohl(msg_content_size);
        cursor += sizeof(uint32_t);

        // 6c. Extract the message content
        std::vector<char> content_buffer(msg_content_size); // Allocate vector of exact current size message content
        boost::asio::read(s, boost::asio::buffer(content_buffer));
        bytes_processed += msg_content_size;
        
        // convert content to string for easier handling
        std::string content(content_buffer.begin(), content_buffer.end());

        // 6d. Display the message based on its type
        std::cout << "From: " << find_name_by_uuid(from_uuid_bin) << "\n";
        std::cout << "Content:\n";

        switch (msg_type)
        {
            // Type 1 - Request Symmetric Key
            case MSG_TYPE_SYM_KEY_REQUEST: 
                std::cout << "Request for symmetric key\n";
                break;
            
            // Type 2 - Send Symmetric Key
            case MSG_TYPE_SYM_KEY_SEND:
                std::cout << "Symmetric key received.\n";
                try {
                     // Decrypt the symmetric key using our *private* key
                    std::string decrypted_sym_key = g_my_info.keys->decrypt(content);
                    // Store it in our RAM DB
                    std::string from_uuid_hex = binary_to_hex_ascii(from_uuid_bin);
                    g_client_db[from_uuid_hex].symmetric_key = decrypted_sym_key;
                    std::cout << "(Symmetric key stored successfully)\n";
                } catch (std::exception& e) {
                    std::cout << "Error decrypting symmetric key\n";
                }
                break;
            
            case MSG_TYPE_TEXT_MESSAGE: // Type 3 - send text Message
            case MSG_TYPE_FILE: // Type 4 - File Transfer
            {
                 // Find the symmetric key we have for this sender
                std::string from_uuid_hex = binary_to_hex_ascii(from_uuid_bin);
                std::string sym_key = g_client_db[from_uuid_hex].symmetric_key;

                if (sym_key.empty()) {
                    std::cout << "can't decrypt message (no symmetric key)\n";
                } else {
                    try {
                        // Decrypt the message content using the stored AES key
                        AESWrapper aes((unsigned char*)sym_key.c_str(), sym_key.length());
                        std::string decrypted = aes.decrypt(content.c_str(), content.length());

                        // if text message
                        if (msg_type == MSG_TYPE_TEXT_MESSAGE) {
                            // Print to console; if file, save to temp file
                            std::cout << decrypted << "\n";
                        } 
                        // else - if file
                        else {
                            auto temp_path = std::filesystem::temp_directory_path() / ("msg_" + std::to_string(msg_id) + ".tmp");
                            // Write binary data to temp file
                            std::ofstream outfile(temp_path, std::ios::binary);
                            outfile.write(decrypted.data(), decrypted.size());
                            outfile.close();
                            std::cout << "File received! Saved to: " << temp_path << "\n";
                        }
                    } catch (std::exception&) {
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

/* Handles requesting waiting messages from the server (Code 140) 
void handle_pull_messages(tcp::socket& s)
{
    // 1. Check if user is registered
    if (!g_is_registered) {
        std::cerr << "Error: You must be registered to perform this action.\n";
        return;
    }

    // 2. Build the request header (23 bytes, no payload)
    std::vector<char> request_buffer;
    request_buffer.reserve(REQUEST_HEADER_SIZE);

    uint8_t version = CLIENT_VERSION;
    uint16_t code = htons(REQUEST_CODE_WAITING_MESSAGES); // Code 604
    uint32_t net_payload_size = htonl(0); // Payload size is 0

    // Add header parts
    request_buffer.insert(request_buffer.end(), g_my_info.uuid_bin.begin(), g_my_info.uuid_bin.end()); // Our UUID
    request_buffer.insert(request_buffer.end(), (char*)&version, (char*)&version + sizeof(version));
    request_buffer.insert(request_buffer.end(), (char*)&code, (char*)&code + sizeof(code));
    request_buffer.insert(request_buffer.end(), (char*)&net_payload_size, (char*)&net_payload_size + sizeof(net_payload_size));
    
    // 3. Send request
    std::cout << "Requesting waiting messages from server..." << std::endl;
    boost::asio::write(s, boost::asio::buffer(request_buffer));

    // 4. Wait for server response (Header)
    std::vector<char> response_header(RESPONSE_HEADER_SIZE);
    boost::asio::read(s, boost::asio::buffer(response_header));

    // 5. Parse response header
    uint16_t response_code;
    uint32_t response_payload_size;
    std::memcpy(&response_code, response_header.data() + SERVER_VERSION_SIZE, RESPONSE_CODE_SIZE);
    std::memcpy(&response_payload_size, response_header.data() + SERVER_VERSION_SIZE + RESPONSE_CODE_SIZE, RESPONSE_PAYLOAD_SIZE);
    response_code = ntohs(response_code);
    response_payload_size = ntohl(response_payload_size);

    // 6. Read response payload (which contains all the messages)
    std::vector<char> response_payload(response_payload_size);
    if (response_payload_size > 0) {
        boost::asio::read(s, boost::asio::buffer(response_payload));
    }

    // 7. Process response
    if (response_code == RESPONSE_CODE_PULL_WAITING_MESSAGE)
    {
        if (response_payload_size == 0) {
            std::cout << "You have no new messages.\n";
            return;
        }
        
        std::cout << "\n--- Received Messages ---" << std::endl;
        
        // 8. Loop through the payload, one message at a time
        size_t cursor = 0;
        while (cursor < response_payload_size)
        {
            // 8a. Parse the message header (FromUUID, MsgID, Type, ContentSize)
            std::string from_uuid_bin(response_payload.data() + cursor, CLIENT_UUID_SIZE);
            cursor += CLIENT_UUID_SIZE;

            uint32_t msg_id;
            std::memcpy(&msg_id, response_payload.data() + cursor, sizeof(uint32_t));
            msg_id = ntohl(msg_id);
            cursor += sizeof(uint32_t);

            uint8_t msg_type = response_payload[cursor];
            cursor += sizeof(uint8_t);

            uint32_t msg_content_size;
            std::memcpy(&msg_content_size, response_payload.data() + cursor, sizeof(uint32_t));
            msg_content_size = ntohl(msg_content_size);
            cursor += sizeof(uint32_t);

            // 8b. Extract the message content
            std::string content(response_payload.data() + cursor, msg_content_size);
            cursor += msg_content_size;

            // 8c. Display the message based on its type
            std::cout << "From: " << find_name_by_uuid(from_uuid_bin) << "\n";
            std::cout << "Content:\n";

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
                        std::string decrypted_sym_key = g_my_info.keys->decrypt(content);
                        // Store it in our RAM DB
                        std::string from_uuid_hex = binary_to_hex_ascii(from_uuid_bin);
                        g_client_db[from_uuid_hex].symmetric_key = decrypted_sym_key;
                        std::cout << "(Symmetric key stored successfully)\n";
                    } catch (std::exception& e) {
                        std::cerr << "(Error decrypting symmetric key: " << e.what() << ")\n";
                    }
                    break;
                }
                
                case MSG_TYPE_TEXT_MESSAGE: // Type 3 - send text Message
                {
                    // Find the symmetric key we have for this sender
                    std::string from_uuid_hex = binary_to_hex_ascii(from_uuid_bin);
                    std::string sym_key = g_client_db[from_uuid_hex].symmetric_key;

                    if (sym_key.empty()) {
                        std::cout << "can’t decrypt message (no symmetric key on file)\n";
                    } else {
                        try {
                            // Decrypt the message using the stored AES key
                            AESWrapper aes_decryptor((unsigned char*)sym_key.c_str(), sym_key.length());
                            std::string decrypted_text = aes_decryptor.decrypt(content.c_str(), content.length());
                            std::cout << decrypted_text << "\n";
                        } catch (std::exception& e) {
                            std::cerr << "can’t decrypt message (decryption failed)\n";
                        }
                    }
                    break;
                }

                case MSG_TYPE_FILE: // Type 4 - send a file
                {
                    std::string from_uuid_hex = binary_to_hex_ascii(from_uuid_bin);
                    std::string sym_key = g_client_db[from_uuid_hex].symmetric_key;

                    if (sym_key.empty()) {
                        std::cout << "can’t decrypt message (no symmetric key on file)\n";
                    } else {
                        try {
                            // Decrypt content
                            AESWrapper aes_decryptor((unsigned char*)sym_key.c_str(), sym_key.length());
                            std::string decrypted_content = aes_decryptor.decrypt(content.c_str(), content.length());

                            if (msg_type == MSG_TYPE_TEXT_MESSAGE) {
                                std::cout << decrypted_content << "\n";
                            }
                            else { // It's a file! Save it.
                                // Create a temporary file path
                                auto temp_path = std::filesystem::temp_directory_path() / ("msg_" + std::to_string(msg_id) + ".tmp");
                                
                                // Write binary data to file
                                std::ofstream outfile(temp_path, std::ios::binary);
                                outfile.write(decrypted_content.data(), decrypted_content.size());
                                outfile.close();
                                
                                std::cout << "File received! Saved to: " << temp_path << "\n";
                            }
                        } catch (std::exception& e) {
                            std::cerr << "can’t decrypt message (decryption failed)\n";
                        }
                    }
                    break;
                }
                
                default:
                    std::cout << "Unknown message type received.\n";
            }
            std::cout << ".\n";
            std::cout << ".\n";
            std::cout << "----<EOM>----\n\n";
        }
    }
    else
    {
        std::string error_msg(response_payload.begin(), response_payload.end());
        std::cerr << "Server responded with an error: " << error_msg << std::endl;
    }
} */

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
        return { line.substr(0, colon_pos), line.substr(colon_pos + 1) }; // std::pair<std::string, std::string> (host, port)
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

        // Load server info from file
        auto server_info = load_server_info();
        host = server_info.first; 
        port = server_info.second;
    }
    catch (std::exception& e) // catch errors from loading server info
    {
        std::cerr << e.what() << std::endl;
        return 1;
    }
   
    std::cout << "Connecting to " << host << ":" << port << "..." << std::endl;

    try
    {
        boost::asio::io_context io_context;
        tcp::socket s(io_context);
        tcp::resolver resolver(io_context);
        boost::asio::connect(s, resolver.resolve(host, port));
        
        std::cout << "Connected successfully." << std::endl;

        // --- Main Menu Loop ---
        std::string users_choice;
        while (true)
        {
            show_menu();
            std::getline(std::cin, users_choice);
            users_choice = trim(users_choice); // Trim whitespace
            
            if (users_choice == "0") {
                break; // Exit loop
            }
            else if (users_choice == "110") {
                handle_registration(s);
                continue;
            }
            else if (users_choice == "120")
            {
                handle_client_list(s);
                continue;
            }
            else if (users_choice == "130")
            {
                handle_request_public_key(s);
                continue;
            }
            else if (users_choice == "140")
            {
                handle_pull_messages(s);
                continue;
            }
            else if (users_choice == "150" || users_choice == "151" || users_choice == "152" || users_choice == "153")
            {
                handle_send_message_options(s, users_choice);
                continue;
            }
            else // Other menu options will go here
            {
                std::cout << "Invalid option. Please try again.\n"; // unrecognized input
            }
        }
        
        s.close(); // Close the socket
        std::cout << "Disconnected from server." << std::endl;
    }
    catch (std::exception& e) // catch any exceptions from main thread
    {
        std::cerr << "Exception: " << e.what() << "\n";
    }

    return 0; // end of program
}