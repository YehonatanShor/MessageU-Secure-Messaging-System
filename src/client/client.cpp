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
#include <cstdint>      
#include <algorithm>    // For std::min
#include <cryptopp/hex.h>   // For hex encoding

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
const uint8_t  CLIENT_VERSION = 1;
const uint16_t REQUEST_CODE_REGISTER = 600;
const uint16_t REQUEST_CODE_CLIENTS_LIST = 601;
const uint16_t REQUEST_CODE_PUBLIC_KEY = 602;
const uint16_t REQUEST_CODE_SEND_TEXT_MESSAGE = 603;
const uint16_t REQUEST_CODE_WAITING_MESSAGES = 604;
//const uint8_t  CLIENT_ID; // UUID
//const std::string PAYLOAD; // Content of the request

// size in bytes
const size_t CLIENT_UUID_SIZE = 16;
const size_t CLIENT_VERSION_SIZE = 1;
const size_t REQUEST_CODE_SIZE = 2;
const size_t REQUEST_PAYLOAD_SIZE = 4;
const size_t USERNAME_FIXED_SIZE = 255;
const size_t PUBLIC_KEY_FIXED_SIZE = 160;
const size_t REQUEST_HEADER_SIZE = 16 + 1 + 2 + 4; // ClientID(16) + Version(1) + Code(2) + PayloadSize(4)

// server response code to client
const uint8_t  SERVER_VERSION = 1;
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

/**
 * @brief Attempts to load client info from my.info into RAM
 * @return True if successful, False otherwise.
 */
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
    uint32_t net_payload_size = htonl(payload_size); // Convert to network byte order

    // Add header parts
    request_buffer.insert(request_buffer.end(), CLIENT_UUID_SIZE, 0); // Add 16 null bytes as a placeholder for the ClientID
    request_buffer.insert(request_buffer.end(), (char*)&version, (char*)&version + sizeof(version));
    request_buffer.insert(request_buffer.end(), (char*)&code, (char*)&code + sizeof(code));
    request_buffer.insert(request_buffer.end(), (char*)&net_payload_size, (char*)&net_payload_size + sizeof(net_payload_size));
    
    // Add payload parts
    request_buffer.insert(request_buffer.end(), username_payload.begin(), username_payload.end());
    request_buffer.insert(request_buffer.end(), public_key_payload.begin(), public_key_payload.end());
    
    /*
    // Debug: Print the entire request in hex
    std::cout << "the registration request is: ";
    std::copy(request_buffer.begin(), 
              request_buffer.end(), 
              std::ostream_iterator<char>(std::cout, "")); // אין רווחים בין התווים

    std::cout << std::endl;*/

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

/**
 * @brief Handles requesting the client list (Code 120/601)
 */
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
                continue;
            }
            else if (users_choice == "140")
            {
                continue;
            }
            else if (users_choice == "150")
            {
                continue;
            }
            else if (users_choice == "151")
            {
                continue;
            }
            else if (users_choice == "152")
            {
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