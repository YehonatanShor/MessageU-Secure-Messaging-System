#include "MessageUClient.h"
#include "protocol/constants.h"
#include "network/connection.h"
#include "network/protocol_handler.h"
#include "crypto/key_manager.h"
#include "crypto/encryption.h"
#include "storage/file_manager.h"
#include "storage/client_storage.h"
#include "ui/menu.h"
#include "handlers/registration_handler.h"
#include "handlers/client_list_handler.h"
#include "handlers/public_key_handler.h"
#include "handlers/messaging_handler.h"
#include "handlers/deletion_handler.h"
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
        Menu::show_connecting(server_info.host, server_info.port);
        connection_->connect(server_info.host, server_info.port);
        Menu::show_connected();
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
    Menu::show_main_menu();
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
    Menu::show_welcome(g_my_info.name);
}

    // Implementat menu options

// Handles entire registration process of user (input 110/ request code 600)
void MessageUClient::handle_registration()
{
    RegistrationHandler handler(connection_.get(), &g_my_info, &g_is_registered, &g_client_db);
    handler.handle(
        [this]() { return this->is_user_registered(); },
        [this]() { this->load_my_info(); }
    );
}

// Handles reques for client list (input 120/ request code 601)
void MessageUClient::handle_client_list()
{
    ClientListHandler handler(connection_.get(), &g_my_info, &g_is_registered, &g_client_db);
    handler.handle();
}

//Handles requesting another users public key (input 130/ request code 602)
void MessageUClient::handle_request_public_key()
{
    PublicKeyHandler handler(connection_.get(), &g_my_info, &g_is_registered, &g_client_db);
    handler.handle();
}

// Handles pulling waiting messages from  server (input 140/ request code 604)
void MessageUClient::handle_pull_messages()
{
    MessagingHandler handler(connection_.get(), &g_my_info, &g_is_registered, &g_client_db);
    handler.handle_pull_messages();
}

// Handles users choice and calls the appropriate function (inpput 150, 151, 152, 153 / request code 603)
void MessageUClient::handle_send_message_options(const std::string& menu_choice)
{
    MessagingHandler handler(connection_.get(), &g_my_info, &g_is_registered, &g_client_db);
    handler.handle_send_message(menu_choice);
}

// Handles deleting user from server and client (input 154 / request code 605)
void MessageUClient::handle_delete_user()
{
    DeletionHandler handler(connection_.get(), &g_my_info, &g_is_registered, &g_client_db);
    handler.handle();
}

