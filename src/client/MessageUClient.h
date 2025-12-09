#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <boost/asio.hpp>
#include "RSAWrapper.h"

using boost::asio::ip::tcp;

// Client-side RAM Storage structure
struct ClientInfo {
    std::string username;
    std::string public_key;
    std::string symmetric_key;
};

// MessageUClient class for managing client operations
class MessageUClient
{
public:
    // Constructor and Destructor
    MessageUClient();
    ~MessageUClient();

    // Connection management
    void connect();
    void close();

    // Show menu to user
    void show_menu();

    // Main functions for implementing the menu
    void handle_registration();             // 110
    void handle_client_list();              // 120
    void handle_request_public_key();       // 130
    void handle_pull_messages();            // 140
    void handle_send_message_options(const std::string& menu_choice); // Handles options 150, 151, 152, 153
    void handle_delete_user();             // 154

private:
    // Network members to set up Boost.Asio connection
    boost::asio::io_context p_io_context;
    tcp::socket p_socket;
    tcp::resolver p_resolver;

    // Client state structure (replaces g_my_info)
    struct MyInfo {
        std::string name;
        std::string uuid_hex;
        std::string uuid_bin;
        // unique_ptr automatically handles memory deletion
        std::unique_ptr<RSAPrivateWrapper> keys; 
    } g_my_info;

    bool g_is_registered = false; // Registration status flag
    std::map<std::string, ClientInfo> g_client_db; // In-RAM client database

    // Internal helpers
    bool is_user_registered();
    void load_my_info();
    std::pair<std::string, std::string> load_server_info();
    std::string find_uuid_by_name(const std::string& name);
    std::string find_name_by_uuid(const std::string& uuid_bin);
};