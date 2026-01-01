#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include "RSAWrapper.h"

// Forward declarations
class Connection;

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

    // Client state structure (replaces g_my_info)
    // Made public to allow handlers to access it
    struct MyInfo {
        std::string name;
        std::string uuid_hex;
        std::string uuid_bin;
        // unique_ptr automatically handles memory deletion
        std::unique_ptr<RSAPrivateWrapper> keys; 
    };

private:
    // Network connection
    std::unique_ptr<Connection> connection_;

    // Client state instance
    MyInfo g_my_info;

    bool g_is_registered = false; // Registration status flag
    std::map<std::string, ClientInfo> g_client_db; // In-RAM client database

    // Internal helpers
    bool is_user_registered();
    void load_my_info();
};