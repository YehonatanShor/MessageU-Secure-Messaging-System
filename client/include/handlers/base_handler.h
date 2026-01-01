#pragma once

#include <string>
#include <memory>
#include <map>
#include "RSAWrapper.h"
#include "network/connection.h"
#include "MessageUClient.h"

// Forward declarations
struct ClientInfo;

/**
 * Base handler class for client request handlers.
 * 
 * Provides common functionality and state access for all handlers.
 */
class BaseHandler {
protected:
    // Reference to connection (non-owning)
    Connection* connection_;
    
    // Reference to client's own info (non-owning)
    MessageUClient::MyInfo* my_info_;
    
    // Reference to registration status (non-owning)
    bool* is_registered_;
    
    // Reference to client database (non-owning)
    std::map<std::string, ClientInfo>* client_db_;
    
    // Helper function to find UUID by name
    std::string find_uuid_by_name(const std::string& name);
    
    // Helper function to find name by UUID
    std::string find_name_by_uuid(const std::string& uuid_bin);
    
    // Helper function to convert binary UUID to hex
    std::string binary_to_hex_ascii(const std::string& bin_uuid);
    
    // Helper function to convert hex UUID to binary
    std::string hex_ascii_to_binary(const std::string& hex_uuid);

public:
    BaseHandler(
        Connection* connection,
        MessageUClient::MyInfo* my_info,
        bool* is_registered,
        std::map<std::string, ClientInfo>* client_db
    );
    
    virtual ~BaseHandler() = default;
};

