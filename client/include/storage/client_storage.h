#pragma once

#include <string>
#include <memory>
#include "RSAWrapper.h"
#include "protocol/constants.h"

/**
 * Client data structure for storage.
 */
struct ClientData {
    std::string username;
    std::string uuid_hex;
    std::string uuid_bin;
    std::unique_ptr<RSAPrivateWrapper> private_key;
};

/**
 * Server connection info structure.
 */
struct ServerInfo {
    std::string host;
    std::string port;
};

/**
 * Client storage manager for persistent data.
 * 
 * This class handles loading and saving client information
 * (my.info) and server connection info (server.info).
 */
class ClientStorage {
public:
    /**
     * Load client data from my.info file.
     * 
     * @return ClientData structure, or nullptr if file doesn't exist or is invalid
     */
    static std::unique_ptr<ClientData> load_client_data();
    
    /**
     * Save client data to my.info file.
     * 
     * @param username Client username
     * @param uuid_hex Client UUID in hex format
     * @param private_key_b64 Base64 encoded private key
     * @throws std::runtime_error if save fails
     */
    static void save_client_data(
        const std::string& username,
        const std::string& uuid_hex,
        const std::string& private_key_b64
    );
    
    /**
     * Check if client is registered (my.info exists and is valid).
     * 
     * @return true if registered, false otherwise
     */
    static bool is_client_registered();
    
    /**
     * Delete client data file.
     * 
     * @return true if deleted, false otherwise
     */
    static bool delete_client_data();
    
    /**
     * Load server connection info from server.info file.
     * 
     * @return ServerInfo structure with host and port
     * @throws std::runtime_error if file cannot be read or is invalid
     */
    static ServerInfo load_server_info();
};


