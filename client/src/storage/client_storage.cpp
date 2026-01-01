#include "storage/client_storage.h"
#include "storage/file_manager.h"
#include "crypto/key_manager.h"
#include <sstream>
#include <stdexcept>

using namespace Protocol;

std::unique_ptr<ClientData> ClientStorage::load_client_data() {
    if (!FileManager::file_exists(MY_INFO_FILE)) {
        return nullptr;
    }
    
    try {
        std::string content = FileManager::read_file_text(MY_INFO_FILE);
        std::istringstream iss(content);
        
        std::string name, uuid_hex, private_key_b64, line;
        
        // Read first line (username)
        if (!std::getline(iss, name)) {
            return nullptr;
        }
        
        // Read second line (UUID)
        if (!std::getline(iss, uuid_hex)) {
            return nullptr;
        }
        
        // Read the rest (potentially multi-line Base64 key)
        while (std::getline(iss, line)) {
            private_key_b64 += line;
        }
        
        // Validate
        if (name.empty() || uuid_hex.empty() || private_key_b64.empty()) {
            return nullptr;
        }
        
        // Create ClientData
        auto data = std::make_unique<ClientData>();
        data->username = name;
        data->uuid_hex = uuid_hex;
        data->private_key = KeyManager::load_private_key_from_base64(private_key_b64);
        
        return data;
    } catch (...) {
        return nullptr;
    }
}

void ClientStorage::save_client_data(
    const std::string& username,
    const std::string& uuid_hex,
    const std::string& private_key_b64) {
    
    std::ostringstream oss;
    oss << username << "\n" << uuid_hex << "\n" << private_key_b64;
    FileManager::write_file_text(MY_INFO_FILE, oss.str());
}

bool ClientStorage::is_client_registered() {
    return FileManager::file_exists(MY_INFO_FILE);
}

bool ClientStorage::delete_client_data() {
    return FileManager::delete_file(MY_INFO_FILE);
}

ServerInfo ClientStorage::load_server_info() {
    if (!FileManager::file_exists(SERVER_INFO_FILE)) {
        throw std::runtime_error("Error: Could not open " + SERVER_INFO_FILE);
    }
    
    std::string content = FileManager::read_file_text(SERVER_INFO_FILE);
    std::istringstream iss(content);
    
    std::string line;
    if (!std::getline(iss, line)) {
        throw std::runtime_error(SERVER_INFO_FILE + " is empty.");
    }
    
    // Remove trailing newline if present
    if (!line.empty() && line.back() == '\n') {
        line.pop_back();
    }
    
    size_t colon_pos = line.find(':');
    if (colon_pos == std::string::npos || colon_pos == 0 || colon_pos == line.length() - 1) {
        throw std::runtime_error("Invalid format in " + SERVER_INFO_FILE);
    }
    
    ServerInfo info;
    info.host = line.substr(0, colon_pos);
    info.port = line.substr(colon_pos + 1);
    
    return info;
}



