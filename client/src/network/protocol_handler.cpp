#include "network/protocol_handler.h"
#include <cstring>
#include <algorithm>
#include <stdexcept>

#if defined(_WIN32)
#include <winsock2.h> // For htonl, ntohl, htons, ntohs
#else
#include <arpa/inet.h> // For htonl, ntohl, htons, ntohs
#endif

using namespace Protocol;

std::vector<char> ProtocolHandler::build_request_header(
    const std::string& client_uuid_bin,
    uint16_t request_code,
    uint32_t payload_size) {
    
    std::vector<char> header;
    header.reserve(REQUEST_HEADER_SIZE);
    
    // Client UUID (16 bytes)
    header.insert(header.end(), client_uuid_bin.begin(), client_uuid_bin.end());
    if (client_uuid_bin.length() < CLIENT_UUID_SIZE) {
        header.insert(header.end(), CLIENT_UUID_SIZE - client_uuid_bin.length(), 0);
    }
    
    // Client Version (1 byte)
    header.push_back(CLIENT_VERSION);
    
    // Request Code (2 bytes, network byte order)
    uint16_t code_net = htons(request_code);
    header.insert(header.end(), (char*)&code_net, (char*)&code_net + sizeof(code_net));
    
    // Payload Size (4 bytes, network byte order)
    uint32_t size_net = htonl(payload_size);
    header.insert(header.end(), (char*)&size_net, (char*)&size_net + sizeof(size_net));
    
    return header;
}

std::vector<char> ProtocolHandler::build_registration_request(
    const std::string& username,
    const std::string& public_key) {
    
    std::vector<char> request;
    uint32_t payload_size = REGISTRATION_PAYLOAD_SIZE;
    
    // Build header (with empty UUID for registration)
    std::string empty_uuid(CLIENT_UUID_SIZE, 0);
    auto header = build_request_header(empty_uuid, REQUEST_CODE_REGISTER, payload_size);
    request.insert(request.end(), header.begin(), header.end());
    
    // Build payload
    // Username (padded to USERNAME_FIXED_SIZE)
    char username_payload[USERNAME_FIXED_SIZE] = {0};
    size_t username_len = std::min(username.length(), (size_t)USERNAME_FIXED_SIZE);
    std::memcpy(username_payload, username.c_str(), username_len);
    request.insert(request.end(), username_payload, username_payload + USERNAME_FIXED_SIZE);
    
    // Public Key (padded to PUBLIC_KEY_FIXED_SIZE)
    char public_key_payload[PUBLIC_KEY_FIXED_SIZE] = {0};
    size_t key_len = std::min(public_key.length(), (size_t)PUBLIC_KEY_FIXED_SIZE);
    std::memcpy(public_key_payload, public_key.c_str(), key_len);
    request.insert(request.end(), public_key_payload, public_key_payload + PUBLIC_KEY_FIXED_SIZE);
    
    return request;
}

std::vector<char> ProtocolHandler::build_client_list_request(
    const std::string& client_uuid_bin) {
    return build_request_header(client_uuid_bin, REQUEST_CODE_CLIENTS_LIST, 0);
}

std::vector<char> ProtocolHandler::build_public_key_request(
    const std::string& client_uuid_bin,
    const std::string& target_uuid_bin) {
    
    std::vector<char> request;
    auto header = build_request_header(client_uuid_bin, REQUEST_CODE_PUBLIC_KEY, target_uuid_bin.length());
    request.insert(request.end(), header.begin(), header.end());
    request.insert(request.end(), target_uuid_bin.begin(), target_uuid_bin.end());
    return request;
}

std::vector<char> ProtocolHandler::build_waiting_messages_request(
    const std::string& client_uuid_bin) {
    return build_request_header(client_uuid_bin, REQUEST_CODE_WAITING_MESSAGES, 0);
}

std::vector<char> ProtocolHandler::build_send_message_request(
    const std::string& client_uuid_bin,
    const std::string& target_uuid_bin,
    uint8_t msg_type,
    const std::string& content) {
    
    std::vector<char> request;
    
    // Build message payload: TargetUUID(16) + Type(1) + Size(4) + Content(N)
    std::vector<char> msg_payload;
    msg_payload.insert(msg_payload.end(), target_uuid_bin.begin(), target_uuid_bin.end());
    msg_payload.push_back(msg_type);
    uint32_t content_size_net = htonl(content.length());
    msg_payload.insert(msg_payload.end(), (char*)&content_size_net, (char*)&content_size_net + sizeof(content_size_net));
    msg_payload.insert(msg_payload.end(), content.begin(), content.end());
    
    // Build complete request
    auto header = build_request_header(client_uuid_bin, REQUEST_CODE_SEND_MESSAGE, msg_payload.size());
    request.insert(request.end(), header.begin(), header.end());
    request.insert(request.end(), msg_payload.begin(), msg_payload.end());
    
    return request;
}

std::vector<char> ProtocolHandler::build_delete_user_request(
    const std::string& client_uuid_bin) {
    return build_request_header(client_uuid_bin, REQUEST_CODE_DELETE_USER, 0);
}

std::pair<uint16_t, uint32_t> ProtocolHandler::parse_response_header(
    const std::vector<char>& header_data) {
    
    if (header_data.size() < RESPONSE_HEADER_SIZE) {
        throw std::runtime_error("Response header too small");
    }
    
    uint16_t response_code;
    uint32_t payload_size;
    
    std::memcpy(&response_code, header_data.data() + SERVER_VERSION_SIZE, RESPONSE_CODE_SIZE);
    std::memcpy(&payload_size, header_data.data() + SERVER_VERSION_SIZE + RESPONSE_CODE_SIZE, RESPONSE_PAYLOAD_SIZE);
    
    response_code = ntohs(response_code);
    payload_size = ntohl(payload_size);
    
    return {response_code, payload_size};
}

std::string ProtocolHandler::parse_registration_response(
    const std::vector<char>& payload) {
    
    if (payload.size() != CLIENT_UUID_SIZE) {
        throw std::runtime_error("Invalid registration response size");
    }
    
    return std::string(payload.begin(), payload.end());
}

