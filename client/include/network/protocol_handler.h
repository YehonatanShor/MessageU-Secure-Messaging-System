#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include "protocol/constants.h"

/**
 * Protocol handler for building requests and parsing responses.
 * 
 * This class handles the binary protocol serialization/deserialization,
 * including endianness conversion and struct packing.
 */
class ProtocolHandler {
public:
    /**
     * Build a request header.
     * 
     * @param client_uuid_bin Client UUID in binary format (16 bytes)
     * @param request_code Request code
     * @param payload_size Payload size in bytes
     * @return Request header as vector of bytes
     */
    static std::vector<char> build_request_header(
        const std::string& client_uuid_bin,
        uint16_t request_code,
        uint32_t payload_size
    );
    
    /**
     * Build a registration request.
     * 
     * @param username Username (will be padded to USERNAME_FIXED_SIZE)
     * @param public_key Public key (must be PUBLIC_KEY_FIXED_SIZE bytes)
     * @return Complete request (header + payload) as vector of bytes
     */
    static std::vector<char> build_registration_request(
        const std::string& username,
        const std::string& public_key
    );
    
    /**
     * Build a client list request.
     * 
     * @param client_uuid_bin Client UUID in binary format
     * @return Request header as vector of bytes
     */
    static std::vector<char> build_client_list_request(
        const std::string& client_uuid_bin
    );
    
    /**
     * Build a public key request.
     * 
     * @param client_uuid_bin Requester's UUID in binary format
     * @param target_uuid_bin Target client's UUID in binary format
     * @return Complete request (header + payload) as vector of bytes
     */
    static std::vector<char> build_public_key_request(
        const std::string& client_uuid_bin,
        const std::string& target_uuid_bin
    );
    
    /**
     * Build a waiting messages request.
     * 
     * @param client_uuid_bin Client UUID in binary format
     * @return Request header as vector of bytes
     */
    static std::vector<char> build_waiting_messages_request(
        const std::string& client_uuid_bin
    );
    
    /**
     * Build a send message request.
     * 
     * @param client_uuid_bin Sender's UUID in binary format
     * @param target_uuid_bin Target client's UUID in binary format
     * @param msg_type Message type
     * @param content Message content
     * @return Complete request (header + payload) as vector of bytes
     */
    static std::vector<char> build_send_message_request(
        const std::string& client_uuid_bin,
        const std::string& target_uuid_bin,
        uint8_t msg_type,
        const std::string& content
    );
    
    /**
     * Build a delete user request.
     * 
     * @param client_uuid_bin Client UUID in binary format
     * @return Request header as vector of bytes
     */
    static std::vector<char> build_delete_user_request(
        const std::string& client_uuid_bin
    );
    
    /**
     * Parse a response header.
     * 
     * @param header_data Response header bytes (RESPONSE_HEADER_SIZE bytes)
     * @return Tuple of (response_code, payload_size)
     */
    static std::pair<uint16_t, uint32_t> parse_response_header(
        const std::vector<char>& header_data
    );
    
    /**
     * Parse registration response.
     * 
     * @param payload Response payload
     * @return Client UUID in binary format
     */
    static std::string parse_registration_response(
        const std::vector<char>& payload
    );
};

