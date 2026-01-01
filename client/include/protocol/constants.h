#pragma once

#include <cstdint>
#include <cstddef>
#include <string>

/**
 * Protocol and configuration constants for MessageU client.
 * 
 * This header contains all protocol definitions, message types,
 * response codes, and configuration values.
 */

namespace Protocol {

    // ========================================================================
    // Configuration Files
    // ========================================================================
    
    const std::string MY_INFO_FILE = "my.info";
    const std::string SERVER_INFO_FILE = "server.info";

    // ========================================================================
    // Protocol Versions
    // ========================================================================
    
    constexpr uint8_t CLIENT_VERSION = 2;

    // ========================================================================
    // Protocol Sizes (in bytes)
    // ========================================================================
    
    constexpr size_t CLIENT_VERSION_SIZE = 1;
    constexpr size_t CLIENT_UUID_SIZE = 16;
    constexpr size_t REQUEST_CODE_SIZE = 2;
    constexpr size_t REQUEST_PAYLOAD_SIZE = 4;
    constexpr size_t REQUEST_HEADER_SIZE = 16 + 1 + 2 + 4;  // ClientID(16) + Version(1) + Code(2) + PayloadSize(4)
    constexpr size_t USERNAME_FIXED_SIZE = 255;
    constexpr size_t PUBLIC_KEY_FIXED_SIZE = 160;
    constexpr size_t REGISTRATION_PAYLOAD_SIZE = USERNAME_FIXED_SIZE + PUBLIC_KEY_FIXED_SIZE;

    constexpr size_t SERVER_VERSION_SIZE = 1;
    constexpr size_t RESPONSE_CODE_SIZE = 2;
    constexpr size_t RESPONSE_PAYLOAD_SIZE = 4;
    constexpr size_t RESPONSE_HEADER_SIZE = 1 + 2 + 4;  // Version(1) + Code(2) + PayloadSize(4)
    constexpr size_t RESPONSE_MSG_ID_SIZE = 4;
    constexpr size_t RESPONSE_MSG_TYPE_SIZE = 1;
    constexpr size_t RESPONSE_MSG_SIZE = 4;

    // ========================================================================
    // Request Codes (from client to server)
    // ========================================================================
    
    constexpr uint16_t REQUEST_CODE_REGISTER = 600;
    constexpr uint16_t REQUEST_CODE_CLIENTS_LIST = 601;
    constexpr uint16_t REQUEST_CODE_PUBLIC_KEY = 602;
    constexpr uint16_t REQUEST_CODE_SEND_MESSAGE = 603;
    constexpr uint16_t REQUEST_CODE_WAITING_MESSAGES = 604;
    constexpr uint16_t REQUEST_CODE_DELETE_USER = 605;

    // ========================================================================
    // Response Codes (from server to client)
    // ========================================================================
    
    constexpr uint16_t RESPONSE_CODE_REGISTER_SUCCESS = 2100;
    constexpr uint16_t RESPONSE_CODE_DISPLAYING_CLIENTS_LIST = 2101;
    constexpr uint16_t RESPONSE_CODE_SEND_PUBLIC_KEY = 2102;
    constexpr uint16_t RESPONSE_CODE_SEND_TEXT_MESSAGE = 2103;
    constexpr uint16_t RESPONSE_CODE_PULL_WAITING_MESSAGE = 2104;
    constexpr uint16_t RESPONSE_CODE_DELETE_USER_SUCCESS = 2105;
    constexpr uint16_t RESPONSE_CODE_GENERAL_ERROR = 9000;

    // ========================================================================
    // Message Types (for payload of code 603)
    // ========================================================================
    
    constexpr uint8_t MSG_TYPE_SYM_KEY_REQUEST = 1;
    constexpr uint8_t MSG_TYPE_SYM_KEY_SEND = 2;
    constexpr uint8_t MSG_TYPE_TEXT_MESSAGE = 3;
    constexpr uint8_t MSG_TYPE_FILE = 4;

    // ========================================================================
    // Protocol Strings (for menu options)
    // ========================================================================
    
    const std::string SEND_SYMMETRIC_KEY_REQUEST_STR = "151";
    const std::string SEND_SYMMETRIC_KEY_STR = "152";
    const std::string SEND_TEXT_MESSAGE_STR = "150";
    const std::string SEND_FILE_STR = "153";

} // namespace Protocol


