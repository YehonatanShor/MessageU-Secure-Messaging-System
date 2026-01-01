#pragma once

#include <string>
#include <vector>

/**
 * UI/Menu display manager.
 * 
 * This class provides functions for displaying menus,
 * messages, and formatted output to the user.
 */
class Menu {
public:
    /**
     * Display the main menu.
     */
    static void show_main_menu();
    
    /**
     * Display welcome message with username.
     * 
     * @param username Client username
     */
    static void show_welcome(const std::string& username);
    
    /**
     * Display connection status message.
     * 
     * @param host Server hostname
     * @param port Server port
     */
    static void show_connecting(const std::string& host, const std::string& port);
    
    /**
     * Display connection success message.
     */
    static void show_connected();
    
    /**
     * Display success message.
     * 
     * @param message Success message to display
     */
    static void show_success(const std::string& message);
    
    /**
     * Display error message.
     * 
     * @param message Error message to display
     */
    static void show_error(const std::string& message);
    
    /**
     * Display info message.
     * 
     * @param message Info message to display
     */
    static void show_info(const std::string& message);
    
    /**
     * Display prompt for user input.
     * 
     * @param prompt Prompt text
     */
    static void show_prompt(const std::string& prompt);
    
    /**
     * Display invalid option message.
     */
    static void show_invalid_option();
    
    /**
     * Display registered clients list.
     * 
     * @param clients Vector of pairs (name, uuid_hex)
     */
    static void show_client_list(const std::vector<std::pair<std::string, std::string>>& clients);
    
    /**
     * Display messages header.
     */
    static void show_messages_header();
    
    /**
     * Display a single message.
     * 
     * @param from_name Sender name
     * @param content Message content
     * @param is_text Whether message is text (true) or file (false)
     */
    static void show_message(const std::string& from_name, const std::string& content, bool is_text = true);
    
    /**
     * Display file saved message.
     * 
     * @param filepath Path where file was saved
     */
    static void show_file_saved(const std::string& filepath);
    
    /**
     * Display "no messages" message.
     */
    static void show_no_messages();
    
    /**
     * Display "no key" message for decryption.
     */
    static void show_no_key();
    
    /**
     * Display decryption failed message.
     */
    static void show_decryption_failed();
};


