#include "ui/menu.h"
#include <iostream>

void Menu::show_main_menu() {
    std::cout << "\nMessageU client at your service.\n\n"
              << "110) Register\n"
              << "120) Request for clients list\n"
              << "130) Request for public key\n"
              << "140) Request for waiting messages\n"
              << "150) Send a text message\n"
              << "151) Send a request for symmetric key\n"
              << "152) Send your symmetric key\n"
              << "153) Send a file\n"
              << "154) Delete user\n"
              << "0) Exit client\n"
              << "?\n";
}

void Menu::show_welcome(const std::string& username) {
    std::cout << "Welcome, " << username << "!" << std::endl;
}

void Menu::show_connecting(const std::string& host, const std::string& port) {
    std::cout << "Connecting to " << host << ":" << port << "..." << std::endl;
}

void Menu::show_connected() {
    std::cout << "Connected successfully.\n";
}

void Menu::show_success(const std::string& message) {
    std::cout << message << std::endl;
}

void Menu::show_error(const std::string& message) {
    std::cout << "Error: " << message << std::endl;
}

void Menu::show_info(const std::string& message) {
    std::cout << message << std::endl;
}

void Menu::show_prompt(const std::string& prompt) {
    std::cout << prompt;
}

void Menu::show_invalid_option() {
    std::cout << "Invalid option. Please try again.\n";
}

void Menu::show_client_list(const std::vector<std::pair<std::string, std::string>>& clients) {
    std::cout << "\n--- Registered Clients ---" << std::endl;
    for (const auto& [name, uuid_hex] : clients) {
        std::cout << "Name: " << name << "\nUUID: " << uuid_hex << "\n---\n";
    }
}

void Menu::show_messages_header() {
    std::cout << "\n--- Messages ---\n";
}

void Menu::show_message(const std::string& from_name, const std::string& content, bool is_text) {
    std::cout << "From: " << from_name << "\nContent:\n";
    if (is_text) {
        std::cout << content << "\n";
    }
}

void Menu::show_file_saved(const std::string& filepath) {
    std::cout << "File saved in path: " << filepath << "\n";
}

void Menu::show_no_messages() {
    std::cout << "No new messages.\n";
}

void Menu::show_no_key() {
    std::cout << "Can't decrypt (no key)\n";
}

void Menu::show_decryption_failed() {
    std::cout << "Decryption failed.\n";
}

void Menu::show_end_of_messages() {
    std::cout << "\n\n----<EOM>----\n\n";
}


