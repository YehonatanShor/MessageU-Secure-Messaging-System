#include "MessageUClient.h"
#include "ui/menu.h"
#include <iostream>
#include <string>
#include <algorithm>

// Constants for menu options
const std::string REGISTER_STR = "110";
const std::string CLIENTS_LIST_STR = "120";
const std::string REQUEST_PUBLIC_KEY_STR = "130";
const std::string REQUEST_WAITING_MESSAGES_STR = "140";
const std::string SEND_TEXT_MESSAGE_STR = "150";
const std::string SEND_SYMMETRIC_KEY_REQUEST_STR = "151";
const std::string SEND_SYMMETRIC_KEY_STR = "152";
const std::string SEND_FILE_STR = "153";
const std::string DELETE_USER_STR = "154";
const std::string EXIT_CLIENT_STR = "0";

// Trim whitespace from users input (two-sided of string)
std::string trim_str(const std::string& s) {
    auto start = std::find_if_not(s.begin(), s.end(), [](unsigned char c){ return std::isspace(c); });
    auto end = std::find_if_not(s.rbegin(), s.rend(), [](unsigned char c){ return std::isspace(c); }).base();
    return (start < end ? std::string(start, end) : std::string());
}

int main()
{
    try {
		// Create client object to manage client operations
        MessageUClient client;
        client.connect();

        while (true) {
			// Display menu and get user input
            client.show_menu();

            std::string users_choice;
            std::getline(std::cin, users_choice);
            users_choice = trim_str(users_choice);

			// Handle user choice
            if (users_choice == EXIT_CLIENT_STR) break;
            else if (users_choice == DELETE_USER_STR) client.handle_delete_user();
            else if (users_choice == REGISTER_STR) client.handle_registration();
            else if (users_choice == CLIENTS_LIST_STR) client.handle_client_list();
            else if (users_choice == REQUEST_PUBLIC_KEY_STR) client.handle_request_public_key();
            else if (users_choice == REQUEST_WAITING_MESSAGES_STR) client.handle_pull_messages();
            else if (users_choice == SEND_TEXT_MESSAGE_STR || 
                     users_choice == SEND_SYMMETRIC_KEY_REQUEST_STR || 
                     users_choice == SEND_SYMMETRIC_KEY_STR || 
                     users_choice == SEND_FILE_STR) 
            {
                client.handle_send_message_options(users_choice);
            }
			// unrecognized input
            else {
                Menu::show_invalid_option();
            }
        }
    } 
	// catch any exceptions from main thread
    catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
    }
    return 0;
}