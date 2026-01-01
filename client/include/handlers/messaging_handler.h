#pragma once

#include "handlers/base_handler.h"
#include <string>

/**
 * Handler for sending and receiving messages.
 */
class MessagingHandler : public BaseHandler {
public:
    using BaseHandler::BaseHandler;
    
    /**
     * Handle pulling waiting messages from server.
     */
    void handle_pull_messages();
    
    /**
     * Handle sending messages (text, file, or symmetric key operations).
     * 
     * @param menu_choice Menu choice string ("150", "151", "152", "153")
     */
    void handle_send_message(const std::string& menu_choice);
};


