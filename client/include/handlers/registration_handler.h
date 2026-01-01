#pragma once

#include "handlers/base_handler.h"
#include <functional>

/**
 * Handler for client registration process.
 */
class RegistrationHandler : public BaseHandler {
public:
    using BaseHandler::BaseHandler;
    
    /**
     * Handle the registration process.
     * 
     * @param is_user_registered_func Function to check if user is already registered
     * @param load_my_info_func Function to load user info after registration
     */
    void handle(std::function<bool()> is_user_registered_func, std::function<void()> load_my_info_func);
};

