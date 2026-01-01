#pragma once

#include "handlers/base_handler.h"

/**
 * Handler for deleting user account.
 */
class DeletionHandler : public BaseHandler {
public:
    using BaseHandler::BaseHandler;
    
    /**
     * Handle the user deletion process.
     */
    void handle();
};


