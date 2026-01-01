#pragma once

#include "handlers/base_handler.h"

/**
 * Handler for requesting and displaying client list.
 */
class ClientListHandler : public BaseHandler {
public:
    using BaseHandler::BaseHandler;
    
    /**
     * Handle the client list request.
     */
    void handle();
};

