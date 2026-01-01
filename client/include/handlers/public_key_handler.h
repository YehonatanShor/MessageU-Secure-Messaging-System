#pragma once

#include "handlers/base_handler.h"

/**
 * Handler for requesting public keys from other clients.
 */
class PublicKeyHandler : public BaseHandler {
public:
    using BaseHandler::BaseHandler;
    
    /**
     * Handle the public key request.
     */
    void handle();
};

