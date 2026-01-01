#include "network/connection.h"
#include <stdexcept>

Connection::Connection() 
    : socket_(std::make_unique<tcp::socket>(io_context_)),
      resolver_(std::make_unique<tcp::resolver>(io_context_)) {
}

Connection::~Connection() {
    close();
}

void Connection::connect(const std::string& host, const std::string& port) {
    try {
        boost::asio::connect(*socket_, resolver_->resolve(host, port));
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("Connection failed: ") + e.what());
    }
}

void Connection::send(const std::vector<char>& data) {
    if (!socket_ || !socket_->is_open()) {
        throw std::runtime_error("Cannot send: not connected");
    }
    try {
        boost::asio::write(*socket_, boost::asio::buffer(data));
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("Send failed: ") + e.what());
    }
}

std::vector<char> Connection::receive(size_t size) {
    if (!socket_ || !socket_->is_open()) {
        throw std::runtime_error("Cannot receive: not connected");
    }
    try {
        std::vector<char> buffer(size);
        boost::asio::read(*socket_, boost::asio::buffer(buffer, size));
        return buffer;
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("Receive failed: ") + e.what());
    }
}

void Connection::close() {
    if (socket_ && socket_->is_open()) {
        socket_->close();
    }
}

bool Connection::is_connected() const {
    return socket_ && socket_->is_open();
}



