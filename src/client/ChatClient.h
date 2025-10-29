#pragma once // Prevents multiple inclusions

#include <string>
#include <thread>
#include <atomic>
#include <boost/asio.hpp>

using boost::asio::ip::tcp;

class ChatClient
{
public:
    // Constructor
    ChatClient(boost::asio::io_context& context);
    
    // Public functions - the "API" of our client (which the client can call from main)
    bool connect(const std::string& host, const std::string& port);
    void send_message(const std::string& message);
    void run(); // to start the client
    void stop(); // to stop the client and clean up

private:
    void read_loop(); // Private function for the reading thread

    // Internal variables (state) of the class
    boost::asio::io_context& io_context_;
    tcp::socket socket_;
    std::thread reader_thread_; // thread for processing incoming messages
    std::atomic<bool> running_; // global atomic variable to manage the running state of both threads
};