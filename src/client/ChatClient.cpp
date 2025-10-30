#include "ChatClient.h"
#include <iostream>
#include <functional> // for std::ref

// Constructor
ChatClient::ChatClient(boost::asio::io_context& context)
    : io_context_(context), socket_(context), running_(false)
{
    // All constructor operations are performed in the Initializer List,
    //so the constructor body is empty.
}

// Connect tovserver
bool ChatClient::connect(const std::string& host, const std::string& port)
{
    try
    {
        tcp::resolver resolver(io_context_);
        boost::asio::connect(socket_, resolver.resolve(host, port));
        running_ = true; // conected successfully to server
        return true;
    }
    catch (std::exception& e) // Connection failed
    {
        std::cerr << "Connection failed: " << e.what() << "\n";
        return false;
    }
}

// Start reading thread in the background
void ChatClient::run()
{
    reader_thread_ = std::thread(&ChatClient::read_loop, this);
}

// Stop client action and clean up
void ChatClient::stop()
{
    running_ = false; // signal reading thread to stop
    if (socket_.is_open())
    {
        socket_.shutdown(tcp::socket::shutdown_both);
        socket_.close();
    }
    if (reader_thread_.joinable())
    {
        reader_thread_.join(); // wait for reading thread to finish running
    }
}

// The main writing logic (now part of the client class)
void ChatClient::send_message(const std::string& message)
{
    if (!running_ || message.empty()) return; // safety check - don't send if not running or empty message
    
    try
    {
        // Sends 4-byte header (length)
        uint32_t message_length = static_cast<uint32_t>(message.length());
        uint32_t network_length = htonl(message_length); // Converts from host to network format (Little Indian to Big Indian)
        boost::asio::write(socket_, boost::asio::buffer(&network_length, sizeof(network_length)));
        
        boost::asio::write(socket_, boost::asio::buffer(message)); // Sends message body
    }
    catch(std::exception& e) // Sending failed
    {
        std::cerr << "Send failed: " << e.what() << "\n";
        stop();
    }
}

// The reading logic for incoming messages (private function)
void ChatClient::read_loop()
{
    try
    {
        while (running_) // while connection is active
        {
            uint32_t network_header; // read header first (4 bytes)
            boost::asio::read(socket_, boost::asio::buffer(&network_header, sizeof(network_header)));
            uint32_t message_length = ntohl(network_header); // Converts from network to host format (Big Indian to Little Indian)

            if (message_length == 0) continue;// Skip empty messages

            // Create string buffer of *exact* size of incoming message
            std::string reply(message_length, '\0');

            // Read exactly message_length bytes into the string buffer
            boost::asio::read(socket_, boost::asio::buffer(&reply[0], message_length));
            
            // \r[K clears the line (in case user is typing) and prints
            std::cout << "\rReply is: " << reply << "\n" << "Enter message: " << std::flush;
        }
    }

    // Closing communication if server has disconnected
    catch (std::exception& e)
    {
        std::cout << "\rConnection closed." << std::endl;
        running_ = false; // signal writing thread to stop
    }
}