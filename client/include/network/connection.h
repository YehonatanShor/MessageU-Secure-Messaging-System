#pragma once

#include <string>
#include <vector>
#include <memory>
#include <boost/asio.hpp>

using boost::asio::ip::tcp;

/**
 * Network connection abstraction for MessageU client.
 * 
 * This class encapsulates Boost.Asio networking details and provides
 * a simple interface for connecting, sending, and receiving data.
 */
class Connection {
public:
    Connection();
    ~Connection();
    
    /**
     * Connect to a server.
     * 
     * @param host Server hostname or IP address
     * @param port Server port as string
     * @throws std::runtime_error if connection fails
     */
    void connect(const std::string& host, const std::string& port);
    
    /**
     * Send data to the server.
     * 
     * @param data Data to send
     * @throws std::runtime_error if send fails
     */
    void send(const std::vector<char>& data);
    
    /**
     * Receive data from the server.
     * 
     * @param size Number of bytes to receive
     * @return Received data
     * @throws std::runtime_error if receive fails
     */
    std::vector<char> receive(size_t size);
    
    /**
     * Close the connection.
     */
    void close();
    
    /**
     * Check if connection is open.
     * 
     * @return true if connected, false otherwise
     */
    bool is_connected() const;

private:
    boost::asio::io_context io_context_;
    std::unique_ptr<tcp::socket> socket_;
    std::unique_ptr<tcp::resolver> resolver_;
};

