// command in terminal: cd C:\Users\User\Documents\Yehonatan\open-university\defensive-programing\MessageU1
// Compile command:    g++ my_client.cpp -o my_client.exe -std=c++17 -lWs2_32
// Run command:    my_client.exe 127.0.0.1 1234

#if defined(_WIN32)
#include <winsock2.h> // For htonl, ntohl
#endif

#include <cstdlib>
#include <iostream>
#include <string>
#include <boost/asio.hpp>
#include <thread>
#include <atomic>
#include <functional>
#include <cstdint> // For uint32_t

using boost::asio::ip::tcp;

// global atomic variable to manage the running state of both threads
std::atomic<bool> running(true);

// read_loop is responsible *only* for reading messages from the server.
void read_loop(tcp::socket& s)
{
    try
    {
        while (running) // while the connection is active
        {
            uint32_t network_header; // read the header first (4 bytes)
            boost::asio::read(s, boost::asio::buffer(&network_header, sizeof(network_header)));

            // Convert header from network byte order to host byte order
            uint32_t message_length = ntohl(network_header);

            if (message_length == 0) continue; // Skip empty messages
            
            // Create a string buffer of the *exact* size of the incoming message
            std::string reply(message_length, '\0');
            
            // Read exactly message_length bytes into the string
            boost::asio::read(s, boost::asio::buffer(&reply[0], message_length));
            
            // \r[K clears the line (in case user is typing) and prints
            std::cout << "\rReply is: " << reply << "\n" << "Enter message: " << std::flush;
        }
    }
    catch (std::exception& e)
    {
        // Closing communication if the server has disconnected
        std::cout << "\rConnection closed." << std::endl;
        running = false; // signal the writing thread to stop
    }
}

int main(int argc, char* argv[])
{
    try
    {
        if (argc != 3) // Check command line arguments.
        {
            std::cerr << "Usage: blocking_tcp_echo_client <host> <port>\n";
            return 1;
        }

        boost::asio::io_context io_context;
        tcp::socket s(io_context);
        tcp::resolver resolver(io_context);
        boost::asio::connect(s, resolver.resolve(argv[1], argv[2]));
        
        std::cout << "Connected! You can start typing." << std::endl;

        // Turn on the reading process in the background
        std::thread reader_thread(read_loop, std::ref(s));

        // main thread becomes the writing thread
        while (running) // while the connection is active
        {
            std::cout << "Enter message: ";
            
            // Use std::string to dynamically hold the message
            std::string request;
            std::getline(std::cin, request); // Read a full line
            
            if (!running) // check if the connection was closed while typing
                break;
            
            if (request.empty()) continue; // Don't send empty messages
            
            // Send Message Length Header
            uint32_t message_length = static_cast<uint32_t>(request.length());
            uint32_t network_length = htonl(message_length); //Converts the message length to the network format - Little Indian to Big Indian 
            
            boost::asio::write(s, boost::asio::buffer(&network_length, sizeof(network_length))); // Send the 4-byte header
            boost::asio::write(s, boost::asio::buffer(request)); // Send the actual string data
        }

        // if the writing loop ends (because running = false),
        // close the socket. This will cause read_loop to exit.
        if (s.is_open())
        {
            s.shutdown(tcp::socket::shutdown_both);
            s.close();
        }
        reader_thread.join(); // wait for the reading thread to finish
    }
    catch (std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
        running = false; // make sure to stop the reading thread
    }
}