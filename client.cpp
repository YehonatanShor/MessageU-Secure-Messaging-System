// command in terminal: cd C:\Users\User\Documents\Yehonatan\open-university\defensive-programing\MessageU1
// Compile command:    g++ client.cpp -o client.exe -std=c++17 -lWs2_32
// Run command:    client.exe

#include <iostream>
#include <string>
#include <boost/asio.hpp>

using boost::asio::ip::tcp;

#define DEFAULT_PORT "8080"
#define DEFAULT_BUFLEN 1024
#define SERVER_IP "127.0.0.1"
#define MESSAGE_TO_SERVER "Hello from client, happy to connect!"

int main() {
    
    try {
        // Creating io_context object required by Asio
        boost::asio::io_context io_context;

        // Create socket
        tcp::socket s(io_context);

        // Connecting to server
        tcp::resolver resolver(io_context); // convert SERVER_IP and DEFAULT_PORT to endpoints
        auto endpoints = resolver.resolve(SERVER_IP, DEFAULT_PORT);
        boost::asio::connect(s, endpoints);
        std::cout << "Client connected to server successfully!" << std::endl;

        // Sending data to server
        std::cout << "Sending message to server..." << std::endl;
        boost::asio::write(s, boost::asio::buffer(MESSAGE_TO_SERVER, strlen(MESSAGE_TO_SERVER)));

        // Receiving data from server
        char serverMessage[DEFAULT_BUFLEN] = { 0 };
        s.read_some(boost::asio::buffer(serverMessage, DEFAULT_BUFLEN));
        std::cout << "Response from server: " << serverMessage << std::endl; 
    }

    catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;   // Handle exceptions
        return 1;
    }

    return 0;
}