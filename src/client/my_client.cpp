// command in terminal: cd C:\Users\User\Documents\Yehonatan\open-university\defensive-programing\MessageU1
// Compile command:    g++ my_client.cpp ChatClient.cpp -o my_client.exe -std=c++17 -lWs2_32 -lpthread
// Run command:        my_client.exe

#include "ChatClient.h" // include the ChatClient class definitio
#include <iostream>
#include <string>
#include <fstream>
#include <stdexcept>

int main(int argc, char* argv[])
{
    std::string host;
    std::string port;
    const std::string conection_information_filename = "server.info";

    std::ifstream config_file(conection_information_filename); // try to open file
    if (!config_file.is_open())
    {
        std::cerr << "Error: Could not open conection_information_filename file '" << conection_information_filename << "'.\n";
        return 1;
    }

    std::string line;
    if (std::getline(config_file, line)) // read first line
    {
        size_t colon_pos = line.find(':'); // Find the colon separator
        
        if (colon_pos == std::string::npos || colon_pos == 0 || colon_pos == line.length() - 1) // check if the content of file is valid
        {
            // if not valid
            std::cerr << "Error: Invalid format in " << conection_information_filename << ". Expected format: IP:Port\n";
            return 1;
        }
        
        host = line.substr(0, colon_pos); // extract the host (IP address)
        port = line.substr(colon_pos + 1); // extract the port number
    }
    else
    {
        std::cerr << "Error: Configuration file '" << conection_information_filename << "' is empty.\n";
        return 1;
    }
    
    config_file.close(); // close file after reading

    try
    {
        boost::asio::io_context io_context;
        ChatClient client(io_context); // creates the client object


        // connects to the server
        if (!client.connect(host, port)) 
        {
            return 1; // exits if connection failed
        }

        client.run(); // listening to server for incoming messages - background process

        std::cout << "Connected to " << host << ":" << port << std::endl;
                std::cout << R"(
MessageU client at your service.

110) Register
120) Request for clients list
130) Request for public key
140) Request for waiting messages
150) Send a text message
151) Send a request for symmetric key
152) Send your symmetric key
  0) Exit client
? 
)" << std::endl;
        std::cout << "Enter message: " << std::flush;

        // main thread becomes the writing thread
        while (true) // while the connection is active
        {
            // Use std::string to dynamically hold the message
            std::string line;
            std::getline(std::cin, line); // waits for user input
            
            if (line == "0") // exit client
                break;
                
            client.send_message(line); // Sends message to server
        }

        client.stop(); // stops the client and cleans up
    }
    catch (std::exception& e) // catch any exceptions from main thread
    {
        std::cerr << "Exception: " << e.what() << "\n";
    }

    return 0; // end of program
}