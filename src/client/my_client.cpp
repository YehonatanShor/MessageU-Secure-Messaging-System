// command in terminal: cd C:\Users\User\Documents\Yehonatan\open-university\defensive-programing\MessageU1
// Compile command:    g++ my_client.cpp ChatClient.cpp -o my_client.exe -std=c++17 -lWs2_32 -lpthread
// Run command:        my_client.exe 127.0.0.1 1234

#include "ChatClient.h" // include the ChatClient class definition
#include <iostream>
#include <string>

int main(int argc, char* argv[])
{
    try
    {
        if (argc != 3) // בדיקת ארגומנטים (host, port)
        {
            std::cerr << "Usage: my_client <host> <port>\n";
            return 1;
        }

        boost::asio::io_context io_context;
        ChatClient client(io_context); // creates the client object

        // connects to the server
        if (!client.connect(argv[1], argv[2])) 
        {
            return 1; // exits if connection failed
        }

        client.run();  // starts background process - listening to server for incoming messages

        std::cout << "Connected! You can start typing." << std::endl;
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
? )" << std::endl;
        std::cout << "Enter message: " << std::flush;

        // main thread becomes the writing thread
        while (true) // while the connection is active
        {
            // Use std::string to dynamically hold the message
            std::string line;
            std::getline(std::cin, line); // waits for user input
            
            if (line == "/quit") // 
                break;
                
            client.send_message(line); // Sends the message to the server
        }

        client.stop(); // stops the client and cleans up
    }
    catch (std::exception& e) // catch any exceptions from main thread
    {
        std::cerr << "Exception: " << e.what() << "\n";
    }
    return 0; // End of program
}