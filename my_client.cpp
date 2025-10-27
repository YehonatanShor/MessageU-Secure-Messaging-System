// command in terminal: cd C:\Users\User\Documents\Yehonatan\open-university\defensive-programing\MessageU1
// Compile command:    g++ my_client.cpp -o my_client.exe -std=c++17 -lWs2_32
// Run command:    my_client.exe 127.0.0.1 1234
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <boost/asio.hpp>
#include <thread>
#include <atomic>
#include <functional>

using boost::asio::ip::tcp;

const int max_length = 1024;
// global atomic variable to manage the running state of both threads
std::atomic<bool> running(true);

void clear(char message[], int length) {
    std::memset(message, 0, length);
}

// thread function only for reading messages from server
void read_loop(tcp::socket& s)
{
    try
    {
        while (running) // while the connection is active
        {
            char reply[max_length];
            clear(reply, max_length);

            size_t reply_length = boost::asio::read(s, boost::asio::buffer(reply, max_length));
            std::cout << "\nReply is: " << reply << std::endl;
        }
    }

    catch (std::exception& e)
    {
        std::cout << "Connection closed by server." << std::endl;
        running = false; // signal the writing thread to stop
    }
}

int main(int argc, char* argv[])
{
    try
    {
        if (argc != 3)
        {
            std::cerr << "Usage: blocking_tcp_echo_client <host> <port>\n";
            return 1;
        }

        boost::asio::io_context io_context;
        tcp::socket s(io_context);
        tcp::resolver resolver(io_context);
        boost::asio::connect(s, resolver.resolve(argv[1], argv[2]));
        
        // Turn on the reading process in the background
        std::thread reader_thread(read_loop, std::ref(s));

        // main thread becomes the writing thread
        while (running) // while the connection is active
        {
            std::cout << "Enter message: ";
            char request[max_length];
            clear(request, max_length);
            std::cin.getline(request, max_length);
            
            if (!running) // check if the connection was closed while typing
                break;

            boost::asio::write(s, boost::asio::buffer(request, max_length));
        }

        // if the writing loop ends, close the socket and wait for the reading thread to finish
        s.close();
        reader_thread.join(); // wait for the reading thread to finish
    }
    catch (std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
        running = false; // make sure to stop the reading thread
    }
}