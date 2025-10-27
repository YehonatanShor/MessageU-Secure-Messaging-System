// command in terminal: cd C:\Users\User\Documents\Yehonatan\open-university\defensive-programing\MessageU1
// Compile command:    g++ my_server.cpp -o my_server.exe -std=c++17 -lWs2_32
// Run command:    my_server.exe 1234 
#include <cstdlib>
#include <iostream>
#include <thread>
#include <utility>
#include <boost/asio.hpp>
#include <atomic>
#include <functional>

using boost::asio::ip::tcp;

const int max_length = 1024;
// a local atomic variable to manage the running state of the session for each client
std::atomic<bool> session_running(true);

void clear(char message[], int length)
{
    std::memset(message, 0, length);
}

// thread function only for writing messages to the client
void write_loop(tcp::socket& sock, std::atomic<bool>& running)
{
    try
    {
        while (running) // while the connection is active
        {

            // Warning: This input is shared by all clients! 
            // if two clients are connected, both will get the same message from the server.
            std::cout << "Enter message (for " << sock.remote_endpoint() << "): ";
            char data[max_length];
            clear(data, max_length);
            std::cin.getline(data, max_length);

            if (!running) // check if the connection was closed while typing
                break;

            boost::asio::write(sock, boost::asio::buffer(data, max_length));
        }
    }
    catch (std::exception& e)
    {
        running = false; // signal the reading thread to stop
    }
}

// thread function to handle a single client session
void session(tcp::socket sock) 
{
    std::atomic<bool> running(true);
    std::cout << "Client connected: " << sock.remote_endpoint() << std::endl;

    // turn on the writing process in the background
    std::thread writer_thread(write_loop, std::ref(sock), std::ref(running));

    try
    {
        // main thread becomes the reading thread
        for ( ; running ; )
        {
            char data[max_length];
            clear(data, max_length);

            size_t reply_length = boost::asio::read(sock,
                boost::asio::buffer(data, max_length));
            
            std::cout << "\nReceived from " << sock.remote_endpoint() << ": " << data << std::endl;
        }
    }
    catch (std::exception& e)
    {
        // client disconnected
        std::cout << "\nClient " << sock.remote_endpoint() << " disconnected." << std::endl;
    }

    running = false; // signal the writing thread to stop
    sock.close(); // close the socket, this will cause write to throw an error and release it
    writer_thread.join(); // wait for the writing thread to finish
    std::cout << "Session ended for " << sock.remote_endpoint() << std::endl;
}

void server(boost::asio::io_context& io_context, unsigned short port)
{
    tcp::acceptor a(io_context, tcp::endpoint(tcp::v4(), port));
    for ( ; ; )
    {
        // run each session in its own thread
        // he detach remains as it was. The session will take care of cleaning itself.
        std::thread(session, a.accept()).detach(); 
    }
}

int main(int argc, char* argv[])
{
    try
    {
        if (argc != 2)
        {
            std::cerr << "Usage: blocking_tcp_echo_server <port>\n";
            return 1;
        }
        boost::asio::io_context io_context;
        server(io_context, std::atoi(argv[1]));
    }
    catch (std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
    }
}