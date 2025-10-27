//
// blocking_tcp_echo_server.cpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2003-2019 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//


// command in terminal: cd C:\Users\User\Documents\Yehonatan\open-university\defensive-programing\MessageU1
// Compile command:    g++ eg_server.cpp -o eg_server.exe -std=c++17 -lWs2_32
// Run command:    eg_server.exe 1234 
#include <cstdlib>
#include <iostream>
#include <thread>
#include <utility>
#include <boost/asio.hpp>

using boost::asio::ip::tcp;

const int max_length = 1024;

void clear(char message[], int length)
{
    for (int i = 0; i< length; i++)
        message[i] = '\0';
}

void session(tcp::socket sock) {
    try
    {
        for (;;)
        {
            char data[max_length];
            size_t reply_length =
            boost::asio::read(sock,boost::asio::buffer(data,
            max_length));
            std::cout << "Received message: " << data <<std::endl;
            clear(data, max_length);
            std::cout << "Enter message: ";
            std::cin.getline(data, max_length);
            boost::asio::write(sock, boost::asio::buffer(data,
            max_length));
        }
    }
    catch (std::exception& e)
    {
        
    }
}

void server(boost::asio::io_context& io_context, unsigned short port)
{
    tcp::acceptor a(io_context, tcp::endpoint(tcp::v4(), port));
    for ( ; ; )
    {
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