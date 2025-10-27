//
// blocking_tcp_echo_client.cpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2003-2019 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//


// command in terminal: cd C:\Users\User\Documents\Yehonatan\open-university\defensive-programing\MessageU1
// Compile command:    g++ eg_client.cpp -o eg_client.exe -std=c++17 -lWs2_32
// Run command:    eg_client.exe 127.0.0.1 1234
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <boost/asio.hpp>

using boost::asio::ip::tcp;

void clear(char message[], int length){
    for (int i = 0; i< length; i++)
        message[i] = '\0';
}

int main(int argc, char* argv[])
{
    const int max_length = 1024;
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
        
        for( ; ; )
        {
            std::cout << "Enter message: ";
            std::string request; 
            std::getline(std::cin, request); 

            boost::asio::write(s, boost::asio::buffer(request));

            char reply[max_length];
            size_t reply_length = s.read_some(boost::asio::buffer(reply, max_length));
            
            std::cout << "Reply is: ";
            std::cout.write(reply, reply_length);
            std::cout << "\n";
        }
    }

    catch (std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
    }
} 