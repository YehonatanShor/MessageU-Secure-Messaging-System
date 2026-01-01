#pragma once

#include <string>
#include <fstream>

/**
 * File I/O operations manager.
 * 
 * This class provides simple file reading and writing operations
 * with proper error handling.
 */
class FileManager {
public:
    /**
     * Read entire file content as binary string.
     * 
     * @param filepath Path to the file
     * @return File content as string
     * @throws std::runtime_error if file cannot be opened or read
     */
    static std::string read_file_binary(const std::string& filepath);
    
    /**
     * Read entire file content as text (line by line).
     * 
     * @param filepath Path to the file
     * @return File content as string
     * @throws std::runtime_error if file cannot be opened or read
     */
    static std::string read_file_text(const std::string& filepath);
    
    /**
     * Write content to file (binary mode).
     * 
     * @param filepath Path to the file
     * @param content Data to write
     * @throws std::runtime_error if file cannot be written
     */
    static void write_file_binary(const std::string& filepath, const std::string& content);
    
    /**
     * Write content to file (text mode).
     * 
     * @param filepath Path to the file
     * @param content Data to write
     * @throws std::runtime_error if file cannot be written
     */
    static void write_file_text(const std::string& filepath, const std::string& content);
    
    /**
     * Check if file exists.
     * 
     * @param filepath Path to the file
     * @return true if file exists, false otherwise
     */
    static bool file_exists(const std::string& filepath);
    
    /**
     * Delete a file.
     * 
     * @param filepath Path to the file
     * @return true if file was deleted, false otherwise
     */
    static bool delete_file(const std::string& filepath);
};



