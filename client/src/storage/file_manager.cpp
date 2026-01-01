#include "storage/file_manager.h"
#include <stdexcept>
#include <filesystem>

std::string FileManager::read_file_binary(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot open file: " + filepath);
    }
    // Read the whole file into a string
    return std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

std::string FileManager::read_file_text(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file) {
        throw std::runtime_error("Cannot open file: " + filepath);
    }
    std::string content;
    std::string line;
    while (std::getline(file, line)) {
        content += line + "\n";
    }
    return content;
}

void FileManager::write_file_binary(const std::string& filepath, const std::string& content) {
    std::ofstream file(filepath, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot write to file: " + filepath);
    }
    file.write(content.data(), content.size());
    file.close();
}

void FileManager::write_file_text(const std::string& filepath, const std::string& content) {
    std::ofstream file(filepath);
    if (!file) {
        throw std::runtime_error("Cannot write to file: " + filepath);
    }
    file << content;
    file.close();
}

bool FileManager::file_exists(const std::string& filepath) {
    return std::filesystem::exists(filepath);
}

bool FileManager::delete_file(const std::string& filepath) {
    try {
        if (std::filesystem::exists(filepath)) {
            return std::filesystem::remove(filepath);
        }
        return false;
    } catch (...) {
        return false;
    }
}


