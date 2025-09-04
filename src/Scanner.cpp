#include "Scanner.h"
#include <iostream>
#include <sstream>
#include <iomanip>

Scanner::Scanner(const std::string& basePath, const std::string& logPath) 
    : logPath(logPath) {
    if (!loadMaliciousHashes(basePath)) {
        throw std::runtime_error("Failed to load malicious hashes database");
    }
    
    logFile.open(logPath, std::ios::out | std::ios::trunc);
    if (!logFile.is_open()) {
        throw std::runtime_error("Failed to open log file: " + logPath);
    }
    
    // Записываем заголовок в лог
    logFile << "Scan Log\n";
    logFile << "========\n\n";
}

bool Scanner::loadMaliciousHashes(const std::string& baseFile) {
    std::ifstream file(baseFile);
    if (!file.is_open()) {
        std::cerr << "Error: Cannot open base file: " << baseFile << std::endl;
        return false;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        size_t pos = line.find(';');
        if (pos != std::string::npos) {
            std::string hash = line.substr(0, pos);
            std::string verdict = line.substr(pos + 1);
            maliciousHashes[hash] = verdict;
        }
    }
    
    std::cout << "Loaded " << maliciousHashes.size() << " malicious hashes\n";
    return true;
}

ScanResult Scanner::scanDirectory(const std::string& path) {
    size_t totalFiles = 0;
    size_t maliciousFiles = 0;
    size_t errorCount = 0;
    
    auto startTime = std::chrono::high_resolution_clock::now();
    
    try {
        if (!fs::exists(path) || !fs::is_directory(path)) {
            throw std::runtime_error("Path does not exist or is not a directory: " + path);
        }
        
        std::cout << "Scanning directory: " << path << std::endl;
        
        for (const auto& entry : fs::recursive_directory_iterator(path)) {
            if (entry.is_regular_file()) {
                processFile(entry.path(), totalFiles, maliciousFiles, errorCount);
            }
        }
    } catch (const fs::filesystem_error& e) {
        std::cerr << "Filesystem error: " << e.what() << std::endl;
        errorCount++;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        errorCount++;
    }
    
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
    
    return {totalFiles, maliciousFiles, errorCount, duration};
}

void Scanner::processFile(const fs::path& filePath, size_t& totalFiles, 
                         size_t& maliciousFiles, size_t& errorCount) {
    totalFiles++;
    
    try {
        std::string hash = MD5::hashFile(filePath.string());
        
        if (hash.empty()) {
            std::cerr << "Error calculating hash for: " << filePath << std::endl;
            errorCount++;
            return;
        }
        
        auto it = maliciousHashes.find(hash);
        if (it != maliciousHashes.end()) {
            maliciousFiles++;
            logMaliciousFile(filePath, hash, it->second);
            std::cout << "MALICIOUS: " << filePath << " - " << it->second << std::endl;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error processing file " << filePath << ": " << e.what() << std::endl;
        errorCount++;
    }
}

void Scanner::logMaliciousFile(const fs::path& filePath, const std::string& hash, 
                              const std::string& verdict) {
    logFile << "File: " << filePath.string() << "\n";
    logFile << "Hash: " << hash << "\n";
    logFile << "Verdict: " << verdict << "\n";
    logFile << "----------------------------------------\n";
    logFile.flush();
}