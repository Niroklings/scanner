#ifndef SCANNER_H
#define SCANNER_H

#include <string>
#include <vector>
#include <unordered_map>
#include <fstream>
#include <chrono>
#include <iostream>
#include "MD5.h"

// Кросс-платформенная обертка для filesystem
#if __has_include(<filesystem>)
#include <filesystem>
namespace fs = std::filesystem;
#elif __has_include(<experimental/filesystem>)
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#else
#error "No filesystem support"
#endif

struct ScanResult {
    size_t totalFiles;
    size_t maliciousFiles;
    size_t errorCount;
    std::chrono::milliseconds duration;
};

class Scanner {
public:
    Scanner(const std::string& basePath, const std::string& logPath);
    ~Scanner();
    
    ScanResult scanDirectory(const std::string& path);
    bool loadMaliciousHashes(const std::string& baseFile);
    
private:
    std::unordered_map<std::string, std::string> maliciousHashes;
    std::ofstream logFile;
    std::string logPath;
    
    void processFile(const fs::path& filePath, size_t& totalFiles, 
                    size_t& maliciousFiles, size_t& errorCount);
    void logMaliciousFile(const fs::path& filePath, const std::string& hash, 
                         const std::string& verdict);
   // std::string toUTF8(const std::string& str);
};

#endif