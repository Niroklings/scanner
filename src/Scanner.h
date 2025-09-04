#ifndef SCANNER_H
#define SCANNER_H

#include <string>
#include <vector>
#include <unordered_map>
#include <fstream>
#include <chrono>
#include <filesystem>
#include "MD5.h"

namespace fs = std::filesystem;

struct ScanResult {
    size_t totalFiles;
    size_t maliciousFiles;
    size_t errorCount;
    std::chrono::milliseconds duration;
};

class Scanner {
public:
    Scanner(const std::string& basePath, const std::string& logPath);
    
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
};

#endif