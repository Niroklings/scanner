#ifndef SCANNER_H
#define SCANNER_H

#include <string>
#include <vector>
#include <unordered_map>
#include <fstream>
#include <chrono>
#include <iostream>
#include "MD5.h"

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
    
    ScanResult() : totalFiles(0), maliciousFiles(0), errorCount(0), duration(0) {}
    ScanResult(size_t total, size_t malicious, size_t errors, std::chrono::milliseconds dur)
        : totalFiles(total), maliciousFiles(malicious), errorCount(errors), duration(dur) {}
};

class Scanner {
public:
    Scanner(const std::string& basePath, const std::string& logPath);
    ~Scanner();
    
    ScanResult scanDirectory(const std::string& path);
    bool loadMaliciousHashes(const std::string& baseFile);
    
    std::string calculateFileHash(const std::string& filePath);
    size_t getMaliciousHashesCount() const { return maliciousHashes.size(); }
    bool isLogFileOpen() const { return logFile.is_open(); }
    std::unordered_map<std::string, std::string> maliciousHashes;
private:
    
    std::ofstream logFile;
    std::string logPath;
    
    void processFile(const fs::path& filePath, size_t& totalFiles, 
                    size_t& maliciousFiles, size_t& errorCount);
    void logMaliciousFile(const fs::path& filePath, const std::string& hash, 
                         const std::string& verdict);
    
    bool openLogFile();
    void closeLogFile();
    std::string convertPathToString(const fs::path& path);
    
    Scanner(const Scanner&) = delete;
    Scanner& operator=(const Scanner&) = delete;
};

#endif 
