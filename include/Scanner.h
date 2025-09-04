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
    
    ScanResult() : totalFiles(0), maliciousFiles(0), errorCount(0), duration(0) {}
    ScanResult(size_t total, size_t malicious, size_t errors, std::chrono::milliseconds dur)
        : totalFiles(total), maliciousFiles(malicious), errorCount(errors), duration(dur) {}
};

class Scanner {
public:
    // Конструктор и деструктор
    Scanner(const std::string& basePath, const std::string& logPath);
    ~Scanner();
    
    // Основные методы сканирования
    ScanResult scanDirectory(const std::string& path);
    bool loadMaliciousHashes(const std::string& baseFile);
    
    // Вспомогательные методы (опционально)
    std::string calculateFileHash(const std::string& filePath);
    size_t getMaliciousHashesCount() const { return maliciousHashes.size(); }
    bool isLogFileOpen() const { return logFile.is_open(); }
    // В класс Scanner добавить:
    //size_t getMaliciousHashesCount() const { return maliciousHashes.size(); }
    std::unordered_map<std::string, std::string> maliciousHashes;
    // В класс Scanner добавить публичный метод:
   // size_t getMaliciousHashesCount() const { return maliciousHashes.size(); }
private:
    
    std::ofstream logFile;
    std::string logPath;
    
    // Внутренние методы обработки
    void processFile(const fs::path& filePath, size_t& totalFiles, 
                    size_t& maliciousFiles, size_t& errorCount);
    void logMaliciousFile(const fs::path& filePath, const std::string& hash, 
                         const std::string& verdict);
    
    // Вспомогательные методы
    bool openLogFile();
    void closeLogFile();
    std::string convertPathToString(const fs::path& path);
    
    // Запрет копирования
    Scanner(const Scanner&) = delete;
    Scanner& operator=(const Scanner&) = delete;
};

#endif // SCANNER_H
