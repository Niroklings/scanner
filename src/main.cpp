#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#ifdef _WIN32
#include <windows.h>
#endif
#include "Scanner.h"

void printUsage() {
    std::cout << "Usage: scanner --base <base.csv> --log <report.log> --path <directory>\n";
    std::cout << "Options:\n";
    std::cout << "  --base    Path to CSV file with malicious hashes\n";
    std::cout << "  --log     Path to output log file\n";
    std::cout << "  --path    Directory to scan\n";
    std::cout << "  --help    Show this help message\n";
}

void parseArguments(int argc, char* argv[], std::string& baseFile, 
                   std::string& logFile, std::string& scanPath) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--base" && i + 1 < argc) {
            baseFile = argv[++i];
        } else if (arg == "--log" && i + 1 < argc) {
            logFile = argv[++i];
        } else if (arg == "--path" && i + 1 < argc) {
            scanPath = argv[++i];
        } else if (arg == "--help") {
            printUsage();
            exit(0);
        }
    }
    
    if (baseFile.empty() || logFile.empty() || scanPath.empty()) {
        printUsage();
        exit(1);
    }
}

int main(int argc, char* argv[]) {
    // Устанавливаем кодировку для Windows
    #ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    #endif
    
    if (argc < 4) {
        printUsage();
        return 1;
    }
    
    std::string baseFile, logFile, scanPath;
    parseArguments(argc, argv, baseFile, logFile, scanPath);
    
    try {
        Scanner scanner(baseFile, logFile);
        ScanResult result = scanner.scanDirectory(scanPath);
        
        // Вывод отчета
        std::cout << "\n=== SCAN REPORT ===\n";
        std::cout << "Total files processed: " << result.totalFiles << "\n";
        std::cout << "Malicious files found: " << result.maliciousFiles << "\n";
        std::cout << "Errors encountered: " << result.errorCount << "\n";
        std::cout << "Scan duration: " << result.duration.count() << " ms\n";
        
        if (result.maliciousFiles > 0) {
            std::cout << "\nWARNING: " << result.maliciousFiles 
                      << " malicious files detected!\n";
            std::cout << "See detailed log: " << logFile << "\n";
        } else {
            std::cout << "\nScan completed successfully. No threats detected.\n";
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}