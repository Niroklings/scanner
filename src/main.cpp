#include <iostream>
#include <string>
#include <dlfcn.h>

// C-структура для результатов
struct CScanResult {
    size_t totalFiles;
    size_t maliciousFiles;
    size_t errorCount;
    long long durationMs;
};

// Объявления C-функций
typedef void* (*CreateScannerFunc)(const char*, const char*);
typedef void (*DestroyScannerFunc)(void*);
typedef CScanResult (*ScanDirectoryFunc)(void*, const char*);
typedef bool (*LoadHashesFunc)(void*, const char*);
typedef size_t (*GetHashesCountFunc)(void*);

void printUsage() {
    std::cout << "Usage: scanner --base <base.csv> --log <report.log> --path <directory>\n";
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
    if (argc < 4) {
        printUsage();
        return 1;
    }
    
    std::string baseFile, logFile, scanPath;
    parseArguments(argc, argv, baseFile, logFile, scanPath);
    
    // Загружаем динамическую библиотеку
    void* handle = dlopen("./libScannerLib.dylib", RTLD_LAZY);
    if (!handle) {
        std::cerr << "Cannot load library: " << dlerror() << std::endl;
        return 1;
    }
    
    // Загружаем функции из библиотеки
    CreateScannerFunc createScanner = (CreateScannerFunc)dlsym(handle, "createScanner");
    DestroyScannerFunc destroyScanner = (DestroyScannerFunc)dlsym(handle, "destroyScanner");
    ScanDirectoryFunc scanDirectory = (ScanDirectoryFunc)dlsym(handle, "scanDirectory");
    LoadHashesFunc loadHashes = (LoadHashesFunc)dlsym(handle, "loadMaliciousHashes");
    GetHashesCountFunc getHashesCount = (GetHashesCountFunc)dlsym(handle, "getMaliciousHashesCount");
    
    if (!createScanner || !destroyScanner || !scanDirectory || !loadHashes) {
        std::cerr << "Cannot load functions: " << dlerror() << std::endl;
        dlclose(handle);
        return 1;
    }
    
    try {
    // Используем функции из DLL
    void* scanner = createScanner(baseFile.c_str(), logFile.c_str());
    if (!scanner) {
        throw std::runtime_error("Failed to create scanner");
    }
    
    // ЗАГРУЗКА ХЕШЕЙ УЖЕ ВЫПОЛНЯЕТСЯ В КОНСТРУКТОРЕ SCANNER
    // Не нужно вызывать loadHashes повторно!
    
   // std::cout << "Scanning directory: " << scanPath << std::endl;
    
    // Выполняем сканирование
    CScanResult result = scanDirectory(scanner, scanPath.c_str());
    
    // Вывод отчета
    std::cout << "\n=== SCAN REPORT ===\n";
    std::cout << "Total files processed: " << result.totalFiles << "\n";
    std::cout << "Malicious files found: " << result.maliciousFiles << "\n";
    std::cout << "Errors encountered: " << result.errorCount << "\n";
    std::cout << "Scan duration: " << result.durationMs << " ms\n";
    
    if (result.maliciousFiles > 0) {
        std::cout << "\nWARNING: " << result.maliciousFiles 
                  << " malicious files detected!\n";
        std::cout << "See detailed log: " << logFile << "\n";
    } else {
        std::cout << "\nScan completed successfully. No threats detected.\n";
    }
    
    destroyScanner(scanner);
    
} catch (const std::exception& e) {
    std::cerr << "Fatal error: " << e.what() << std::endl;
    dlclose(handle);
    return 1;
}
    
    dlclose(handle);
    return 0;
}