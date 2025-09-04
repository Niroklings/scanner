#include <string>
#include <memory>
#include "../../include/Scanner.h"

// C-интерфейс для совместимости
extern "C" {

// Простая C-структура для результатов (без C++ типов)
struct CScanResult {
    size_t totalFiles;
    size_t maliciousFiles;
    size_t errorCount;
    long long durationMs;
};

// Создание сканера
void* createScanner(const char* basePath, const char* logPath) {
    try {
        return new Scanner(std::string(basePath), std::string(logPath));
    } catch (...) {
        return nullptr;
    }
}

// Уничтожение сканера
void destroyScanner(void* scanner) {
    delete static_cast<Scanner*>(scanner);
}

// Сканирование директории
CScanResult scanDirectory(void* scanner, const char* path) {
    Scanner* sc = static_cast<Scanner*>(scanner);
    if (!sc) return {0, 0, 0, 0};
    
    try {
        auto result = sc->scanDirectory(std::string(path));
        return {
            result.totalFiles,
            result.maliciousFiles,
            result.errorCount,
            static_cast<long long>(result.duration.count())
        };
    } catch (...) {
        return {0, 0, 0, 0};
    }
}

// Загрузка базы хешей
bool loadMaliciousHashes(void* scanner, const char* baseFile) {
    Scanner* sc = static_cast<Scanner*>(scanner);
    if (!sc) return false;
    
    return sc->loadMaliciousHashes(std::string(baseFile));
}

// Получение количества загруженных хешей
size_t getMaliciousHashesCount(void* scanner) {
    Scanner* sc = static_cast<Scanner*>(scanner);
    if (!sc) return 0;
    
    // Используем публичный метод, который нужно добавить в Scanner
    return sc->getMaliciousHashesCount();
}

} // extern "C"