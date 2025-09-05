#include <memory>
#include <string>

#include "../../include/Scanner.h"

extern "C" {

struct CScanResult {
  size_t totalFiles;
  size_t maliciousFiles;
  size_t errorCount;
  long long durationMs;
};

void* createScanner(const char* basePath, const char* logPath) {
  try {
    return new Scanner(std::string(basePath), std::string(logPath));
  } catch (...) {
    return nullptr;
  }
}

void destroyScanner(void* scanner) { delete static_cast<Scanner*>(scanner); }

CScanResult scanDirectory(void* scanner, const char* path) {
  Scanner* sc = static_cast<Scanner*>(scanner);
  if (!sc) return {0, 0, 0, 0};

  try {
    auto result = sc->scanDirectory(std::string(path));
    return {result.totalFiles, result.maliciousFiles, result.errorCount,
            static_cast<long long>(result.duration.count())};
  } catch (...) {
    return {0, 0, 0, 0};
  }
}

bool loadMaliciousHashes(void* scanner, const char* baseFile) {
  Scanner* sc = static_cast<Scanner*>(scanner);
  if (!sc) return false;

  return sc->loadMaliciousHashes(std::string(baseFile));
}

size_t getMaliciousHashesCount(void* scanner) {
  Scanner* sc = static_cast<Scanner*>(scanner);
  if (!sc) return 0;
  return sc->getMaliciousHashesCount();
}
}