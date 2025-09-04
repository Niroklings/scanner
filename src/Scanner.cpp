#include "../include/Scanner.h"

#include <codecvt>
#include <iomanip>
#include <locale>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#endif

Scanner::Scanner(const std::string& basePath, const std::string& logPath)
    : logPath(logPath) {
  if (!loadMaliciousHashes(basePath)) {
    throw std::runtime_error("Failed to load malicious hashes database");
  }

#ifdef _WIN32
  std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
  std::wstring wideLogPath = converter.from_bytes(logPath);
  logFile.open(wideLogPath, std::ios::out | std::ios::trunc);
#else
  logFile.open(logPath, std::ios::out | std::ios::trunc);
#endif

  if (!logFile.is_open()) {
    throw std::runtime_error("Failed to open log file: " + logPath);
  }

  logFile << "Scan Log\n";
  logFile << "========\n\n";
}

Scanner::~Scanner() {
  if (logFile.is_open()) {
    logFile.close();
  }
}

bool Scanner::loadMaliciousHashes(const std::string& baseFile) {
#ifdef _WIN32
  std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
  std::wstring wideBaseFile = converter.from_bytes(baseFile);
  std::ifstream file(wideBaseFile);
#else
  std::ifstream file(baseFile);
#endif

  if (!file.is_open()) {
    std::cerr << "Error: Cannot open base file: " << baseFile << std::endl;
    return false;
  }

  std::string line;
  while (std::getline(file, line)) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }

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
#ifdef _WIN32
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    std::wstring widePath = converter.from_bytes(path);
    fs::path dirPath(widePath);
#else
    fs::path dirPath(path);
#endif

    if (!fs::exists(dirPath) || !fs::is_directory(dirPath)) {
      throw std::runtime_error("Path does not exist or is not a directory: " +
                               path);
    }

    std::cout << "Scanning directory: " << path << std::endl;

    for (const auto& entry : fs::recursive_directory_iterator(dirPath)) {
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
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      endTime - startTime);

  return {totalFiles, maliciousFiles, errorCount, duration};
}

void Scanner::processFile(const fs::path& filePath, size_t& totalFiles,
                          size_t& maliciousFiles, size_t& errorCount) {
  totalFiles++;

  try {
    std::string filePathStr;
#ifdef _WIN32
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    filePathStr = converter.to_bytes(filePath.wstring());
#else
    filePathStr = filePath.string();
#endif

    std::string hash = MD5::hashFile(filePathStr);

    if (hash.empty()) {
      std::cerr << "Error calculating hash for: " << filePathStr << std::endl;
      errorCount++;
      return;
    }

    auto it = maliciousHashes.find(hash);
    if (it != maliciousHashes.end()) {
      maliciousFiles++;
      logMaliciousFile(filePath, hash, it->second);
      std::cout << "MALICIOUS: " << filePathStr << " - " << it->second
                << std::endl;
    }

  } catch (const std::exception& e) {
    std::cerr << "Error processing file: " << e.what() << std::endl;
    errorCount++;
  }
}

void Scanner::logMaliciousFile(const fs::path& filePath,
                               const std::string& hash,
                               const std::string& verdict) {
#ifdef _WIN32
  std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
  std::string filePathStr = converter.to_bytes(filePath.wstring());
#else
  std::string filePathStr = filePath.string();
#endif

  logFile << "File: " << filePathStr << "\n";
  logFile << "Hash: " << hash << "\n";
  logFile << "Verdict: " << verdict << "\n";
  logFile << "----------------------------------------\n";
  logFile.flush();
}
