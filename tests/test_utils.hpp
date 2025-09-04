#ifndef TEST_UTILS_HPP
#define TEST_UTILS_HPP

#include <string>
#include <fstream>
#include <filesystem>

namespace test_utils {

inline void createTestFile(const std::string& path, const std::string& content) {
    std::ofstream file(path);
    file << content;
    file.close();
}

inline void createTestDirectory(const std::string& path) {
    std::filesystem::create_directories(path);
}

inline void cleanupTestDirectory(const std::string& path) {
    std::filesystem::remove_all(path);
}

inline std::string getTestResourcePath() {
    return std::filesystem::temp_directory_path() / "scanner_test";
}

} 

#endif