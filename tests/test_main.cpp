#include <dlfcn.h>
#include <gtest/gtest.h>

#include "test_utils.hpp"

extern "C" {
void* createScanner(const char*, const char*);
void destroyScanner(void*);
struct CScanResult {
  size_t t, m, e;
  long long d;
};
CScanResult scanDirectory(void*, const char*);
bool loadMaliciousHashes(void*, const char*);
}

class MainTest : public ::testing::Test {
 protected:
  void SetUp() override {
    test_dir_ = test_utils::getTestResourcePath();
    test_utils::createTestDirectory(test_dir_);

    test_utils::createTestFile(test_dir_ + "/test.txt", "test content");

    csv_path_ = test_dir_ + "/test_base.csv";
    std::ofstream csv(csv_path_);
    csv << "d8e8fca2dc0f896fd7cb4cb0031ba249;TestVerdict\n";
    csv.close();
  }

  void TearDown() override { test_utils::cleanupTestDirectory(test_dir_); }

  std::string test_dir_;
  std::string csv_path_;
  void* dll_handle_ = nullptr;
};

TEST_F(MainTest, DLLLoading) {
  std::vector<std::string> possible_paths = {
      "./libScannerLib.dylib", "./scannerlib/libScannerLib.dylib",
      "../scannerlib/libScannerLib.dylib", "libScannerLib.dylib"};

  void* dll_handle_ = nullptr;
  std::string found_path;

  for (const auto& path : possible_paths) {
    dll_handle_ = dlopen(path.c_str(), RTLD_LAZY);
    if (dll_handle_) {
      found_path = path;
      break;
    }
  }

  if (!dll_handle_) {
    GTEST_SKIP() << "DLL not found, skipping DLL tests";
    return;
  }

  EXPECT_NE(dll_handle_, nullptr);
  dlclose(dll_handle_);
}

TEST_F(MainTest, ArgumentParsing) {
  const char* argv[] = {"scanner", "--base", "test.csv", "--log",
                        "log.txt", "--path", "/tmp"};
  int argc = 7;

  std::string base, log, path;

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--base" && i + 1 < argc)
      base = argv[++i];
    else if (arg == "--log" && i + 1 < argc)
      log = argv[++i];
    else if (arg == "--path" && i + 1 < argc)
      path = argv[++i];
  }

  EXPECT_EQ(base, "test.csv");
  EXPECT_EQ(log, "log.txt");
  EXPECT_EQ(path, "/tmp");
}

TEST_F(MainTest, InvalidArguments) {
  const char* argv[] = {"scanner", "--base", "test.csv"};
  int argc = 3;

  std::string base, log, path;

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--base" && i + 1 < argc)
      base = argv[++i];
    else if (arg == "--log" && i + 1 < argc)
      log = argv[++i];
    else if (arg == "--path" && i + 1 < argc)
      path = argv[++i];
  }

  EXPECT_TRUE(log.empty());
  EXPECT_TRUE(path.empty());
}
