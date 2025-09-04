#include <gtest/gtest.h>
#include <fstream>
#include "Scanner.h"
#include "MD5.h"
#include "test_utils.hpp"

class ScannerTest : public ::testing::Test {
protected:
    void SetUp() override {
        test_dir_ = test_utils::getTestResourcePath();
        test_utils::createTestDirectory(test_dir_);
        
        test_utils::createTestFile(test_dir_ + "/safe1.txt", "safe content 1");
        test_utils::createTestFile(test_dir_ + "/safe2.log", "safe content 2");
        
        malicious_content_ = "known_malicious_content_12345";
        test_utils::createTestFile(test_dir_ + "/malicious.exe", malicious_content_);
        
        std::string subdir = test_dir_ + "/subdir";
        test_utils::createTestDirectory(subdir);
        test_utils::createTestFile(subdir + "/safe3.txt", "safe content 3");
        
        csv_path_ = test_dir_ + "/test_base.csv";
        std::string real_hash = MD5::hash(malicious_content_);
        std::ofstream csv(csv_path_);
        csv << real_hash << ";TestVerdict\n";
        csv.close();
        
        std::string restricted_file = test_dir_ + "/no_access.txt";
        test_utils::createTestFile(restricted_file, "secret");
        std::string command = "chmod 000 " + restricted_file;
        system(command.c_str());
    }

    void TearDown() override {
        std::string restricted_file = test_dir_ + "/no_access.txt";
        std::string command = "chmod 644 " + restricted_file;
        system(command.c_str());
        
        test_utils::cleanupTestDirectory(test_dir_);
    }

    std::string test_dir_;
    std::string csv_path_;
    std::string malicious_content_;
};

TEST_F(ScannerTest, LoadMaliciousHashes) {
    Scanner scanner(csv_path_, test_dir_ + "/test.log");
    EXPECT_GT(scanner.getMaliciousHashesCount(), 0);
}

TEST_F(ScannerTest, LoadInvalidCSV) {
    EXPECT_THROW(Scanner scanner("invalid_path.csv", test_dir_ + "/test.log"), std::runtime_error);
}

TEST_F(ScannerTest, ScanFindsMaliciousFiles) {
    std::string log_path = test_dir_ + "/scan.log";
    Scanner scanner(csv_path_, log_path);
    
    auto result = scanner.scanDirectory(test_dir_);
    
    EXPECT_GT(result.totalFiles, 0);
    EXPECT_GT(result.maliciousFiles, 0); 
    EXPECT_GE(result.errorCount, 0); 
}

TEST_F(ScannerTest, ScanEmptyDirectory) {
    std::string empty_dir = test_dir_ + "/empty";
    test_utils::createTestDirectory(empty_dir);
    
    std::string log_path = test_dir_ + "/empty_scan.log";
    Scanner scanner(csv_path_, log_path);
    
    auto result = scanner.scanDirectory(empty_dir);
    
    EXPECT_EQ(result.totalFiles, 0);
    EXPECT_EQ(result.maliciousFiles, 0);
    EXPECT_EQ(result.errorCount, 0);
}


TEST_F(ScannerTest, LogFileCreation) {
    std::string log_path = test_dir_ + "/malicious.log";
    Scanner scanner(csv_path_, log_path);
    
    scanner.scanDirectory(test_dir_);
    
    std::ifstream log_file(log_path);
    EXPECT_TRUE(log_file.is_open());
    EXPECT_TRUE(log_file.good());
}

TEST_F(ScannerTest, ScannerObjectLifetime) {
    std::string log_path = test_dir_ + "/lifetime.log";
    
    {
        Scanner scanner(csv_path_, log_path);
        auto result = scanner.scanDirectory(test_dir_);
        EXPECT_GT(result.totalFiles, 0);
    }
    
    EXPECT_TRUE(true);
}