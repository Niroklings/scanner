#include <gtest/gtest.h>
#include "MD5.h"
#include "test_utils.hpp"

class MD5Test : public ::testing::Test {
protected:
    void SetUp() override {
        test_dir_ = test_utils::getTestResourcePath();
        test_utils::createTestDirectory(test_dir_);
    }

    void TearDown() override {
        test_utils::cleanupTestDirectory(test_dir_);
    }

    std::string test_dir_;
};

TEST_F(MD5Test, HashString) {
    EXPECT_EQ(MD5::hash("hello"), "5d41402abc4b2a76b9719d911017c592");
    EXPECT_EQ(MD5::hash(""), "d41d8cd98f00b204e9800998ecf8427e");
    EXPECT_EQ(MD5::hash("test"), "098f6bcd4621d373cade4e832627b4f6");
}

TEST_F(MD5Test, HashFile) {
    std::string file_path = test_dir_ + "/test_file.txt";
    test_utils::createTestFile(file_path, "hello");
    
    EXPECT_EQ(MD5::hashFile(file_path), "5d41402abc4b2a76b9719d911017c592");
}

TEST_F(MD5Test, HashEmptyFile) {
    std::string file_path = test_dir_ + "/empty_file.txt";
    test_utils::createTestFile(file_path, "");
    
    EXPECT_EQ(MD5::hashFile(file_path), "d41d8cd98f00b204e9800998ecf8427e");
}

TEST_F(MD5Test, HashNonExistentFile) {
    EXPECT_EQ(MD5::hashFile("non_existent_file.txt"), "");
}

TEST_F(MD5Test, HashLargeContent) {
    std::string large_content(1000, 'a');
    std::string expected_hash = "cabe45dcc9ae5b66ba86600cca6b8ba8"; 
    
    EXPECT_EQ(MD5::hash(large_content), expected_hash);
}