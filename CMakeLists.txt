cmake_minimum_required(VERSION 3.10)
project(scanner)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(APPLE)
    set(CMAKE_MACOSX_RPATH 1)
endif()

enable_testing()

find_package(GTest REQUIRED)
include(GoogleTest)

add_subdirectory(scannerlib)

add_executable(scanner src/main.cpp)
target_link_libraries(scanner ScannerLib ${CMAKE_DL_LIBS})

add_executable(scanner_tests
    tests/test_md5.cpp
    tests/test_scanner.cpp
    tests/test_main.cpp
    lib/MD5.cpp
    src/Scanner.cpp
)

target_link_libraries(scanner_tests
    GTest::gtest_main
    ${CMAKE_DL_LIBS}
)

target_include_directories(scanner_tests PRIVATE include)

gtest_discover_tests(scanner_tests)

add_test(NAME scanner_tests COMMAND scanner_tests)

include_directories(include)

add_custom_target(test_all
    COMMAND ./scanner_tests
    DEPENDS scanner_tests
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running all tests"
)