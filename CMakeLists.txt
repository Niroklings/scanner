cmake_minimum_required(VERSION 3.10)
project(scanner)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Настройки для macOS
if(APPLE)
    set(CMAKE_MACOSX_RPATH 1)
endif()

# Поиск GTest
find_package(GTest REQUIRED)
include(GoogleTest)

# Основной проект
add_subdirectory(scannerlib)

# Исполняемый файл
add_executable(scanner src/main.cpp)
target_link_libraries(scanner ScannerLib ${CMAKE_DL_LIBS})

# Тесты
add_executable(tests
    tests/test_md5.cpp
    tests/test_scanner.cpp
    tests/test_main.cpp
    lib/MD5.cpp
    src/Scanner.cpp
)

target_link_libraries(tests
    GTest::gtest
    GTest::gtest_main
    ${CMAKE_DL_LIBS}
)

target_include_directories(tests PRIVATE include)
gtest_discover_tests(tests)

# Заголовочные файлы
include_directories(include)