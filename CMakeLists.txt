cmake_minimum_required(VERSION 3.10)
project(scanner)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Настройки для macOS
if(APPLE)
    set(CMAKE_MACOSX_RPATH 1)
endif()

# Подключаем динамическую библиотеку
add_subdirectory(scannerlib)

# Основной исполняемый файл
add_executable(scanner src/main.cpp)
target_link_libraries(scanner ScannerLib)

# Заголовочные файлы
include_directories(include)