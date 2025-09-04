cmake_minimum_required(VERSION 3.10)
project(scanner)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Настройки для macOS
if(APPLE)
    set(CMAKE_MACOSX_RPATH 1)
endif()

# Исходные файлы
set(SOURCES
    src/main.cpp
    src/Scanner.cpp
    lib/MD5.cpp
)

# Заголовочные файлы
include_directories(include)

# Создание исполняемого файла
add_executable(scanner ${SOURCES})

# Установка целевых свойств
target_compile_features(scanner PRIVATE cxx_std_17)