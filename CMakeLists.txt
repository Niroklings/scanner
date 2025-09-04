cmake_minimum_required(VERSION 3.10)
project(scanner)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Кросс-платформенные настройки
if(WIN32)
    add_definitions(-D_WIN32_WINNT=0x0601)
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
elseif(APPLE)
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

# Для Windows добавляем необходимые библиотеки
if(WIN32)
    target_link_libraries(scanner Version)
endif()

target_compile_features(scanner PRIVATE cxx_std_17)