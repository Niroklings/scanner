add_library(ScannerLib SHARED 
    src/ScannerLib.cpp
    ../src/Scanner.cpp
    ../lib/MD5.cpp
)

target_include_directories(ScannerLib PUBLIC ../include)

if(APPLE)
    set_target_properties(ScannerLib PROPERTIES
        OUTPUT_NAME "ScannerLib"
        SUFFIX ".dylib"
        MACOSX_RPATH ON
    )
endif()