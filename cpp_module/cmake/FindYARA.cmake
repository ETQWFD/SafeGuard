# FindYARA.cmake - 定位 libyara
# 查找顺序：vcpkg / 系统默认路径 / 手动指定 YARA_ROOT

find_path(YARA_INCLUDE_DIR
    NAMES yara.h
    HINTS ${YARA_ROOT}/include
          ${CMAKE_PREFIX_PATH}/include
)

find_library(YARA_LIBRARY
    NAMES yara libyara
    HINTS ${YARA_ROOT}/lib ${YARA_ROOT}/bin
          ${CMAKE_PREFIX_PATH}/lib
)

if(YARA_INCLUDE_DIR AND YARA_LIBRARY)
    set(YARA_FOUND TRUE)
    set(YARA_INCLUDE_DIRS ${YARA_INCLUDE_DIR})
    set(YARA_LIBRARIES ${YARA_LIBRARY})
    message(STATUS "Found YARA: ${YARA_LIBRARY}")
else()
    set(YARA_FOUND FALSE)
    message(FATAL_ERROR "libyara not found. Install it first:\n"
        "  Windows: vcpkg install yara:x64-windows\n"
        "  Linux:   sudo apt install libyara-dev\n"
        "  or set -DYARA_ROOT=<path>")
endif()

mark_as_advanced(YARA_INCLUDE_DIR YARA_LIBRARY)
