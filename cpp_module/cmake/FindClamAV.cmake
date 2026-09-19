# FindClamAV.cmake - 定位 libclamav
# 查找顺序：vcpkg / 系统默认路径 / 手动指定 CLAMAV_ROOT

find_path(CLAMAV_INCLUDE_DIR
    NAMES clamav.h
    HINTS ${CLAMAV_ROOT}/include
          ${CMAKE_PREFIX_PATH}/include
    PATH_SUFFIXES clamav
)

find_library(CLAMAV_LIBRARY
    NAMES clamav libclamav
    HINTS ${CLAMAV_ROOT}/lib ${CLAMAV_ROOT}/bin
          ${CMAKE_PREFIX_PATH}/lib
)

if(CLAMAV_INCLUDE_DIR AND CLAMAV_LIBRARY)
    set(CLAMAV_FOUND TRUE)
    set(CLAMAV_INCLUDE_DIRS ${CLAMAV_INCLUDE_DIR})
    set(CLAMAV_LIBRARIES ${CLAMAV_LIBRARY})
    message(STATUS "Found ClamAV: ${CLAMAV_LIBRARY}")
else()
    set(CLAMAV_FOUND FALSE)
    message(FATAL_ERROR "libclamav not found. Install it first:\n"
        "  Windows: vcpkg install clamav:x64-windows\n"
        "  Linux:   sudo apt install libclamav-dev\n"
        "  or set -DCLAMAV_ROOT=<path>")
endif()

mark_as_advanced(CLAMAV_INCLUDE_DIR CLAMAV_LIBRARY)
