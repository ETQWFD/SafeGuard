cmake_minimum_required(VERSION 3.16)
project(SafeGuardEngine LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# ---- 第三方依赖：ClamAV / YARA / OpenSSL ----
# Windows (vcpkg): 先执行 vcpkg install clamav:x64-windows yara:x64-windows openssl:x64-windows
# Linux:           sudo apt install libclamav-dev libyara-dev libssl-dev
find_package(ClamAV REQUIRED)
find_package(YARA REQUIRED)
find_package(OpenSSL REQUIRED)

# ---- 源码 ----
set(SG_SOURCES
    src/dllmain.cpp
    src/clamav_engine.cpp
    src/yara_engine.cpp
    src/scanner.cpp
    src/hasher.cpp
    src/pe_analyzer.cpp
    src/virus_db.cpp
    src/behavior_rules.cpp
    src/realtime_monitor.cpp
    src/usb_monitor.cpp
    src/registry_monitor.cpp
    src/quarantine.cpp
    src/process_guard.cpp
    src/whitelist.cpp
    src/json_util.cpp
)

if(WIN32)
  add_library(safeguard SHARED ${SG_SOURCES})
  target_compile_definitions(safeguard PRIVATE _CRT_SECURE_NO_WARNINGS)
else()
  add_library(safeguard SHARED ${SG_SOURCES})
  target_compile_options(safeguard PRIVATE -fvisibility=hidden)
endif()

target_include_directories(safeguard PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party
    ${CLAMAV_INCLUDE_DIRS}
    ${YARA_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(safeguard PRIVATE
    ${CLAMAV_LIBRARIES}
    ${YARA_LIBRARIES}
    OpenSSL::Crypto
)

if(WIN32)
  target_link_libraries(safeguard PRIVATE
      advapi32 user32 shell32 ole32
      wintrust crypt32
  )
else()
  target_link_libraries(safeguard PRIVATE pthread)
endif()

set_target_properties(safeguard PROPERTIES
    OUTPUT_NAME "safeguard"
    POSITION_INDEPENDENT_CODE ON
)

if(WIN32)
  # 输出到项目根目录，方便 Python 加载
  set_target_properties(safeguard PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/.."
  )
else()
  set_target_properties(safeguard PROPERTIES
      LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/.."
  )
endif()

message(STATUS "ClamAV: ${CLAMAV_INCLUDE_DIRS} ${CLAMAV_LIBRARIES}")
message(STATUS "YARA:   ${YARA_INCLUDE_DIRS} ${YARA_LIBRARIES}")
