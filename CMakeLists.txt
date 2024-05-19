cmake_minimum_required(VERSION 3.15)
project(sentinel VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

option(SENTINEL_BUILD_TOOLS "Build standalone tools" ON)
option(SENTINEL_BUILD_EXAMPLES "Build examples" ON)
option(SENTINEL_BUILD_TESTS "Build unit tests" ON)

if(MSVC)
    add_compile_options(/W4 /WX- /MP)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS UNICODE _UNICODE)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

include_directories(${CMAKE_SOURCE_DIR}/include)

file(GLOB_RECURSE SENTINEL_SOURCES "src/*.cpp" "src/*.c")

add_library(sentinel STATIC ${SENTINEL_SOURCES})
target_include_directories(sentinel PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

if(WIN32)
    target_link_libraries(sentinel PUBLIC ntdll dbghelp psapi)
endif()

install(TARGETS sentinel ARCHIVE DESTINATION lib)
install(DIRECTORY include/sentinel DESTINATION include)

# Tools
if(SENTINEL_BUILD_TOOLS)
    add_executable(sig_scan tools/sig_scan.cpp)
    target_link_libraries(sig_scan sentinel)
endif()

if(SENTINEL_BUILD_TOOLS)
    add_executable(ac_probe tools/ac_probe.cpp)
    target_link_libraries(ac_probe sentinel)
endif()

# Examples
if(SENTINEL_BUILD_EXAMPLES)
    add_executable(basic_scan examples/basic_scan.cpp)
    target_link_libraries(basic_scan sentinel)
    add_executable(driver_comm_example examples/driver_comm.cpp)
    target_link_libraries(driver_comm_example sentinel)
endif()
