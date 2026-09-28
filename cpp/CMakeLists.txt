# C++ port of the MCP stdio proxy inspection core (Gap 5 companion to ../rust).
# STATUS: VERIFIED via a g++ Docker image (see cpp/README.md).
cmake_minimum_required(VERSION 3.16)
project(mcp_inspect_cpp CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra -Wpedantic)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

add_executable(mcp-inspect src/main.cpp)

enable_testing()
add_executable(test_inspect tests/test_inspect.cpp)
add_test(NAME inspect_parity COMMAND test_inspect)
