# Simple build for the C++ inspection core (alternative to CMake).
CXX ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -Wpedantic -O2 -Iinclude

.PHONY: all test clean

all: mcp-inspect

mcp-inspect: src/main.cpp include/mcp_inspect.hpp
	$(CXX) $(CXXFLAGS) src/main.cpp -o mcp-inspect

test_inspect: tests/test_inspect.cpp include/mcp_inspect.hpp
	$(CXX) $(CXXFLAGS) tests/test_inspect.cpp -o test_inspect

test: test_inspect
	./test_inspect

clean:
	rm -f mcp-inspect test_inspect
