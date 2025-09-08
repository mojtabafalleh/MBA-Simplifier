cmake_minimum_required(VERSION 3.8)
project(MBA-Simplifier)

set(CMAKE_CXX_STANDARD 20)

# سورس پروژه
add_executable(MBA-Simplifier "MBA-Simplifier.cpp" "simulator.h"  "analysis.h")

# include dirs
include_directories(deps/)

# Unicorn
add_subdirectory(deps/unicorn)
target_link_libraries(MBA-Simplifier unicorn "${CMAKE_SOURCE_DIR}/libs/XEDParse_x64.lib") 
