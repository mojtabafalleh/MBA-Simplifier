cmake_minimum_required(VERSION 3.8)
project(MBA-Simplifier)

set(CMAKE_CXX_STANDARD 20)

# سورس پروژه
add_executable(MBA-Simplifier "MBA-Simplifier.cpp" "simulator.h"  "analysis.h"  "InstructionSynthesizer.h")

# include dirs
include_directories(deps/)

# Unicorn
add_subdirectory(deps/unicorn)
target_link_libraries(MBA-Simplifier unicorn "${CMAKE_SOURCE_DIR}/libs/XEDParse_x64.lib") 

add_custom_command(TARGET MBA-Simplifier POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_SOURCE_DIR}/deps/XEDParse.dll"
        $<TARGET_FILE_DIR:MBA-Simplifier>
)