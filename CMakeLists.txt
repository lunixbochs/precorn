cmake_minimum_required(VERSION 2.6)

project(fuzzl)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

link_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
add_definitions(-O2 -std=c99)

file(GLOB_RECURSE FUZZ_SOURCES src/*.c)
add_library(fuzzl SHARED ${FUZZ_SOURCES})
target_link_libraries(fuzzl unicorn)
