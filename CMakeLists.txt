cmake_minimum_required(VERSION 2.6)

project(precorn)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

link_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
add_definitions(-ggdb -O2 -std=c99 -Wno-deprecated-declarations)

# dlmalloc
# HAVE_MORECORE disables brk() in allocator (as it cannot coexist)
add_definitions(-DUSE_DL_PREFIX=1 -DHAVE_MORECORE=0)

file(GLOB_RECURSE FUZZ_SOURCES src/*.c)
add_library(precorn SHARED ${FUZZ_SOURCES})
target_link_libraries(precorn unicorn capstone)
