cmake_minimum_required(VERSION 2.6)

project(precorn)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

link_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
add_definitions(-ggdb -O2 -std=c99 -Wno-deprecated-declarations)

include_directories(src)
# OS detection
if (NOT DEFINED OS)
    if (APPLE)
        set(OS "osx")
    elseif (CMAKE_SYSTEM_NAME MATCHES "Linux")
        set(OS "linux")
#    elseif (CMAKE_SYSTEM_NAME MATCHES "NetBSD")
#        set(OS "netbsd")
    else()
        message(FATAL_ERROR "Unsupported OS: ${CMAKE_SYSTEM_NAME}")
    endif()
endif()

# CPU detection
if (NOT DEFINED CPU)
#    if (CMAKE_SYSTEM_PROCESSOR MATCHES "^i[36]86$")
#        set(CPU "i386")
     if (CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64)$")
        set(CPU "x86_64")
#    elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "^mips")
#        set(CPU "mips")
#    elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "^arm")
#        set(CPU "arm")
    else()
        message(FATAL_ERROR "Unsupported processor: ${CMAKE_SYSTEM_PROCESSOR}")
    endif()
endif()

# dlmalloc
# HAVE_MORECORE disables brk() in allocator (as it cannot coexist)
add_definitions(-DUSE_DL_PREFIX=1 -DHAVE_MORECORE=0)

# for ucontext and glib
add_definitions(-D_GNU_SOURCE -D_XOPEN_SOURCE)

file(GLOB FUZZ_SOURCES src/*.c)
add_library(precorn SHARED ${FUZZ_SOURCES} src/${OS}/${CPU}.c src/${CPU}.c)
target_link_libraries(precorn unicorn capstone)
