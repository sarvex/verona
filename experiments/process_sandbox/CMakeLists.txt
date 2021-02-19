cmake_minimum_required(VERSION 3.8)
project(sandbox C CXX)

INCLUDE (CheckCXXSourceCompiles)

set(CHILD_SOURCES library_runner.cc)
set(LIBSANDBOX_SOURCES libsandbox.cc)
set(LIBSANDBOX_HEADERS sandbox.hh)

include_directories(AFTER "${CMAKE_SOURCE_DIR}/../../src/rt/external/snmalloc/src")
set(CMAKE_CXX_STANDARD 17)


if (MSVC)
else ()
	add_compile_options(-mcx16 -Wall -Wextra -Werror "$<$<CONFIG:DEBUG>:-fno-inline>")
endif()

set(DEFAULT_KQUEUE false)
set(DEFAULT_PROCDESC false)
set(DEFAULT_CAPSICUM false)

if (${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
	set(DEFAULT_KQUEUE true)
	set(DEFAULT_PROCDESC true)
	set(DEFAULT_CAPSICUM true)
endif()

set(ENABLE_KQUEUE ${DEFAULT_KQUEUE} CACHE BOOL "Use kqueue for for file descriptor event handling")
set(ENABLE_PROCDESC ${DEFAULT_PROCDESC} CACHE BOOL "Use process descriptors and kqueue for creating the child process")
set(ENABLE_CAPSICUM ${DEFAULT_CAPSICUM} CACHE BOOL "Use Capsicum to restruct child process privileges")

if (${ENABLE_KQUEUE})
	add_definitions(-DUSE_KQUEUE)
endif()
if (${ENABLE_PROCDESC})
	add_definitions(-DUSE_KQUEUE_PROCDESC)
endif()
if (${ENABLE_CAPSICUM})
	add_definitions(-DUSE_CAPSICUM)
endif()

add_library(sandbox SHARED ${LIBSANDBOX_SOURCES})
add_executable(library_runner ${CHILD_SOURCES})

find_package(Threads REQUIRED)
target_link_libraries(library_runner Threads::Threads)
target_link_libraries(sandbox Threads::Threads)

if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
	target_link_libraries(library_runner -ldl -lbsd)
	target_link_libraries(sandbox -ldl -lbsd -lrt)
endif()


enable_testing()
add_subdirectory(tests)

