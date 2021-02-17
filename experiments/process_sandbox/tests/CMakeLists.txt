project(snadbox-tests C CXX)
set(UNIT_TESTS
	child_process
	shm
	socketpair
	poller
	)

find_package(Threads REQUIRED)

foreach(TEST_NAME ${UNIT_TESTS})
	set(TEST_SRC "${TEST_NAME}.cc")
	set(TEST_NAME "test-${TEST_NAME}")
	add_executable(${TEST_NAME} ${TEST_SRC})
	set_target_properties(${TEST_NAME} PROPERTIES
		INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR};${CMAKE_SOURCE_DIR}/../../src/rt/external/snmalloc/src"
	)
	target_link_libraries(${TEST_NAME} Threads::Threads)
	if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
		target_link_libraries(${TEST_NAME} rt)
	endif ()
	add_test(${TEST_NAME} ${TEST_NAME})
endforeach()
