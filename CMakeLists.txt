cmake_minimum_required(VERSION 3.14)

project(server-client)

find_package(LLVM REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_STANDARD 17)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")

set(USE_SYSTEM_CURL ON CACHE BOOL "" FORCE)
set(BUILD_CPR_TESTS OFF CACHE BOOL "" FORCE)
set(SPDLOG_BUILD_TESTING OFF CACHE BOOL "" FORCE)

find_package(OpenSSL REQUIRED)

set(OPENSSL_USE_STATIC_LIBS TRUE)

add_subdirectory(shared/spdlog)
add_subdirectory(shared/cpr)
add_subdirectory(server)
add_subdirectory(client)

target_include_directories(server PRIVATE ${PROJECT_SOURCE_DIR}/shared ${OPENSSL_INCLUDE_DIR} ${CPR_INCLUDE_DIRS})
target_link_libraries(server PRIVATE spdlog ${OPENSSL_LIBRARIES} ${CPR_LIBRARIES})

target_include_directories(client PRIVATE ${PROJECT_SOURCE_DIR}/shared ${OPENSSL_INCLUDE_DIR})
target_link_libraries(client PRIVATE spdlog ${OPENSSL_LIBRARIES} )
