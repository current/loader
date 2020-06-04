cmake_minimum_required(VERSION 3.14)

project(server)

set(CMAKE_CXX_STANDARD 17)
set(source_dir "${PROJECT_SOURCE_DIR}/src")

file(GLOB_RECURSE source_files "${source_dir}/*.cpp")
file(GLOB_RECURSE header_files "${source_dir}/*.h")

add_executable(
	server
	${source_files}
	${header_files}
)