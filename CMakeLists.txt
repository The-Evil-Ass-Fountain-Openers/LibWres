cmake_minimum_required(VERSION 3.16)

project(LibWres LANGUAGES CXX)
# specify the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

include(CMakePackageConfigHelpers)

add_definitions(-DHAVE_DIRENT_H=1)
add_definitions(-D_GNU_SOURCE=1)
set(COMMON_INCLUDE "common/")
include_directories(${COMMON_INCLUDE})

#add_subdirectory(common)
add_subdirectory(wres)


#add_subdirectory(test)
