cmake_minimum_required (VERSION 3.0)

project(symx CXX)
project(vmclient CXX)

include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG(-std=c++11 COMPILER_SUPPORTS_CXX11)
CHECK_CXX_COMPILER_FLAG(-std=c++0x COMPILER_SUPPORTS_CXX0X)
if(COMPILER_SUPPORTS_CXX11)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
elseif(COMPILER_SUPPORTS_CXX0X)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")
else()
	message(STATUS "The compiler ${CMAKE_CXX_COMPILER} has no C++11 support. Please use a different C++ compiler.")
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O2 -Wall -Wextra -Wno-unused-parameter")
include_directories(AFTER "." "inc" "dynamorio/include")
link_directories(AFTER "dynamorio/lib64")

add_executable(symx src/main.cpp src/utils.cpp src/vm.cpp)
target_link_libraries(symx rt z3 drinjectlib drconfiglib openreil)

add_library(vmclient SHARED src/vmclient.cpp)
set_target_properties(vmclient PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
