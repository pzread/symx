cmake_minimum_required (VERSION 3.0)

project(symx CXX)
project(vmclient CXX)

include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG(-std=c++14 COMPILER_SUPPORTS_CXX14)
CHECK_CXX_COMPILER_FLAG(-std=c++1y COMPILER_SUPPORTS_CXX1Y)
if(COMPILER_SUPPORTS_CXX14)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14")
elseif(COMPILER_SUPPORTS_CXX1Y)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++1y")
else()
	message(STATUS "The compiler ${CMAKE_CXX_COMPILER} has no C++14 support. Please use a different C++ compiler.")
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -Wall -Wextra -Wno-unused-parameter")

include_directories(AFTER "." "inc" "dynamorio/include")
link_directories(AFTER "dynamorio/lib64")

add_executable(symx src/main.cpp src/utils.cpp src/expr.cpp src/state.cpp src/vm.cpp solver/z3.cpp arch/openreil/openreil.cpp)
target_link_libraries(symx rt z3 drinjectlib drconfiglib openreil)
set_target_properties(symx PROPERTIES COMPILE_FLAGS "-g" LINK_FLAGS "-pthread")

add_library(vmclient SHARED src/vmclient.cpp)
set_target_properties(vmclient PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
