cmake_minimum_required (VERSION 3.0)

project(symx CXX)
project(z3test C)

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

include_directories(symx AFTER . inc)
add_executable(symx src/expr.cpp src/state.cpp src/utils.cpp arch/arm/arm.cpp solver/z3.cpp src/symx.cpp)
target_link_libraries(symx capstone z3)

add_executable(z3test test/z3test.c)
target_link_libraries(z3test capstone z3)
