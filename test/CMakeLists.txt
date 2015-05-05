cmake_minimum_required (VERSION 2.6)

project(dyntrac C)

set(CMAKE_C_FLAGS "-DUNIX -O2 -Wall -Wextra -Wno-unused-parameter")

find_package(DynamoRIO)
if (NOT DynamoRIO_FOUND)
    message(FATAL_ERROR "DynamoRIO package required to build")
endif(NOT DynamoRIO_FOUND)
add_library(dyntrac SHARED dyntrac.c)
configure_DynamoRIO_client(dyntrac)
