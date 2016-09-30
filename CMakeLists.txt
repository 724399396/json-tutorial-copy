cmake_minimum_required (VERSION 2.6)
project (leptjson_test C)

if (CMAKE_C_COMPILTER_ID MATCHES "GNU|Clang")
   set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS -ansi -pendantic -Wall")
endif()

add_library(leptjson leptjson.c)
add_executable(leptjson_test test.c)
target_link_libraries(leptjson_test leptjson)
