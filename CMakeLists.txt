project(installer)

cmake_minimum_required(VERSION 2.8)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wfatal-errors -pedantic -std=c89 -Wl,--no-undefined -fPIC -Wall -Wextra -Wconversion -Werror=return-type")

add_library(minitar STATIC "minitar.c")
add_executable(example "example.c")
target_link_libraries(example minitar)
