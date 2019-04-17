project(installer)

cmake_minimum_required(VERSION 2.8)

set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden -Wfatal-errors -pedantic -std=gnu89 -Wl,--no-undefined -fPIC -Wall -Wextra -Wconversion -Werror=return-type -Werror=implicit-function-declaration")

add_executable(minitar "minitar.c" "main.c")
