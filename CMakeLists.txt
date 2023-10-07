cmake_minimum_required(VERSION 3.27)

project(latex-fast-preview VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_library(base INTERFACE)
target_compile_options(base INTERFACE -Wall -Wextra -Wshadow)

add_executable(main src/main.cpp)
target_link_libraries(main PRIVATE base)

add_library(injected SHARED src/injected.cpp)
target_link_libraries(injected PRIVATE base)
