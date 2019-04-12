cmake_minimum_required(VERSION 3.10)
project(proj2)

set(CMAKE_CXX_STANDARD 11)

add_executable(proj2 ipk-scan.cpp argument_parser.cpp argument_parser.h)