cmake_minimum_required(VERSION 3.10)
project(proj2)

set(CMAKE_CXX_STANDARD 11)
set(GCC_COVERAGE_LINK_FLAGS    "-lpcap")
set(CMAKE_MODULE_PATH "/home/schlupov/school/ctvrty_semestr/IPK/proj2")

include(FindPCAP)
find_package(PCAP REQUIRED)

add_executable(proj2 ipk-scan.cpp argument_parser.cpp argument_parser.h udp.cpp udp.h tcp.cpp tcp.h)

target_link_libraries(proj2 ${PCAP_LIBRARY})