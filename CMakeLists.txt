cmake_minimum_required(VERSION 3.10)
project(PacketProbe CXX)

set(CMAKE_CXX_STANDARD 17)
include_directories(include)

add_executable(packet_sniffer packet_sniffer.cpp src/logger.cpp)

enable_testing()
add_executable(test_sniffer tests/test_sniffer.cpp)
find_package(GTest REQUIRED)
target_link_libraries(test_sniffer GTest::GTest GTest::Main pthread)
add_test(NAME SnifferTest COMMAND test_sniffer)