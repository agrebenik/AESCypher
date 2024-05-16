cmake_minimum_required(VERSION 3.23)
project(AESCypher)

set(CMAKE_CXX_STANDARD 23)

add_executable(AESCypher main.cpp Repl.cpp Repl.h AESCypher.cpp AESCypher.h Util.cpp Util.h)
