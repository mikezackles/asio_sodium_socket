cmake_minimum_required(VERSION 3.5 FATAL_ERROR)
project(asio_sodium_socket VERSION 0.1 LANGUAGES CXX)

include("${CMAKE_SOURCE_DIR}/cmake/target_all_warnings_except.cmake")
include("${CMAKE_SOURCE_DIR}/cmake/target_use_modern_cxx.cmake")

find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_search_module(LIBSODIUM REQUIRED libsodium)

set(ASIO_LOCATION "${CMAKE_SOURCE_DIR}/bundle/core/asio" CACHE PATH
  "the location of the asio library (coroutines required)")
set(GSL_LOCATION "${CMAKE_SOURCE_DIR}/bundle/core/gsl" CACHE PATH
  "the location of Microsoft's Guideline Support Library")
set(OPTIONAL_LOCATION "${CMAKE_SOURCE_DIR}/bundle/core/optional" CACHE PATH
  "the location of std::experimental::optional")

set(CMAKE_CXX_EXTENSIONS OFF) # Turn off gnu extensions

add_library(asio_sodium_socket INTERFACE)
target_compile_definitions(asio_sodium_socket
  INTERFACE
  ASIO_STANDALONE)
target_include_directories(asio_sodium_socket
  INTERFACE
  "include"
  "${ASIO_LOCATION}/asio/include"
  "${GSL_LOCATION}/include"
  "${OPTIONAL_LOCATION}")
target_link_libraries(asio_sodium_socket INTERFACE sodium ${CMAKE_THREAD_LIBS_INIT})
# TODO - whitelist features here if necessary
target_use_modern_cxx(asio_sodium_socket TYPE INTERFACE)

add_executable(tests
  "test/main.cpp"
  "test/handshake_hello.cpp"
  "test/handshake_response.cpp"
  "test/message_header.cpp"
  "test/handshake.cpp"
  "test/read_write.cpp"
  "test/socket.cpp")

target_include_directories(tests
  PRIVATE
  "${CMAKE_SOURCE_DIR}/bundle/test/catch/include")

target_all_warnings_except(tests
  CLANG
  -Wno-c++98-compat
  -Wno-c++98-compat-pedantic
  -Wno-exit-time-destructors # catch
  -Wno-weak-vtables # AFAIK there's not much to do about this one while remaining header-only
  -Wno-implicit-fallthrough # asio coroutines
  -Wno-padded
  GCC
  -Wno-unknown-pragmas
  )

target_link_libraries(tests asio_sodium_socket)

enable_testing()
add_test(tests tests)
