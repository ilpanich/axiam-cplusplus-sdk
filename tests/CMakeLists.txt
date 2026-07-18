# Unit + integration test executable. Uses the vendored self-contained harness
# (third_party/testing/assert.hpp) so it builds fully offline.
add_executable(axiam_cpp_tests
  main.cpp
  test_sensitive.cpp
  test_errors.cpp
  test_builder.cpp
  test_client.cpp
  test_single_flight.cpp
  test_guard.cpp
  test_jwks.cpp
  test_integration_curl.cpp
)

target_include_directories(axiam_cpp_tests PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_SOURCE_DIR}/third_party/testing
  ${CMAKE_SOURCE_DIR}/third_party/nlohmann
)

target_link_libraries(axiam_cpp_tests PRIVATE
  axiam_cpp
  OpenSSL::SSL
  OpenSSL::Crypto
)

find_package(Threads REQUIRED)
target_link_libraries(axiam_cpp_tests PRIVATE Threads::Threads)

if(AXIAM_ENABLE_COVERAGE AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(axiam_cpp_tests PRIVATE --coverage -O0 -g)
  target_link_options(axiam_cpp_tests PRIVATE --coverage)
endif()

add_test(NAME axiam_cpp_tests COMMAND axiam_cpp_tests)
set_tests_properties(axiam_cpp_tests PROPERTIES TIMEOUT 120)
