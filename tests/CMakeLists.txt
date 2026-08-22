# A REAL shared library exporting the twelve libaxiam_opaque_ffi symbols, so
# src/opaque.cpp's dlopen/dlsym resolution is exercised against a genuine
# dynamic object rather than jumped over. It performs no cryptography — its
# whole job is to be a library that loads. MODULE rather than SHARED because
# nothing links it; it is only ever dlopen()ed.
add_library(axiam_opaque_stub MODULE opaque_stub.cpp)
set_target_properties(axiam_opaque_stub PROPERTIES PREFIX "lib")

# The same source with one export renamed: a library that loads and is missing
# a symbol, which the loader must refuse rather than half-adopt.
add_library(axiam_opaque_stub_incomplete MODULE opaque_stub.cpp)
target_compile_definitions(axiam_opaque_stub_incomplete PRIVATE AXIAM_OPAQUE_STUB_INCOMPLETE)
set_target_properties(axiam_opaque_stub_incomplete PROPERTIES PREFIX "lib")

# Unit + integration test executable. Uses the vendored self-contained harness
# (third_party/testing/assert.hpp) so it builds fully offline.
add_executable(axiam_cpp_tests
  main.cpp
  test_sensitive.cpp
  test_errors.cpp
  test_rule9_binding.cpp
  test_builder.cpp
  test_client.cpp
  test_single_flight.cpp
  test_refresh_guard.cpp
  test_guard.cpp
  test_reason_code.cpp
  test_d5_conformance.cpp
  test_jwks.cpp
  test_authenticator.cpp
  test_webhook.cpp
  test_uma.cpp
  test_uma_challenge.cpp
  test_oidc.cpp
  test_oidc_grants.cpp
  test_oidc_errors.cpp
  # §23 OPAQUE: the binding — exchange lifetime, key-stretching selection,
  # error taxonomy — driven against a fake Native that counts every handle the
  # SDK is given, plus the REAL dlopen loader against a stub shared library.
  test_opaque_binding.cpp
  # §23 OPAQUE: the two HTTP calls around it — what goes on the wire, what does
  # NOT, and which failures may fall back to login().
  test_opaque_login.cpp
  # Contract 1.28: §24 WebAuthn, §25 account lifecycle, §26 PAR. All three are
  # wire-shape suites — what §24.0 is about is that the server's options and the
  # authenticator's response cross this SDK unchanged, and the only way to
  # assert that is to look at the bytes that went out.
  test_webauthn.cpp
  test_account.cpp
  test_oidc_par.cpp
  test_integration_curl.cpp
  test_transport_concurrency.cpp
  test_transport_reuse.cpp
)

target_include_directories(axiam_cpp_tests PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  # src/ is on the path so the internal (non-installed) §9 refresh guard header
  # can be unit-tested directly; see tests/test_refresh_guard.cpp.
  ${CMAKE_SOURCE_DIR}/src
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

# The stub paths reach the suite as compile definitions rather than argv, so it
# stays runnable by `ctest` with no arguments.
add_dependencies(axiam_cpp_tests axiam_opaque_stub axiam_opaque_stub_incomplete)
target_compile_definitions(axiam_cpp_tests PRIVATE
  AXIAM_OPAQUE_STUB_PATH="$<TARGET_FILE:axiam_opaque_stub>"
  AXIAM_OPAQUE_STUB_INCOMPLETE_PATH="$<TARGET_FILE:axiam_opaque_stub_incomplete>")

add_test(NAME axiam_cpp_tests COMMAND axiam_cpp_tests)
set_tests_properties(axiam_cpp_tests PROPERTIES TIMEOUT 120)
