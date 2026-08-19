# Self-contained example programs. Each links the public library target
# (axiam::axiam_cpp) exactly as a downstream consumer would.
add_executable(axiam_example_login_mfa login_mfa.cpp)
target_link_libraries(axiam_example_login_mfa PRIVATE axiam::axiam_cpp)

# CONTRACT.md §23: the SRP-6a exchange, the two ways it can be unavailable, and
# the verifier the server cannot compute for itself.
add_executable(axiam_example_srp_login srp_login.cpp)
target_link_libraries(axiam_example_srp_login PRIVATE axiam::axiam_cpp)

add_executable(axiam_example_rest_authz rest_authz.cpp)
target_link_libraries(axiam_example_rest_authz PRIVATE axiam::axiam_cpp)

add_executable(axiam_example_telemetry_hook telemetry_hook.cpp)
target_link_libraries(axiam_example_telemetry_hook PRIVATE axiam::axiam_cpp)

# The §20.3 pair: a resource server that emits the WWW-Authenticate: UMA
# challenge, and a client that consumes it.
add_executable(axiam_example_uma_resource_server uma_resource_server.cpp)
target_link_libraries(axiam_example_uma_resource_server PRIVATE axiam::axiam_cpp)

add_executable(axiam_example_uma_client uma_client.cpp)
target_link_libraries(axiam_example_uma_client PRIVATE axiam::axiam_cpp)

# The contract-1.11 port (§12.6): the OIDC relying party, the device grant, and
# token exchange.
add_executable(axiam_example_oidc_login oidc_login.cpp)
target_link_libraries(axiam_example_oidc_login PRIVATE axiam::axiam_cpp)

add_executable(axiam_example_device_login device_login.cpp)
target_link_libraries(axiam_example_device_login PRIVATE axiam::axiam_cpp)

add_executable(axiam_example_token_exchange token_exchange.cpp)
target_link_libraries(axiam_example_token_exchange PRIVATE axiam::axiam_cpp)

# CONTRACT.md §22.11 — a NON-NORMATIVE reactor sample.
#
# This SDK ships no reactor runtime and this target adds none: nothing here is
# installed and no public header gained a reactor API. §22.11 plans exactly this
# sample for the C++ SDK, and is explicit about its standing — "It is an example,
# not a contract surface: this section governs, and the sample conforms to it or
# is wrong." So that is checkable rather than aspirational, the program runs the
# committed §22.13 reference vectors and exits non-zero if a byte differs.
#
# Two deliberate deviations from the "links only the public target" pattern the
# examples above follow, both of which mirror what a real integrator does:
#
#   * it reaches for the vendored nlohmann header, because a hand-rolled reactor
#     needs a JSON library and this repository already carries one, so the sample
#     builds offline;
#   * it carries no AMQP client. §22.11 defers the runtime precisely because
#     there is no vendorable AMQP client for this target, so the transport is an
#     abstract seam in the source and the integrator binds their own.
add_executable(axiam_example_reactor reactor/reactor.cpp)
target_link_libraries(axiam_example_reactor PRIVATE axiam::axiam_cpp)
target_include_directories(axiam_example_reactor PRIVATE ${CMAKE_SOURCE_DIR}/third_party)
target_compile_definitions(axiam_example_reactor PRIVATE
  AXIAM_REACTOR_VECTORS="${CMAKE_CURRENT_SOURCE_DIR}/reactor/reactor_v2_reference_vectors.json")
