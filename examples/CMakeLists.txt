# Self-contained example programs. Each links the public library target
# (axiam::axiam_cpp) exactly as a downstream consumer would.
add_executable(axiam_example_login_mfa login_mfa.cpp)
target_link_libraries(axiam_example_login_mfa PRIVATE axiam::axiam_cpp)

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
