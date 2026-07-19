# Self-contained example programs. Each links the public library target
# (axiam::axiam_cpp) exactly as a downstream consumer would.
add_executable(axiam_example_login_mfa login_mfa.cpp)
target_link_libraries(axiam_example_login_mfa PRIVATE axiam::axiam_cpp)

add_executable(axiam_example_rest_authz rest_authz.cpp)
target_link_libraries(axiam_example_rest_authz PRIVATE axiam::axiam_cpp)
