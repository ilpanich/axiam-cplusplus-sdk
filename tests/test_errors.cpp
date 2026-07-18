#include <string>

#include "assert.hpp"
#include "axiam/errors.hpp"

using namespace axiam;

AXIAM_TEST("error hierarchy derives from AxiamError / std::runtime_error") {
    AuthError ae("bad creds");
    AuthzError ze("denied");
    NetworkError ne("timeout");
    AXIAM_CHECK(dynamic_cast<AxiamError*>(&ae) != nullptr);
    AXIAM_CHECK(dynamic_cast<AxiamError*>(&ze) != nullptr);
    AXIAM_CHECK(dynamic_cast<AxiamError*>(&ne) != nullptr);
    AXIAM_CHECK(dynamic_cast<std::runtime_error*>(&ae) != nullptr);
}

AXIAM_TEST("AuthzError carries optional action + resource_id") {
    AuthzError ze("denied", std::string("read"), std::string("res-1"));
    AXIAM_REQUIRE(ze.action().has_value());
    AXIAM_CHECK(*ze.action() == "read");
    AXIAM_REQUIRE(ze.resource_id().has_value());
    AXIAM_CHECK(*ze.resource_id() == "res-1");
}

AXIAM_TEST("NetworkError carries underlying cause") {
    NetworkError ne("transport failure: Could not resolve host", "Could not resolve host");
    AXIAM_CHECK(ne.cause() == "Could not resolve host");
}

AXIAM_TEST("errors can be caught as base AxiamError") {
    bool caught = false;
    try {
        throw AuthError("x");
    } catch (const AxiamError& e) {
        caught = true;
        AXIAM_CHECK(std::string(e.what()) == "x");
    }
    AXIAM_CHECK(caught);
}
