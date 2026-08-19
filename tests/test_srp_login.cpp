// Client::login_srp end to end against a fake transport that really speaks
// SRP-6a (src/client.cpp, CONTRACT.md §23).
//
// test_srp_vectors.cpp proves the arithmetic reproduces the cross-language
// vectors. It says nothing about the two HTTP calls around it: which identity
// is bound into x, what happens when the server names a group other than the
// one A was opened in, whether a tenant with SRP disabled stays
// distinguishable from a wrong password, and — the one that matters most —
// whether a server that cannot prove it holds the verifier is refused rather
// than quietly accepted.
//
// So the fake here is not a canned response: it holds a verifier, picks its
// own b, and computes B, M1 and M2 from whatever A the client sends. A client
// that got u, the padding or the exponent wrong fails against it, which a
// fixture-replaying fake could never detect.

#include <memory>
#include <string>
#include <vector>

#include <openssl/bn.h>
#include <openssl/crypto.h>

#include <json.hpp>

#include "assert.hpp"
#include "axiam/client.hpp"
#include "axiam/errors.hpp"
#include "axiam/srp.hpp"
#include "fake_transport.hpp"

using namespace axiam;
using axtest::FakeState;
using axtest::json_response;
using json = nlohmann::json;

namespace {

// PBKDF2 at a low cost: the derivation under test is the transport's, not the
// KDF's, and Argon2id at production memory would dominate the suite.
SrpKdfParams test_kdf() {
    SrpKdfParams p;
    p.kdf = SrpKdfParams::kPbkdf2Sha256;
    p.iterations = 1000;
    return p;
}

struct BnDeleter {
    void operator()(BIGNUM* p) const noexcept { BN_clear_free(p); }
};
struct BnCtxDeleter {
    void operator()(BN_CTX* p) const noexcept { BN_CTX_free(p); }
};
using BnPtr = std::unique_ptr<BIGNUM, BnDeleter>;
using BnCtxPtr = std::unique_ptr<BN_CTX, BnCtxDeleter>;

BnPtr bn_from_hex(const std::string& hex) {
    BIGNUM* raw = nullptr;
    BN_hex2bn(&raw, hex.c_str());
    return BnPtr(raw);
}

/// PAD(x): raw big-endian bytes, left-padded to the group width. §23.3 rule 8
/// applies to the fake as much as to the SDK — one that skipped the padding
/// would agree with a client that skipped it.
std::string bn_to_padded_bytes(const BIGNUM* value, int byte_length) {
    std::vector<unsigned char> buf(static_cast<std::size_t>(byte_length), 0);
    BN_bn2binpad(value, buf.data(), byte_length);
    return std::string(reinterpret_cast<const char*>(buf.data()), buf.size());
}

std::string bn_to_padded_hex(const BIGNUM* value, int byte_length) {
    return srp::to_hex(bn_to_padded_bytes(value, byte_length));
}

/// The server half of one exchange, for one account.
class SrpServer {
  public:
    SrpServer(const std::string& group_wire, std::string identity, const std::string& password)
        : identity_(std::move(identity)) {
        auto group = SrpGroup::from_wire(group_wire);
        AXIAM_REQUIRE(group.has_value());
        group_ = *group;

        n_ = bn_from_hex(group_.modulus_hex);
        g_ = BnPtr(BN_new());
        BN_set_word(g_.get(), group_.generator);
        k_ = bn_from_hex(srp::multiplier_hex(group_));

        // §23.3 rule 11: 32 fresh bytes, here too, so the fixture cannot
        // accidentally depend on one particular salt.
        salt_ = srp::generate_salt();
        salt_hex_ = srp::to_hex(salt_);

        std::string x = srp::derive_x(identity_, password, salt_, test_kdf());
        BnPtr x_int = bn_from_hex(srp::to_hex(x));
        OPENSSL_cleanse(&x[0], x.size());

        BnCtxPtr ctx(BN_CTX_new());
        BN_mod(x_int.get(), x_int.get(), n_.get(), ctx.get());
        v_ = BnPtr(BN_new());
        BN_mod_exp(v_.get(), g_.get(), x_int.get(), n_.get(), ctx.get());

        // B = k*v + g^b mod N.
        b_priv_ = BnPtr(BN_new());
        BN_rand(b_priv_.get(), 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
        BnPtr gb(BN_new()), kv(BN_new());
        BN_mod_exp(gb.get(), g_.get(), b_priv_.get(), n_.get(), ctx.get());
        BN_mod_mul(kv.get(), k_.get(), v_.get(), n_.get(), ctx.get());
        b_pub_ = BnPtr(BN_new());
        BN_mod_add(b_pub_.get(), kv.get(), gb.get(), n_.get(), ctx.get());
    }

    const SrpGroup& group() const { return group_; }

    /// The challenge body, optionally naming a different group so the client
    /// has to restart the exchange.
    std::string challenge_body(const std::string& group_override = "") const {
        json body;
        body["srp_session"] = "opaque-session-token";
        body["identity"] = identity_;
        body["salt"] = salt_hex_;
        body["group"] = group_override.empty() ? group_.wire_name : group_override;
        body["kdf"] = test_kdf().kdf;
        body["iterations"] = test_kdf().iterations;
        body["b_pub"] = bn_to_padded_hex(b_pub_.get(), group_.byte_length);
        return body.dump();
    }

    /// (M1, M2) for the A the client actually sent.
    ///
    /// `srp::hash_hex` hashes RAW bytes and returns hex, so every input here is
    /// a byte string and every digest is converted back before it is fed into
    /// the next one.
    SrpProofs proofs_for(const std::string& a_pub_hex) const {
        BnPtr a_pub = bn_from_hex(a_pub_hex);
        BnCtxPtr ctx(BN_CTX_new());

        const std::string pad_a = bn_to_padded_bytes(a_pub.get(), group_.byte_length);
        const std::string pad_b = bn_to_padded_bytes(b_pub_.get(), group_.byte_length);
        BnPtr u = bn_from_hex(srp::hash_hex({pad_a, pad_b}));

        // S = (A * v^u)^b mod N — the server's route to the same secret.
        BnPtr vu(BN_new()), base(BN_new()), s(BN_new());
        BN_mod_exp(vu.get(), v_.get(), u.get(), n_.get(), ctx.get());
        BN_mod_mul(base.get(), a_pub.get(), vu.get(), n_.get(), ctx.get());
        BN_mod_exp(s.get(), base.get(), b_priv_.get(), n_.get(), ctx.get());

        const std::string session_key = srp::from_hex(
            srp::hash_hex({bn_to_padded_bytes(s.get(), group_.byte_length)}), "session_key");

        const std::string h_n = srp::from_hex(
            srp::hash_hex({bn_to_padded_bytes(n_.get(), group_.byte_length)}), "h_n");
        const std::string h_g = srp::from_hex(
            srp::hash_hex({bn_to_padded_bytes(g_.get(), group_.byte_length)}), "h_g");
        std::string xored(h_n.size(), '\0');
        for (std::size_t i = 0; i < h_n.size(); ++i) {
            xored[i] = static_cast<char>(h_n[i] ^ h_g[i]);
        }
        const std::string h_i = srp::from_hex(srp::hash_hex({identity_}), "h_i");

        SrpProofs proofs;
        proofs.client_proof =
            srp::hash_hex({xored, h_i, salt_, pad_a, pad_b, session_key});
        proofs.expected_server_proof = srp::hash_hex(
            {pad_a, srp::from_hex(proofs.client_proof, "m1"), session_key});
        return proofs;
    }

  private:
    SrpGroup group_;
    std::string identity_;
    std::string salt_;
    std::string salt_hex_;
    BnPtr n_, g_, k_, v_, b_priv_, b_pub_;
};

constexpr const char* kChallengePath = "/api/v1/auth/srp/challenge";
constexpr const char* kVerifyPath = "/api/v1/auth/srp/verify";

bool is_challenge(const HttpRequest& req) {
    return req.url.find(kChallengePath) != std::string::npos;
}
bool is_verify(const HttpRequest& req) {
    return req.url.find(kVerifyPath) != std::string::npos;
}

std::string client_public_of(const HttpRequest& req) {
    auto body = json::parse(req.body, nullptr, false);
    AXIAM_REQUIRE(!body.is_discarded());
    return body.value("client_public", std::string{});
}

Client make_client(std::shared_ptr<FakeState> st) {
    return Client::builder()
        .base_url("https://api.example.test")
        .tenant_slug("acme")
        .org_slug("globex")
        .transport(axtest::make_fake(st))
        .build();
}

/// A router that answers a challenge with `body` verbatim and fails the test if
/// a proof is ever sent — every refusal case must refuse before that point.
std::shared_ptr<FakeState> refusing_state(std::string challenge, long status = 200) {
    auto st = std::make_shared<FakeState>();
    st->router = [challenge, status](const HttpRequest& req, FakeState&) {
        AXIAM_CHECK_FALSE(is_verify(req));
        return json_response(status, challenge);
    };
    return st;
}

}  // namespace

AXIAM_TEST("§23: a full exchange authenticates both sides and opens a session") {
    auto server = std::make_shared<SrpServer>(SrpGroup::kDefaultWireName, "alice",
                                              "correct horse battery staple");
    auto st = std::make_shared<FakeState>();
    // A is fresh per exchange, so the router learns it from the challenge and
    // answers the verify with the M2 that follows from it.
    std::string a_pub;
    st->router = [server, &a_pub](const HttpRequest& req, FakeState&) {
        if (is_challenge(req)) {
            // §23.3 rule 12: the password has no business on this request.
            AXIAM_CHECK(req.body.find("password") == std::string::npos);
            AXIAM_CHECK(req.body.find("correct horse") == std::string::npos);
            a_pub = client_public_of(req);
            return json_response(200, server->challenge_body());
        }
        auto proofs = server->proofs_for(a_pub);
        auto body = json::parse(req.body, nullptr, false);
        AXIAM_REQUIRE(!body.is_discarded());
        // The fake authenticates the client for real: a client that computed u,
        // the padding or the identity differently never gets past here.
        AXIAM_CHECK(body.value("client_proof", std::string{}) == proofs.client_proof);
        AXIAM_CHECK(body.value("srp_session", std::string{}) == "opaque-session-token");
        json out;
        out["session_id"] = "sess-srp-1";
        out["expires_in"] = 900;
        out["server_proof"] = proofs.expected_server_proof;
        out["user"] = {{"id", "u-1"}, {"username", "alice"}, {"email", "a@x.io"},
                       {"tenant_id", "t-1"}};
        return json_response(200, out.dump());
    };

    Client c = make_client(st);
    // Signed in by EMAIL while the verifier is bound to the USERNAME: §23.3
    // rule 2 says x uses the identity the SERVER named, and this only passes if
    // the SDK honours it.
    LoginResult res = c.login_srp("alice@example.com", "correct horse battery staple");

    AXIAM_CHECK_FALSE(res.mfa_required);
    AXIAM_CHECK(res.session_id == "sess-srp-1");
    AXIAM_CHECK(res.expires_in == 900);
    AXIAM_CHECK(c.has_session());
    AXIAM_CHECK(st->count_path(kChallengePath) == 1);
    AXIAM_CHECK(st->count_path(kVerifyPath) == 1);
}

AXIAM_TEST("§23: a narrower group restarts the exchange with a fresh A") {
    auto server = std::make_shared<SrpServer>("rfc5054_2048", "alice", "a-good-password");
    auto st = std::make_shared<FakeState>();
    std::string a_pub;
    int challenges = 0;
    st->router = [server, &a_pub, &challenges](const HttpRequest& req, FakeState&) {
        if (is_challenge(req)) {
            a_pub = client_public_of(req);
            ++challenges;
            return json_response(200, server->challenge_body());
        }
        auto proofs = server->proofs_for(a_pub);
        json out;
        out["session_id"] = "sess-srp-2";
        out["expires_in"] = 900;
        out["server_proof"] = proofs.expected_server_proof;
        return json_response(200, out.dump());
    };

    Client c = make_client(st);
    LoginResult res = c.login_srp("alice", "a-good-password");
    AXIAM_CHECK(res.session_id == "sess-srp-2");
    // The opening guess is the 4096 group, so a 2048 tenant costs one restart.
    AXIAM_CHECK(challenges == 2);
}

AXIAM_TEST("§23: MFA-required returns the same branch as password login") {
    auto server = std::make_shared<SrpServer>(SrpGroup::kDefaultWireName, "alice", "pw-for-mfa");
    auto st = std::make_shared<FakeState>();
    std::string a_pub;
    st->router = [server, &a_pub](const HttpRequest& req, FakeState&) {
        if (is_challenge(req)) {
            a_pub = client_public_of(req);
            return json_response(200, server->challenge_body());
        }
        auto proofs = server->proofs_for(a_pub);
        json out;
        out["mfa_required"] = true;
        out["challenge_token"] = "chal-srp";
        out["available_methods"] = json::array({"totp"});
        out["server_proof"] = proofs.expected_server_proof;
        return json_response(202, out.dump());
    };

    Client c = make_client(st);
    LoginResult res = c.login_srp("alice", "pw-for-mfa");
    AXIAM_CHECK(res.mfa_required);
    AXIAM_CHECK(detail::reveal(res.challenge_token) == "chal-srp");
    AXIAM_REQUIRE(res.available_methods.size() == 1);
    AXIAM_CHECK(res.available_methods[0] == "totp");
    AXIAM_CHECK_FALSE(c.has_session());
}

AXIAM_TEST("§23.3 rule 6: a server whose M2 does not verify gets no session") {
    auto server = std::make_shared<SrpServer>(SrpGroup::kDefaultWireName, "alice",
                                              "a-perfectly-good-password");
    auto st = std::make_shared<FakeState>();
    std::string a_pub;
    st->router = [server, &a_pub](const HttpRequest& req, FakeState&) {
        if (is_challenge(req)) {
            a_pub = client_public_of(req);
            return json_response(200, server->challenge_body());
        }
        auto proofs = server->proofs_for(a_pub);
        // Flip one hex digit: well-formed, right length, still wrong.
        std::string wrong = proofs.expected_server_proof;
        wrong[0] = (wrong[0] == '0') ? '1' : '0';
        json out;
        out["session_id"] = "sess-should-not-be-adopted";
        out["expires_in"] = 900;
        out["server_proof"] = wrong;
        return json_response(200, out.dump());
    };

    Client c = make_client(st);
    bool threw = false;
    try {
        c.login_srp("alice", "a-perfectly-good-password");
    } catch (const AuthError& e) {
        threw = true;
        AXIAM_CHECK(std::string(e.what()).find("failed to prove") != std::string::npos);
    }
    AXIAM_CHECK(threw);
    // An endpoint that cannot prove it holds the verifier is not the server it
    // claims to be, so there is no session to hand back.
    AXIAM_CHECK_FALSE(c.has_session());
}

AXIAM_TEST("§23.3 rule 6: a server that returns no M2 at all is refused") {
    auto server = std::make_shared<SrpServer>(SrpGroup::kDefaultWireName, "alice", "pw-no-proof");
    auto st = std::make_shared<FakeState>();
    st->router = [server](const HttpRequest& req, FakeState&) {
        if (is_challenge(req)) return json_response(200, server->challenge_body());
        return json_response(200, R"({"session_id":"s","expires_in":900})");
    };

    Client c = make_client(st);
    bool threw = false;
    try {
        c.login_srp("alice", "pw-no-proof");
    } catch (const AuthError&) {
        threw = true;
    }
    AXIAM_CHECK(threw);
    AXIAM_CHECK_FALSE(c.has_session());
}

AXIAM_TEST("§23.5: srp_mode disabled is a configuration fault, not a bad password") {
    // The distinction is the whole point: a caller that saw AuthError here
    // would send a user off to reset a password that works perfectly.
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest& req, FakeState&) {
        AXIAM_CHECK_FALSE(is_verify(req));
        return json_response(404, R"({"message":"not found"})");
    };

    Client c = make_client(st);
    bool threw = false;
    try {
        c.login_srp("alice", "irrelevant");
    } catch (const NetworkError& e) {
        threw = true;
        AXIAM_CHECK(std::string(e.what()).find("srp_mode") != std::string::npos);
        AXIAM_CHECK(std::string(e.what()).find("login()") != std::string::npos);
    }
    AXIAM_CHECK(threw);
}

AXIAM_TEST("§23.4: a group this SDK does not implement is refused, not guessed") {
    auto st = refusing_state(
        R"({"srp_session":"s","identity":"alice","salt":"00112233","group":"rfc5054_1024",)"
        R"("kdf":"pbkdf2_sha256","iterations":1000,"b_pub":"02"})");

    Client c = make_client(st);
    bool threw = false;
    try {
        c.login_srp("alice", "irrelevant");
    } catch (const NetworkError& e) {
        threw = true;
        AXIAM_CHECK(std::string(e.what()).find("rfc5054_1024") != std::string::npos);
    }
    AXIAM_CHECK(threw);
}

AXIAM_TEST("§23.3 rule 4: a KDF this SDK cannot perform names itself") {
    auto st = refusing_state(
        R"({"srp_session":"s","identity":"alice","salt":"00112233","group":"rfc5054_4096",)"
        R"("kdf":"scrypt","iterations":1,"b_pub":"02"})");

    Client c = make_client(st);
    bool threw = false;
    try {
        c.login_srp("alice", "irrelevant");
    } catch (const NetworkError& e) {
        threw = true;
        AXIAM_CHECK(std::string(e.what()).find("scrypt") != std::string::npos);
    }
    AXIAM_CHECK(threw);
}

AXIAM_TEST("§23: a salt that is not hex is refused before the KDF runs") {
    auto st = refusing_state(
        R"({"srp_session":"s","identity":"alice","salt":"not-hex","group":"rfc5054_4096",)"
        R"("kdf":"pbkdf2_sha256","iterations":1000,"b_pub":"02"})");

    Client c = make_client(st);
    bool threw = false;
    try {
        c.login_srp("alice", "irrelevant");
    } catch (const NetworkError&) {
        threw = true;
    }
    AXIAM_CHECK(threw);
}

AXIAM_TEST("§23.3 rule 5: B congruent to zero is refused without a second round trip") {
    // The classic SRP break: B ≡ 0 (mod N) makes S predictable. refusing_state
    // asserts on its own that no proof was sent.
    auto st = refusing_state(
        R"({"srp_session":"s","identity":"alice","salt":"00112233","group":"rfc5054_4096",)"
        R"("kdf":"pbkdf2_sha256","iterations":1000,"b_pub":"00"})");

    Client c = make_client(st);
    bool threw = false;
    try {
        c.login_srp("alice", "irrelevant");
    } catch (const std::exception&) {
        threw = true;
    }
    AXIAM_CHECK(threw);
}

AXIAM_TEST("§23: a server public value that is not hex is refused") {
    // The salt and B are both server-supplied hex, and both have to be
    // rejected as data rather than reaching the arithmetic.
    auto st = refusing_state(
        R"({"srp_session":"s","identity":"alice","salt":"00112233","group":"rfc5054_4096",)"
        R"("kdf":"pbkdf2_sha256","iterations":1000,"b_pub":"zzz-not-hex"})");

    Client c = make_client(st);
    bool threw = false;
    try {
        c.login_srp("alice", "irrelevant");
    } catch (const NetworkError& e) {
        threw = true;
        AXIAM_CHECK(std::string(e.what()).find("b_pub") != std::string::npos);
    }
    AXIAM_CHECK(threw);
}

AXIAM_TEST("§23.3 rule 7: moving a session carries A and leaves no ephemeral behind") {
    // The session owns `a`, which is why it is move-only. The move has to carry
    // A intact — a caller that stored a session in a container would otherwise
    // send a proof computed against an A the server never saw.
    auto group = SrpGroup::from_wire(SrpGroup::kDefaultWireName);
    AXIAM_REQUIRE(group.has_value());

    srp::ClientSession first = srp::ClientSession::begin(*group);
    const std::string a_pub = first.client_public();
    AXIAM_CHECK(a_pub.size() == static_cast<std::size_t>(group->byte_length) * 2);

    srp::ClientSession moved = std::move(first);
    AXIAM_CHECK(moved.client_public() == a_pub);

    srp::ClientSession assigned = srp::ClientSession::begin(*group);
    // Two exchanges never share an ephemeral (§23.3 rule 7).
    AXIAM_CHECK(assigned.client_public() != a_pub);
    assigned = std::move(moved);
    AXIAM_CHECK(assigned.client_public() == a_pub);
}

AXIAM_TEST("§23: a challenge that is not JSON is refused") {
    auto st = refusing_state("not json at all");

    Client c = make_client(st);
    bool threw = false;
    try {
        c.login_srp("alice", "irrelevant");
    } catch (const NetworkError& e) {
        threw = true;
        AXIAM_CHECK(std::string(e.what()).find("not JSON") != std::string::npos);
    }
    AXIAM_CHECK(threw);
}

AXIAM_TEST("§23: a server error on the challenge is reported as itself") {
    auto st = refusing_state(R"({"message":"the identity service is restarting"})", 503);

    Client c = make_client(st);
    bool threw = false;
    try {
        c.login_srp("alice", "irrelevant");
    } catch (const std::exception&) {
        threw = true;
    }
    AXIAM_CHECK(threw);
}

AXIAM_TEST("§23: a rejected proof reaches the caller as an auth failure") {
    auto server = std::make_shared<SrpServer>(SrpGroup::kDefaultWireName, "alice",
                                              "the-real-password");
    auto st = std::make_shared<FakeState>();
    st->router = [server](const HttpRequest& req, FakeState&) {
        if (is_challenge(req)) return json_response(200, server->challenge_body());
        // What a wrong password produces: the exchange is well-formed, M1
        // simply does not match.
        return json_response(401, R"({"error":"invalid_credentials","message":"bad"})");
    };

    Client c = make_client(st);
    bool threw = false;
    try {
        c.login_srp("alice", "not-the-real-password");
    } catch (const AuthError&) {
        threw = true;
    }
    AXIAM_CHECK(threw);
    AXIAM_CHECK_FALSE(c.has_session());
}

AXIAM_TEST("§23.5: enrolment produces a verifier the server can reproduce") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) { return json_response(200, "{}"); };
    Client c = make_client(st);

    SrpEnrollment e = c.srp_enrollment("alice", "a-new-password", std::string("rfc5054_2048"),
                                       test_kdf());
    AXIAM_CHECK(e.group == "rfc5054_2048");
    AXIAM_CHECK(e.kdf == SrpKdfParams::kPbkdf2Sha256);
    AXIAM_CHECK(e.iterations == 1000);
    AXIAM_CHECK(e.salt.size() == 64);      // 32 bytes, hex
    AXIAM_CHECK(e.verifier.size() == 512); // 256 bytes, padded

    // Recompute it the way the server would, from the salt it was given.
    auto group = SrpGroup::from_wire("rfc5054_2048");
    AXIAM_REQUIRE(group.has_value());
    std::string x = srp::derive_x("alice", "a-new-password", srp::from_hex(e.salt, "salt"),
                                  test_kdf());
    AXIAM_CHECK(srp::compute_verifier(*group, x) == e.verifier);
    OPENSSL_cleanse(&x[0], x.size());

    // Two enrolments of the same password must differ: the salt is fresh per
    // §23.3 rule 11, and a repeated verifier would leak that two accounts share
    // a password.
    SrpEnrollment again = c.srp_enrollment("alice", "a-new-password",
                                           std::string("rfc5054_2048"), test_kdf());
    AXIAM_CHECK(again.salt != e.salt);
    AXIAM_CHECK(again.verifier != e.verifier);
}

AXIAM_TEST("§23.5: enrolment defaults to argon2id at AXIAM's costs") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) { return json_response(200, "{}"); };
    Client c = make_client(st);

    // §23.8: Argon2id arrives as an EVP_KDF only in OpenSSL 3.2. Against an
    // older libcrypto the SDK REFUSES rather than substituting PBKDF2, which
    // would produce a verifier no later login could satisfy. Both outcomes are
    // conformant; which one this build takes depends on its libcrypto.
    if (!srp::argon2_available()) {
        bool threw = false;
        try {
            c.srp_enrollment("alice", "a-new-password");
        } catch (const NetworkError& e) {
            threw = true;
            AXIAM_CHECK(std::string(e.what()).find("argon2id") != std::string::npos);
        }
        AXIAM_CHECK(threw);
        return;
    }

    // Nothing named: the widest group and the memory-hard KDF, rather than
    // something weaker by omission.
    SrpEnrollment e = c.srp_enrollment("alice", "a-new-password");
    AXIAM_CHECK(e.group == SrpGroup::kDefaultWireName);
    AXIAM_CHECK(e.kdf == SrpKdfParams::kArgon2id);
    AXIAM_CHECK(e.iterations == 2);
    AXIAM_CHECK(e.memory_kib == 19456);
    AXIAM_CHECK(e.parallelism == 1);
    AXIAM_CHECK(e.verifier.size() == 1024);  // 512 bytes for the 4096-bit group
}

AXIAM_TEST("§23.4: enrolment refuses a group this SDK does not implement") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) { return json_response(200, "{}"); };
    Client c = make_client(st);

    bool threw = false;
    try {
        c.srp_enrollment("alice", "pw", std::string("rfc5054_1024"), test_kdf());
    } catch (const NetworkError& e) {
        threw = true;
        AXIAM_CHECK(std::string(e.what()).find("rfc5054_1024") != std::string::npos);
    }
    AXIAM_CHECK(threw);
}

AXIAM_TEST("§23.1: this build can perform SRP") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) { return json_response(200, "{}"); };
    Client c = make_client(st);
    AXIAM_CHECK(c.srp_available());
}
