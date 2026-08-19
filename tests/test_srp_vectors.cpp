/// \file
/// CONTRACT.md §23.7 conformance for the SRP-6a client.
///
/// `srp-test-vectors.json` is generated from the AXIAM server implementation and
/// vendored into every SDK. Eleven independent SRP implementations do not
/// interoperate by accident; this is the file that says whether this one does.
///
/// §23.7 rule 1 requires every intermediate to be reproduced, not only the final
/// proof — an SDK that gets `u` wrong should find out at `u` rather than at
/// "login sometimes fails".
#include <openssl/bn.h>
#include <openssl/evp.h>

#include <cstdio>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <json.hpp>

#include "assert.hpp"
#include "axiam/errors.hpp"
#include "axiam/srp.hpp"

using axiam::NetworkError;
using axiam::SrpGroup;
using axiam::SrpKdfParams;
using axiam::SrpProofs;
using json = nlohmann::json;

namespace {

/// Walks up from the working directory to find the vendored fixture, so this
/// does not encode how deep in the build tree ctest happens to run it.
const json& vectors() {
    static const json loaded = [] {
        for (const char* prefix : {"", "../", "../../", "../../../", "../../../../"}) {
            std::ifstream in(std::string(prefix) + "srp-test-vectors.json");
            if (!in) continue;
            std::ostringstream buf;
            buf << in.rdbuf();
            json parsed = json::parse(buf.str(), nullptr, false);
            if (!parsed.is_discarded() && parsed.contains("vectors")) return parsed["vectors"];
        }
        return json::array();
    }();
    return loaded;
}

std::string vstr(const json& v, const char* name) {
    return (v.contains(name) && v[name].is_string()) ? v[name].get<std::string>() : std::string{};
}

struct BnDeleter {
    void operator()(BIGNUM* p) const noexcept { BN_free(p); }
};
struct BnCtxDeleter {
    void operator()(BN_CTX* p) const noexcept { BN_CTX_free(p); }
};
using BnPtr = std::unique_ptr<BIGNUM, BnDeleter>;
using BnCtxPtr = std::unique_ptr<BN_CTX, BnCtxDeleter>;

BnPtr bn(const std::string& hex) {
    BIGNUM* raw = nullptr;
    BN_hex2bn(&raw, hex.c_str());
    return BnPtr(raw);
}

std::string hex_of(const BIGNUM* v, int width) {
    std::string bytes(static_cast<std::size_t>(width), '\0');
    BN_bn2binpad(v, reinterpret_cast<unsigned char*>(&bytes[0]), width);
    return axiam::srp::to_hex(bytes);
}

}  // namespace

// ---------------------------------------------------------------------------
// §23.7 rule 4 — group constants
// ---------------------------------------------------------------------------

/// A transcription slip in a modulus is a silent, total break: client and server
/// would still agree with each other while the discrete-log hardness the
/// protocol rests on quietly vanished. A round-trip test cannot catch it,
/// because both sides share the same wrong constant.
AXIAM_TEST("§23.4 every group is a safe prime of the advertised width") {
    for (const SrpGroup& group : SrpGroup::all()) {
        BnCtxPtr ctx(BN_CTX_new());
        BnPtr n = bn(group.modulus_hex);
        AXIAM_REQUIRE(n != nullptr);
        AXIAM_CHECK(BN_num_bits(n.get()) == group.byte_length * 8);
        AXIAM_CHECK(BN_check_prime(n.get(), ctx.get(), nullptr) == 1);

        // A safe prime: N = 2q + 1 with q prime.
        BnPtr n_minus_1(BN_new()), q(BN_new()), g(BN_new()), got(BN_new());
        BN_sub(n_minus_1.get(), n.get(), BN_value_one());
        BN_rshift1(q.get(), n_minus_1.get());
        AXIAM_CHECK(BN_check_prime(q.get(), ctx.get(), nullptr) == 1);

        // g generates the order-q subgroup iff g^q == N-1 for a safe prime.
        BN_set_word(g.get(), group.generator);
        BN_mod_exp(got.get(), g.get(), q.get(), n.get(), ctx.get());
        AXIAM_CHECK(BN_cmp(got.get(), n_minus_1.get()) == 0);
    }
}

AXIAM_TEST("§23.4 an unrecognised group is refused rather than guessed") {
    // Guessing would mean computing in a group whose safety this SDK has not
    // verified — potentially one whose discrete log the server knows.
    AXIAM_CHECK(!SrpGroup::from_wire("rfc5054_1024").has_value());
    AXIAM_CHECK(SrpGroup::from_wire("rfc5054_4096").has_value());
}

// ---------------------------------------------------------------------------
// PAD() and hex
// ---------------------------------------------------------------------------

AXIAM_TEST("§23.3 rule 1 PAD left-pads to the group width") {
    AXIAM_CHECK(axiam::srp::pad_hex("1", 4) == "00000001");
    AXIAM_CHECK(axiam::srp::pad_hex("0102", 2) == "0102");
}

AXIAM_TEST("§23.3 rule 1 PAD refuses an over-wide value rather than truncating") {
    // Silently dropping high bytes would produce a wrong hash that still looked
    // well-formed.
    bool threw = false;
    try {
        axiam::srp::pad_hex("0102030405", 2);
    } catch (const NetworkError&) {
        threw = true;
    }
    AXIAM_CHECK(threw);
}

AXIAM_TEST("a malformed hex field is refused rather than silently truncated") {
    for (const char* bad : {"abc", "zz", ""}) {
        bool threw = false;
        try {
            axiam::srp::from_hex(bad, "salt");
        } catch (const NetworkError&) {
            threw = true;
        }
        AXIAM_CHECK(threw);
    }
}

// ---------------------------------------------------------------------------
// §23.7 rules 1–3 — the vectors
// ---------------------------------------------------------------------------

/// Guards the fixture itself: if these stop holding, everything below silently
/// stops testing the two things it was built to test.
AXIAM_TEST("§23.7 the fixtures cover the cases they exist for") {
    AXIAM_REQUIRE(!vectors().empty());
    bool leading_zero_salt = false, leading_zero_x = false, non_ascii = false;
    std::vector<std::string> seen;
    for (const auto& v : vectors()) {
        if (vstr(v, "salt").rfind("00", 0) == 0) leading_zero_salt = true;
        if (vstr(v, "x").rfind("00", 0) == 0) leading_zero_x = true;
        for (unsigned char c : vstr(v, "identity")) {
            if (c > 0x7f) non_ascii = true;
        }
        seen.push_back(vstr(v, "group"));
    }
    AXIAM_CHECK(leading_zero_salt);
    AXIAM_CHECK(leading_zero_x);
    AXIAM_CHECK(non_ascii);
    for (const SrpGroup& g : SrpGroup::all()) {
        AXIAM_CHECK(std::find(seen.begin(), seen.end(), g.wire_name) != seen.end());
    }
}

AXIAM_TEST("§23.7 rule 1 every vector reproduces every intermediate") {
    for (const auto& v : vectors()) {
        auto group = SrpGroup::from_wire(vstr(v, "group"));
        AXIAM_REQUIRE(group.has_value());
        const int width = group->byte_length;

        BnCtxPtr ctx(BN_CTX_new());
        BnPtr n = bn(group->modulus_hex);
        BnPtr a = bn(vstr(v, "a_priv"));
        BnPtr b = bn(vstr(v, "b_priv"));
        BnPtr x = bn(vstr(v, "x"));
        BnPtr g(BN_new());
        BN_set_word(g.get(), group->generator);
        BN_nnmod(x.get(), x.get(), n.get(), ctx.get());

        // k = H(N | PAD(g))
        AXIAM_CHECK(axiam::srp::pad_hex(axiam::srp::multiplier_hex(*group), 32) == vstr(v, "k"));

        // v = g^x mod N
        AXIAM_CHECK(axiam::srp::compute_verifier(*group, axiam::srp::from_hex(vstr(v, "x"), "x")) ==
                    vstr(v, "verifier"));

        // A = g^a mod N
        BnPtr a_pub(BN_new());
        BN_mod_exp(a_pub.get(), g.get(), a.get(), n.get(), ctx.get());
        AXIAM_CHECK(hex_of(a_pub.get(), width) == vstr(v, "a_pub"));

        // B = (k*v + g^b) mod N
        BnPtr k = bn(axiam::srp::multiplier_hex(*group));
        BnPtr verifier(BN_new()), tmp(BN_new()), b_pub(BN_new());
        BN_mod_exp(verifier.get(), g.get(), x.get(), n.get(), ctx.get());
        BN_mod_mul(tmp.get(), k.get(), verifier.get(), n.get(), ctx.get());
        BN_mod_exp(b_pub.get(), g.get(), b.get(), n.get(), ctx.get());
        BN_mod_add(b_pub.get(), tmp.get(), b_pub.get(), n.get(), ctx.get());
        AXIAM_CHECK(hex_of(b_pub.get(), width) == vstr(v, "b_pub"));

        // u = H(PAD(A) | PAD(B))
        std::string u_hex = axiam::srp::hash_hex(
            {axiam::srp::from_hex(hex_of(a_pub.get(), width), "a"),
             axiam::srp::from_hex(hex_of(b_pub.get(), width), "b")});
        AXIAM_CHECK(u_hex == vstr(v, "u"));

        // S = (B - k*g^x)^(a + u*x) mod N
        BnPtr u = bn(u_hex);
        BnPtr kgx(BN_new()), base(BN_new()), exponent(BN_new()), s(BN_new());
        BN_mod_exp(tmp.get(), g.get(), x.get(), n.get(), ctx.get());
        BN_mod_mul(kgx.get(), k.get(), tmp.get(), n.get(), ctx.get());
        BN_mod_sub(base.get(), b_pub.get(), kgx.get(), n.get(), ctx.get());
        BN_mul(exponent.get(), u.get(), x.get(), ctx.get());
        BN_add(exponent.get(), exponent.get(), a.get());
        BN_mod_exp(s.get(), base.get(), exponent.get(), n.get(), ctx.get());
        AXIAM_CHECK(hex_of(s.get(), width) == vstr(v, "session_secret"));

        // K = H(PAD(S))
        AXIAM_CHECK(axiam::srp::hash_hex({axiam::srp::from_hex(hex_of(s.get(), width), "s")}) ==
                    vstr(v, "session_key"));
    }
}

/// Drives the real session rather than the helpers, with `a` pinned to the
/// vector's value — otherwise this would only test the internals.
AXIAM_TEST("§23.7 rule 1 every vector produces the contract proofs") {
    for (const auto& v : vectors()) {
        auto group = SrpGroup::from_wire(vstr(v, "group"));
        AXIAM_REQUIRE(group.has_value());

        auto session = axiam::srp::ClientSession::with_fixed_ephemeral(*group, vstr(v, "a_priv"));
        AXIAM_CHECK(session.client_public() == vstr(v, "a_pub"));

        SrpProofs proofs = session.finish(vstr(v, "identity"), vstr(v, "salt"), vstr(v, "b_pub"),
                                          axiam::srp::from_hex(vstr(v, "x"), "x"));
        AXIAM_CHECK(proofs.client_proof == vstr(v, "client_proof"));
        AXIAM_CHECK(proofs.expected_server_proof == vstr(v, "server_proof"));
    }
}

// ---------------------------------------------------------------------------
// §23.3 protocol refusals
// ---------------------------------------------------------------------------

/// §23.7 rule 6, with no network round trip. The classic SRP break: a client
/// that accepts `B ≡ 0` derives a predictable `S` and would authenticate against
/// a server that never knew the verifier.
AXIAM_TEST("§23.7 rule 6 a server public value congruent to zero is refused") {
    auto group = SrpGroup::from_wire("rfc5054_2048");
    AXIAM_REQUIRE(group.has_value());
    auto session = axiam::srp::ClientSession::begin(*group);

    bool threw = false;
    try {
        session.finish("alice", std::string(64, '0'),
                       std::string(static_cast<std::size_t>(group->byte_length) * 2, '0'),
                       std::string(32, '\0'));
    } catch (const NetworkError& e) {
        threw = std::string(e.what()).find("invalid public value") != std::string::npos;
    }
    AXIAM_CHECK(threw);
}

AXIAM_TEST("§23.3 rule 7 every exchange uses a fresh client ephemeral") {
    auto group = SrpGroup::from_wire("rfc5054_2048");
    AXIAM_REQUIRE(group.has_value());
    AXIAM_CHECK(axiam::srp::ClientSession::begin(*group).client_public() !=
                axiam::srp::ClientSession::begin(*group).client_public());
}

AXIAM_TEST("§23.3 rule 4 an unknown KDF is refused rather than substituted") {
    // Substituting the other KDF derives a different x and surfaces as "invalid
    // password" — the single most misleading failure available.
    bool named = false;
    try {
        axiam::srp::derive_x("alice", "pw", std::string(32, '\0'), SrpKdfParams{"scrypt", 1, 0, 0});
    } catch (const NetworkError& e) {
        named = std::string(e.what()).find("scrypt") != std::string::npos;
    }
    AXIAM_CHECK(named);
}

// ---------------------------------------------------------------------------
// KDF
// ---------------------------------------------------------------------------

/// Every one of these must change the output, or a verifier would be replayable
/// against a different account or a different salt.
AXIAM_TEST("§23.3 rule 3 the KDF binds identity, password and salt") {
    SrpKdfParams params{SrpKdfParams::kPbkdf2Sha256, 1000, 0, 0};
    std::string salt_a(32, '\x0a');
    std::string salt_b(32, '\x0b');

    std::string base = axiam::srp::derive_x("alice", "pw", salt_a, params);
    AXIAM_CHECK(base.size() == 32);
    AXIAM_CHECK(axiam::srp::derive_x("alice", "pw", salt_a, params) == base);
    AXIAM_CHECK(axiam::srp::derive_x("bob", "pw", salt_a, params) != base);
    AXIAM_CHECK(axiam::srp::derive_x("alice", "pw2", salt_a, params) != base);
    AXIAM_CHECK(axiam::srp::derive_x("alice", "pw", salt_b, params) != base);
}

AXIAM_TEST("§23.7 rule 3 a mangled non-ASCII identity is a different account") {
    SrpKdfParams params{SrpKdfParams::kPbkdf2Sha256, 1000, 0, 0};
    std::string salt(32, '\0');
    AXIAM_CHECK(axiam::srp::derive_x("renée", "pw", salt, params) !=
                axiam::srp::derive_x("renÃ©e", "pw", salt, params));
}

/// §23.8: Argon2id needs OpenSSL >= 3.2. Where it is absent the SDK must REFUSE
/// rather than substitute PBKDF2 — that would derive a different `x` and report
/// a perfectly good password as wrong.
AXIAM_TEST("§23.8 argon2id runs where OpenSSL has it, and is refused where it does not") {
    SrpKdfParams params{SrpKdfParams::kArgon2id, 1, 8192, 1};
    std::string salt(32, '\0');
    if (axiam::srp::argon2_available()) {
        AXIAM_CHECK(axiam::srp::derive_x("alice", "pw", salt, params).size() == 32);
    } else {
        bool named = false;
        try {
            axiam::srp::derive_x("alice", "pw", salt, params);
        } catch (const NetworkError& e) {
            named = std::string(e.what()).find("argon2id") != std::string::npos;
        }
        AXIAM_CHECK(named);
    }
    // The §23.1 probe is unconditional; the Argon2 probe is the one that can
    // legitimately say no.
    AXIAM_CHECK(axiam::srp::available());
}

AXIAM_TEST("KDF defaults match AXIAM's own costs") {
    SrpKdfParams argon = SrpKdfParams{}.with_defaults();
    AXIAM_CHECK(argon.kdf == SrpKdfParams::kArgon2id);
    AXIAM_CHECK(argon.iterations == 2);
    AXIAM_CHECK(argon.memory_kib == 19456);
    AXIAM_CHECK(argon.parallelism == 1);

    SrpKdfParams pbkdf2 = SrpKdfParams{SrpKdfParams::kPbkdf2Sha256, 0, 0, 0}.with_defaults();
    AXIAM_CHECK(pbkdf2.iterations == 600000);
    AXIAM_CHECK(pbkdf2.memory_kib == 0);
}

// ---------------------------------------------------------------------------
// §23.3 rule 6 — server proof comparison
// ---------------------------------------------------------------------------

AXIAM_TEST("§23.3 rule 6 the server proof comparison rejects everything but a match") {
    AXIAM_REQUIRE(!vectors().empty());
    const std::string proof = vstr(vectors()[0], "server_proof");
    AXIAM_CHECK(axiam::srp::verify_server_proof(proof, proof));
    AXIAM_CHECK(!axiam::srp::verify_server_proof(proof, proof.substr(0, proof.size() - 1) + "0"));
    AXIAM_CHECK(!axiam::srp::verify_server_proof(proof, proof.substr(0, 32)));
    AXIAM_CHECK(!axiam::srp::verify_server_proof(proof, ""));
}

// ---------------------------------------------------------------------------
// §23.3 rule 11 — enrolment salts
// ---------------------------------------------------------------------------

AXIAM_TEST("§23.3 rule 11 enrolment salts are 32 fresh bytes") {
    // A reused salt would make every verifier in a tenant equally attackable
    // with one precomputation.
    std::string first = axiam::srp::generate_salt();
    AXIAM_CHECK(first.size() == 32);
    AXIAM_CHECK(first != axiam::srp::generate_salt());
}
