/// \file
/// SRP-6a protocol arithmetic (CONTRACT.md §23) — the implementation behind
/// include/axiam/srp.hpp.
///
/// Everything here is pure: no I/O, no client state, no network. The two HTTP
/// calls and the policy around them are `Client::login_srp` in client.cpp.
///
/// Every BIGNUM allocated here is freed on every path, including the error
/// paths, and every secret intermediate (x, S, K) is wiped before release —
/// BN_clear_free rather than BN_free for anything derived from the password.
#include "axiam/srp.hpp"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cstring>
#include <memory>
#include <stdexcept>

#include "axiam/errors.hpp"

namespace axiam {
namespace {

// ---------------------------------------------------------------------------
// §23.4 Groups — RFC 5054 Appendix A.
//
// Embedded as constants; a modulus is NEVER accepted from the server, because a
// server-supplied N is a server-supplied trapdoor. tests/test_srp_vectors.cpp
// asserts each one's width, primality and safe-primality: a transcription slip
// here is a silent, total break that a client/server round-trip cannot catch,
// since both sides would share the same wrong constant.
// ---------------------------------------------------------------------------

constexpr const char kN2048[] =
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050"
    "A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50"
    "E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8"
    "55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B"
    "CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748"
    "544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6"
    "AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6"
    "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73";

constexpr const char kN3072[] =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33"
    "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864"
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2"
    "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

constexpr const char kN4096[] =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33"
    "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864"
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2"
    "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"
    "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8"
    "DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2"
    "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"
    "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF";


/// RAII for the OpenSSL handles this file allocates. Every one of them has a
/// distinct free function, and a `goto done` chain in C++ would be worse than
/// the deleters.
struct BnDeleter {
    void operator()(BIGNUM* p) const noexcept { BN_clear_free(p); }
};
struct BnCtxDeleter {
    void operator()(BN_CTX* p) const noexcept { BN_CTX_free(p); }
};
struct MdCtxDeleter {
    void operator()(EVP_MD_CTX* p) const noexcept { EVP_MD_CTX_free(p); }
};
struct KdfDeleter {
    void operator()(EVP_KDF* p) const noexcept { EVP_KDF_free(p); }
};
struct KdfCtxDeleter {
    void operator()(EVP_KDF_CTX* p) const noexcept { EVP_KDF_CTX_free(p); }
};
using BnPtr = std::unique_ptr<BIGNUM, BnDeleter>;
using BnCtxPtr = std::unique_ptr<BN_CTX, BnCtxDeleter>;
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, MdCtxDeleter>;
using KdfPtr = std::unique_ptr<EVP_KDF, KdfDeleter>;
using KdfCtxPtr = std::unique_ptr<EVP_KDF_CTX, KdfCtxDeleter>;

constexpr char kHexDigits[] = "0123456789abcdef";

std::string bytes_to_hex(const unsigned char* bytes, std::size_t len) {
    std::string out(len * 2, '\0');
    for (std::size_t i = 0; i < len; ++i) {
        out[i * 2] = kHexDigits[(bytes[i] >> 4) & 0xf];
        out[i * 2 + 1] = kHexDigits[bytes[i] & 0xf];
    }
    return out;
}

int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/// Decodes hex to raw bytes. Never truncates: a malformed field is refused,
/// because silently dropping a nibble would produce a wrong hash that still
/// looked well-formed.
std::string hex_to_bytes(const std::string& hex, const char* field) {
    if (hex.empty() || hex.size() % 2 != 0) {
        throw NetworkError(std::string("SRP: the server's ") + field + " is not valid hex");
    }
    std::string out(hex.size() / 2, '\0');
    for (std::size_t i = 0; i < out.size(); ++i) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            throw NetworkError(std::string("SRP: the server's ") + field + " is not valid hex");
        }
        out[i] = static_cast<char>((hi << 4) | lo);
    }
    return out;
}

BnPtr bn_from_hex(const std::string& hex, const char* field) {
    BIGNUM* raw = nullptr;
    if (BN_hex2bn(&raw, hex.c_str()) == 0) {
        BN_free(raw);
        throw NetworkError(std::string("SRP: the server's ") + field + " is not valid hex");
    }
    return BnPtr(raw);
}

BnPtr bn_from_bytes(const std::string& bytes) {
    BnPtr out(BN_bin2bn(reinterpret_cast<const unsigned char*>(bytes.data()),
                        static_cast<int>(bytes.size()), nullptr));
    if (!out) throw NetworkError("SRP: out of memory");
    return out;
}

/// PAD(v) — exactly `byte_length` big-endian bytes, as raw bytes.
std::string pad_bytes(const BIGNUM* v, int byte_length) {
    std::string out(static_cast<std::size_t>(byte_length), '\0');
    if (BN_bn2binpad(v, reinterpret_cast<unsigned char*>(&out[0]), byte_length) != byte_length) {
        throw NetworkError("SRP: a value is wider than the group modulus");
    }
    return out;
}

std::string sha256(const std::vector<std::string>& parts) {
    MdCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx || EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) {
        throw NetworkError("SRP: SHA-256 is unavailable");
    }
    for (const auto& part : parts) {
        if (EVP_DigestUpdate(ctx.get(), part.data(), part.size()) != 1) {
            throw NetworkError("SRP: SHA-256 failed");
        }
    }
    unsigned char digest[32];
    unsigned int len = 0;
    if (EVP_DigestFinal_ex(ctx.get(), digest, &len) != 1 || len != 32) {
        throw NetworkError("SRP: SHA-256 failed");
    }
    std::string out(reinterpret_cast<const char*>(digest), 32);
    OPENSSL_cleanse(digest, sizeof(digest));
    return out;
}

/// Overwrites a string's buffer before it goes out of scope (§23.3 rule 8).
void wipe(std::string& s) {
    if (!s.empty()) OPENSSL_cleanse(&s[0], s.size());
}

const SrpGroup& group_2048() {
    static const SrpGroup g{"rfc5054_2048", kN2048, 2, 256};
    return g;
}
const SrpGroup& group_3072() {
    static const SrpGroup g{"rfc5054_3072", kN3072, 5, 384};
    return g;
}
const SrpGroup& group_4096() {
    static const SrpGroup g{"rfc5054_4096", kN4096, 5, 512};
    return g;
}

BnPtr generator_bn(const SrpGroup& group) {
    BnPtr g(BN_new());
    if (!g || BN_set_word(g.get(), group.generator) != 1) throw NetworkError("SRP: out of memory");
    return g;
}

}  // namespace

// ---------------------------------------------------------------------------
// The §23.5 value types. They live in `axiam` rather than `axiam::srp` because
// they are part of the client's own vocabulary — Client::srp_enrollment returns
// one — while the arithmetic below is namespaced away from it.
// ---------------------------------------------------------------------------

std::optional<SrpGroup> SrpGroup::from_wire(const std::string& wire_name) {
    if (wire_name == group_2048().wire_name) return group_2048();
    if (wire_name == group_3072().wire_name) return group_3072();
    if (wire_name == group_4096().wire_name) return group_4096();
    return std::nullopt;
}

std::vector<SrpGroup> SrpGroup::all() { return {group_2048(), group_3072(), group_4096()}; }

SrpKdfParams SrpKdfParams::with_defaults() const {
    SrpKdfParams out = *this;
    if (out.kdf.empty()) out.kdf = kArgon2id;
    if (out.kdf == kPbkdf2Sha256) {
        if (out.iterations == 0) out.iterations = 600000;
        out.memory_kib = 0;
        out.parallelism = 0;
    } else {
        if (out.iterations == 0) out.iterations = 2;
        if (out.memory_kib == 0) out.memory_kib = 19456;
        if (out.parallelism == 0) out.parallelism = 1;
    }
    return out;
}

namespace srp {

bool available() { return true; }

bool argon2_available() {
    KdfPtr kdf(EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr));
    return kdf != nullptr;
}

std::string pad_hex(const std::string& hex, int byte_length) {
    BnPtr v = bn_from_hex(hex, "value");
    return srp::to_hex(pad_bytes(v.get(), byte_length));
}

std::string hash_hex(const std::vector<std::string>& parts) {
    return srp::to_hex(sha256(parts));
}

std::string to_hex(const std::string& bytes) {
    return bytes_to_hex(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size());
}

std::string from_hex(const std::string& hex, const char* field) {
    return hex_to_bytes(hex, field);
}

std::string multiplier_hex(const SrpGroup& group) {
    BnPtr n = bn_from_hex(group.modulus_hex, "modulus");
    BnPtr g = generator_bn(group);
    return hash_hex({pad_bytes(n.get(), group.byte_length), pad_bytes(g.get(), group.byte_length)});
}

std::string derive_x(const std::string& identity, const std::string& password,
                     const std::string& salt, const SrpKdfParams& params) {
    std::string secret = identity + ":" + password;
    std::string out(32, '\0');
    auto* out_bytes = reinterpret_cast<unsigned char*>(&out[0]);
    const auto* salt_bytes = reinterpret_cast<const unsigned char*>(salt.data());

    struct Wiper {
        std::string& s;
        ~Wiper() { wipe(s); }
    } wiper{secret};

    if (params.kdf == SrpKdfParams::kPbkdf2Sha256) {
        unsigned iterations = params.iterations ? params.iterations : 600000;
        if (PKCS5_PBKDF2_HMAC(secret.data(), static_cast<int>(secret.size()), salt_bytes,
                              static_cast<int>(salt.size()), static_cast<int>(iterations),
                              EVP_sha256(), 32, out_bytes) != 1) {
            throw NetworkError("SRP: PBKDF2 derivation failed");
        }
        return out;
    }

    if (params.kdf == SrpKdfParams::kArgon2id) {
        KdfPtr kdf(EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr));
        if (!kdf) {
            // §23.8: Argon2 needs OpenSSL >= 3.2. Refuse rather than substitute
            // PBKDF2 — that would derive a different x and surface as "invalid
            // password", the single most misleading failure available here.
            throw NetworkError(
                "SRP: this build's OpenSSL does not provide argon2id (it arrives in 3.2); "
                "the tenant must be configured for pbkdf2_sha256, or this SDK rebuilt "
                "against a newer libcrypto");
        }
        KdfCtxPtr ctx(EVP_KDF_CTX_new(kdf.get()));
        if (!ctx) throw NetworkError("SRP: out of memory");

        unsigned iterations = params.iterations ? params.iterations : 2;
        unsigned memory_kib = params.memory_kib ? params.memory_kib : 19456;
        unsigned lanes = params.parallelism ? params.parallelism : 1;
        // "threads" bounds the actual concurrency and is held at 1 so the result
        // does not depend on how many cores this host happens to have.
        unsigned threads = 1;
        OSSL_PARAM p[7];
        std::size_t n = 0;
        p[n++] = OSSL_PARAM_construct_octet_string(
            "pass", const_cast<char*>(secret.data()), secret.size());
        p[n++] = OSSL_PARAM_construct_octet_string(
            "salt", const_cast<char*>(salt.data()), salt.size());
        p[n++] = OSSL_PARAM_construct_uint("iter", &iterations);
        p[n++] = OSSL_PARAM_construct_uint("memcost", &memory_kib);
        p[n++] = OSSL_PARAM_construct_uint("lanes", &lanes);
        p[n++] = OSSL_PARAM_construct_uint("threads", &threads);
        p[n] = OSSL_PARAM_construct_end();
        if (EVP_KDF_derive(ctx.get(), out_bytes, 32, p) != 1) {
            throw NetworkError("SRP: argon2id derivation failed");
        }
        return out;
    }

    // Never substitute the other KDF: it derives a different x and surfaces as
    // "invalid password", the single most misleading failure this code could
    // produce.
    throw NetworkError("SRP: this SDK does not implement KDF '" + params.kdf +
                       "'; it implements argon2id and pbkdf2_sha256");
}

std::string compute_verifier(const SrpGroup& group, const std::string& x) {
    BnCtxPtr ctx(BN_CTX_new());
    BnPtr n = bn_from_hex(group.modulus_hex, "modulus");
    BnPtr g = generator_bn(group);
    BnPtr xi = bn_from_bytes(x);
    BnPtr v(BN_new());
    if (!ctx || !v || BN_nnmod(xi.get(), xi.get(), n.get(), ctx.get()) != 1 ||
        BN_mod_exp(v.get(), g.get(), xi.get(), n.get(), ctx.get()) != 1) {
        throw NetworkError("SRP: verifier computation failed");
    }
    return srp::to_hex(pad_bytes(v.get(), group.byte_length));
}

std::string generate_salt() {
    std::string salt(32, '\0');
    if (RAND_bytes(reinterpret_cast<unsigned char*>(&salt[0]), 32) != 1) {
        throw NetworkError("SRP: no entropy for the enrolment salt");
    }
    return salt;
}

bool verify_server_proof(const std::string& expected, const std::string& actual) {
    if (expected.size() != actual.size() || expected.empty()) return false;
    return CRYPTO_memcmp(expected.data(), actual.data(), expected.size()) == 0;
}

// ---------------------------------------------------------------------------
// ClientSession
// ---------------------------------------------------------------------------

ClientSession::ClientSession(SrpGroup group, std::string ephemeral_hex)
    : group_(std::move(group)), ephemeral_hex_(std::move(ephemeral_hex)) {
    BnCtxPtr ctx(BN_CTX_new());
    BnPtr n = bn_from_hex(group_.modulus_hex, "modulus");
    BnPtr g = generator_bn(group_);
    BnPtr a = bn_from_hex(ephemeral_hex_, "ephemeral");
    BnPtr a_pub(BN_new());
    if (!ctx || !a_pub || BN_mod_exp(a_pub.get(), g.get(), a.get(), n.get(), ctx.get()) != 1) {
        throw NetworkError("SRP: could not compute the client public value");
    }
    client_public_ = srp::to_hex(pad_bytes(a_pub.get(), group_.byte_length));
}

ClientSession::~ClientSession() { wipe(ephemeral_hex_); }

ClientSession::ClientSession(ClientSession&& other) noexcept
    : group_(std::move(other.group_)),
      ephemeral_hex_(std::move(other.ephemeral_hex_)),
      client_public_(std::move(other.client_public_)) {
    // The moved-from buffer may still hold the secret if the move was a copy
    // (small-string optimisation), so wipe it rather than trust the move.
    wipe(other.ephemeral_hex_);
}

ClientSession& ClientSession::operator=(ClientSession&& other) noexcept {
    if (this != &other) {
        wipe(ephemeral_hex_);
        group_ = std::move(other.group_);
        ephemeral_hex_ = std::move(other.ephemeral_hex_);
        client_public_ = std::move(other.client_public_);
        wipe(other.ephemeral_hex_);
    }
    return *this;
}

ClientSession ClientSession::begin(const SrpGroup& group) {
    unsigned char raw[32];
    if (RAND_bytes(raw, sizeof(raw)) != 1) {
        throw NetworkError("SRP: no entropy for the client ephemeral");
    }
    raw[0] |= 0x80;  // so a is unambiguously >= 2^255
    std::string hex = bytes_to_hex(raw, sizeof(raw));
    OPENSSL_cleanse(raw, sizeof(raw));
    return ClientSession(group, std::move(hex));
}

ClientSession ClientSession::with_fixed_ephemeral(const SrpGroup& group,
                                                  const std::string& ephemeral_hex) {
    return ClientSession(group, ephemeral_hex);
}

SrpProofs ClientSession::finish(const std::string& identity, const std::string& salt_hex,
                                const std::string& server_public_hex,
                                const std::string& x) const {
    const int width = group_.byte_length;
    BnCtxPtr ctx(BN_CTX_new());
    if (!ctx) throw NetworkError("SRP: out of memory");

    std::string salt = hex_to_bytes(salt_hex, "salt");
    BnPtr n = bn_from_hex(group_.modulus_hex, "modulus");
    BnPtr g = generator_bn(group_);
    BnPtr b_pub = bn_from_hex(server_public_hex, "b_pub");

    // §23.3 rule 5. B ≡ 0 is the classic SRP break: S becomes predictable and
    // the exchange would authenticate against a server that never knew the
    // verifier. A broken or hostile server, not a wrong password.
    BnPtr b_mod(BN_new());
    if (!b_mod || BN_nnmod(b_mod.get(), b_pub.get(), n.get(), ctx.get()) != 1) {
        throw NetworkError("SRP: out of memory");
    }
    if (BN_is_zero(b_mod.get())) {
        throw NetworkError("SRP: the server sent an invalid public value (B mod N == 0)");
    }

    std::string pad_a = hex_to_bytes(client_public_, "client_public");
    std::string pad_b = pad_bytes(b_pub.get(), width);

    // u = H(PAD(A) | PAD(B))
    std::string u_bytes = sha256({pad_a, pad_b});
    BnPtr u = bn_from_bytes(u_bytes);
    if (BN_is_zero(u.get())) {
        throw NetworkError("SRP: the server's parameters produce u == 0");
    }

    BnPtr xi = bn_from_bytes(x);
    if (BN_nnmod(xi.get(), xi.get(), n.get(), ctx.get()) != 1) {
        throw NetworkError("SRP: out of memory");
    }
    BnPtr k = bn_from_hex(multiplier_hex(group_), "multiplier");
    BnPtr a = bn_from_hex(ephemeral_hex_, "ephemeral");

    // S = (B - k*g^x)^(a + u*x) mod N
    BnPtr gx(BN_new()), kgx(BN_new()), base(BN_new()), exponent(BN_new()), shared(BN_new());
    if (!gx || !kgx || !base || !exponent || !shared ||
        BN_mod_exp(gx.get(), g.get(), xi.get(), n.get(), ctx.get()) != 1 ||
        BN_mod_mul(kgx.get(), k.get(), gx.get(), n.get(), ctx.get()) != 1 ||
        BN_mod_sub(base.get(), b_pub.get(), kgx.get(), n.get(), ctx.get()) != 1 ||
        // The exponent is NOT reduced: a + u*x is an exponent, and reducing it
        // modulo N rather than the group order would produce a different —
        // wrong — S that still looks perfectly well-formed.
        BN_mul(exponent.get(), u.get(), xi.get(), ctx.get()) != 1 ||
        BN_add(exponent.get(), exponent.get(), a.get()) != 1 ||
        BN_mod_exp(shared.get(), base.get(), exponent.get(), n.get(), ctx.get()) != 1) {
        throw NetworkError("SRP: the exchange could not be completed");
    }

    std::string pad_s = pad_bytes(shared.get(), width);
    std::string session_key = sha256({pad_s});
    struct Wiper {
        std::string& s;
        std::string& k;
        ~Wiper() {
            wipe(s);
            wipe(k);
        }
    } wiper{pad_s, session_key};

    // M1 = H(H(N) XOR H(PAD(g)) | H(I) | s | PAD(A) | PAD(B) | K)
    std::string hn = sha256({pad_bytes(n.get(), width)});
    std::string hg = sha256({pad_bytes(g.get(), width)});
    std::string hxor(hn.size(), '\0');
    for (std::size_t i = 0; i < hn.size(); ++i) {
        hxor[i] = static_cast<char>(hn[i] ^ hg[i]);
    }
    std::string hi = sha256({identity});
    std::string m1 = sha256({hxor, hi, salt, pad_a, pad_b, session_key});

    // M2 = H(PAD(A) | M1 | K)
    std::string m2 = sha256({pad_a, m1, session_key});

    return SrpProofs{srp::to_hex(m1), srp::to_hex(m2)};
}

}  // namespace srp
}  // namespace axiam
