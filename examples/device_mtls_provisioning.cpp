// device_mtls_provisioning — provision an IoT device, then let it authenticate.
//
// This is the flow the certificate namespaces exist for, end to end, and it is
// two programs' worth of work in one file so the seam between them is visible:
//
//   PART 1 (operator side, §27): create a service account for the device,
//   generate a device certificate signed by the tenant's signing CA, and bind
//   the certificate to the account so the server will accept it as that
//   identity.
//
//   PART 2 (device side, §6.1): a second client built with that certificate as
//   its mTLS client identity, calling authenticate_device().
//
// THE ONE-TIME SECRET (§27.5) is the whole reason these are two parts.
// `GeneratedCertificate::private_key_pem` is returned exactly once, by exactly
// this call, and the server does not store it. If the operator side does not
// write it somewhere the device can read, nobody can ever recover it and the
// only fix is to generate a new certificate. Sensitive<T> is what keeps it from
// being lost the OTHER way: it renders redacted everywhere — every stream
// insertion, every log line, every debugger-friendly dump — so the way to get
// the bytes out is to ask for them, at the one point of use, with
// axiam::detail::reveal(). It still reaches the wire; it just does not reach
// your log aggregator by accident.
//
// Set AXIAM_PROVISION=1 to run part 1 (it writes). Part 2 runs whenever
// AXIAM_DEVICE_CERT/AXIAM_DEVICE_KEY name readable PEM files.

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include "axiam/axiam.hpp"
#include "axiam/management.hpp"

namespace {

std::string env_or(const char* key, const std::string& fallback) {
    const char* v = std::getenv(key);
    return (v != nullptr && *v != '\0') ? std::string(v) : fallback;
}

std::string read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("cannot read " + path);
    }
    std::ostringstream buf;
    buf << in.rdbuf();
    return buf.str();
}

// Written with the narrowest permissions the platform offers is the caller's
// job; this example writes plainly and says so, because pretending otherwise
// would be worse than being explicit about what it does not do.
void write_file(const std::string& path, const std::string& contents) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        throw std::runtime_error("cannot write " + path);
    }
    out << contents;
}

// ---- PART 1: the operator provisions the device ------------------------

int provision(axiam::Client& client) {
    auto mgmt = client.management();

    const std::string serial = env_or("AXIAM_DEVICE_SERIAL", "device-0001");
    const std::string tenant =
        env_or("AXIAM_TENANT_ID", "11111111-1111-1111-1111-111111111111");

    // 1. The identity the device will authenticate AS.
    //
    // A device is a machine, so it gets a service account rather than a user.
    // The response carries a client_secret — a one-time secret this flow does
    // not need, because the device will present a certificate instead. It is
    // wrapped in Sensitive<T> all the same: "we are not going to use it" is not
    // a reason to let it print.
    axiam::management::CreateServiceAccountRequest sa_req;
    sa_req.name = serial;
    sa_req.description = "IoT device " + serial;
    const auto account = mgmt.service_accounts().create(sa_req);
    std::cout << "service account " << account.id << " (client_id " << account.client_id
              << ")\n"
              << "  client_secret: " << account.client_secret << "  <- redacted by §7\n";

    // 2. The signing CA to issue from.
    //
    // Per-tenant signing CAs are chained beneath the ORGANIZATION's CA, which
    // is why this is addressed under the organization's ca_certificates handle
    // with the tenant named explicitly rather than implied.
    const auto signing_cas = mgmt.ca_certificates().list_signing_cas(tenant);
    if (signing_cas.empty()) {
        std::cerr << "tenant " << tenant << " has no signing CA — generate one first "
                  << "(ca_certificates().generate_signing_ca(...)).\n";
        return 1;
    }
    const auto& ca = signing_cas.items.front();
    std::cout << "signing CA " << ca.id << " (" << ca.subject << ")\n";

    // 3. The certificate itself.
    //
    // Ed25519 rather than RSA-4096 because the thing holding the private key is
    // a microcontroller; both are permitted and this is the one that will not
    // dominate its boot time.
    axiam::management::CreateCertificateRequest cert_req;
    cert_req.cert_type = axiam::management::CertificateType::Device;
    cert_req.issuer_ca_id = ca.id;
    cert_req.key_algorithm = axiam::management::KeyAlgorithm::Ed25519;
    cert_req.subject = "CN=" + serial;
    cert_req.validity_days = 365;
    cert_req.metadata = R"({"serial":")" + serial + R"("})";
    const auto issued = mgmt.certificates().generate(cert_req);

    std::cout << "certificate " << issued.id << "\n"
              << "  subject     " << issued.subject << "\n"
              << "  fingerprint " << issued.fingerprint << "\n"
              << "  valid       " << issued.not_before << " .. " << issued.not_after << "\n"
              << "  private_key " << issued.private_key_pem << "  <- redacted by §7\n";

    // THE ONE MOMENT the private key exists outside the device. reveal() is
    // deliberately awkward to reach and deliberately narrow in scope: the
    // revealed reference is used on the next line and nowhere else.
    const std::string cert_path = env_or("AXIAM_DEVICE_CERT", serial + ".crt.pem");
    const std::string key_path = env_or("AXIAM_DEVICE_KEY", serial + ".key.pem");
    write_file(cert_path, issued.public_cert_pem);
    write_file(key_path, axiam::detail::reveal(issued.private_key_pem));
    std::cout << "wrote " << cert_path << " and " << key_path
              << " — the key is unrecoverable if these are lost\n";

    // 4. Bind the certificate to the account.
    //
    // Until this lands, the certificate is a valid certificate that
    // authenticates as nobody: the server has no mapping from its fingerprint
    // to an identity. This is the step whose absence looks like "mTLS is
    // broken" when it is actually "mTLS worked and the identity was unknown".
    axiam::management::BindCertificate bind;
    bind.certificate_id = issued.id;
    mgmt.service_accounts().bind_certificate(account.id, bind);
    std::cout << "bound certificate " << issued.id << " to account " << account.id << "\n";

    // 5. The listener must trust the CA for CLIENT certificates.
    //
    // Separate from the CA existing and separate from it having signed this
    // certificate: a CA AXIAM issues from is not automatically a CA it will
    // accept client certificates from, because those are different trust
    // decisions. restart_required comes back true because rustls builds its
    // client trust store once, when the listener is constructed.
    if (env_or("AXIAM_SET_TRUST_ANCHOR", "") == "1") {
        axiam::management::SetMtlsTrustAnchor anchor;
        anchor.enabled = true;
        const auto anchored = mgmt.ca_certificates().set_mtls_trust_anchor(ca.id, anchor);
        std::cout << anchored.message
                  << (anchored.restart_required ? "  (takes effect at next start)" : "") << "\n";
    }

    return 0;
}

// ---- PART 2: the device authenticates ----------------------------------

int authenticate_as_device() {
    const std::string cert_path = env_or("AXIAM_DEVICE_CERT", "");
    const std::string key_path = env_or("AXIAM_DEVICE_KEY", "");
    if (cert_path.empty() || key_path.empty()) {
        std::cout << "\n(set AXIAM_DEVICE_CERT and AXIAM_DEVICE_KEY to run the device half)\n";
        return 0;
    }

    // A SECOND client. The operator's client above holds an administrator's
    // session; this one holds a device's certificate and nothing else, and the
    // two must not be the same object — a device that inherited the operator's
    // session would be authenticated as the operator.
    auto device =
        axiam::Client::builder()
            .base_url(env_or("AXIAM_BASE_URL", "https://localhost:8443"))
            .tenant_id(env_or("AXIAM_TENANT_ID", "11111111-1111-1111-1111-111111111111"))
            // §6.1. The key never leaves this process and is never sent: TLS
            // proves possession of it without transmitting it.
            .with_client_cert(read_file(cert_path), read_file(key_path))
            .build();

    // §6.1: the server reads the identity off the certificate the TLS handshake
    // already validated. There is no password, no client_secret, and no
    // username in this call — the credential IS the connection.
    const auto auth = device.authenticate_device();
    std::cout << "\ndevice authenticated: " << auth.token_type << ", expires in "
              << auth.expires_in << "s\n"
              << "  access_token " << auth.access_token << "  <- redacted by §7\n";

    // And it is a real session: the device can now make authorization checks
    // as itself.
    const auto decision = device.can("read", env_or("AXIAM_RESOURCE_ID", "telemetry"));
    std::cout << "  can read telemetry: " << (decision.allowed ? "yes" : "no") << "\n";
    return 0;
}

}  // namespace

int main() {
    try {
        if (env_or("AXIAM_PROVISION", "") == "1") {
            auto client =
                axiam::Client::builder()
                    .base_url(env_or("AXIAM_BASE_URL", "https://localhost:8443"))
                    .tenant_id(
                        env_or("AXIAM_TENANT_ID", "11111111-1111-1111-1111-111111111111"))
                    .build();
            client.login(env_or("AXIAM_USERNAME", "admin"), env_or("AXIAM_PASSWORD", "admin"));

            const int rc = provision(client);
            if (rc != 0) {
                return rc;
            }
        } else {
            std::cout << "(set AXIAM_PROVISION=1 to run the operator half — it writes)\n";
        }

        return authenticate_as_device();

    } catch (const axiam::management::ConflictError& e) {
        // 409 — most likely this serial is already provisioned. Under
        // AuthzError, per §27.4 rule 7. Caught before AuthzError below, which
        // would otherwise swallow it.
        std::cerr << "already provisioned? " << e.what() << "\n";
        return 1;
    } catch (const axiam::management::NotFoundError& e) {
        // 404 — or the object belongs to another tenant. AXIAM answers the same
        // status for both on purpose, so the SDK does not pretend to tell them
        // apart.
        std::cerr << "not found (or not yours): " << e.what() << "\n";
        return 1;
    } catch (const axiam::AuthzError& e) {
        std::cerr << "refused: " << e.what() << "\n";
        return 1;
    } catch (const axiam::AxiamError& e) {
        std::cerr << "failed: " << e.what() << "\n";
        return 1;
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        return 1;
    }
}
