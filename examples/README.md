# Examples

Small, self-contained programs that link the public `axiam::axiam_cpp` target
exactly as a downstream consumer would. They **compile without a live AXIAM
server** and read all connection details from environment variables, so you can
build them offline and run them against a real server when you have one.

| Example | Shows |
|---------|-------|
| [`login_mfa.cpp`](login_mfa.cpp)   | Two-phase login + MFA verify (CONTRACT.md §1, §5, §5.1) |
| [`rest_authz.cpp`](rest_authz.cpp) | `check_access` / `can` / `batch_check` (CONTRACT.md §1) |

## Build

Examples are gated behind the `AXIAM_BUILD_EXAMPLES` CMake option (OFF by
default), mirroring `AXIAM_BUILD_TESTS`:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DAXIAM_BUILD_EXAMPLES=ON
cmake --build build -j
```

The binaries land in `build/examples/`.

## Run

Configuration is read from the environment (defaults in parentheses):

| Variable | Default | Meaning |
|----------|---------|---------|
| `AXIAM_BASE_URL`    | `https://localhost:8443` | Server base URL |
| `AXIAM_TENANT_SLUG` | `acme` | Tenant slug (§5 — mandatory) |
| `AXIAM_ORG_SLUG`    | `acme` | Organization slug (§5.1 — mandatory for login/refresh) |
| `AXIAM_EMAIL`       | `user@example.com` | Login username / email |
| `AXIAM_PASSWORD`    | `changeme` | Login password |
| `AXIAM_TOTP_CODE`   | `000000` | TOTP code (login_mfa only) |
| `AXIAM_RESOURCE_ID` | all-zero UUID | Resource id to check (rest_authz only) |

```bash
export AXIAM_BASE_URL=https://your-axiam-host:8443
export AXIAM_ORG_SLUG=acme
export AXIAM_TENANT_SLUG=acme
export AXIAM_EMAIL=alice@acme.example
export AXIAM_PASSWORD='correct horse battery staple'

./build/examples/axiam_example_login_mfa
./build/examples/axiam_example_rest_authz
```

> **Why org context?** A tenant slug is only unique within an organization, so
> §5.1 requires an org identifier for login and refresh. Without it the server
> rejects login with HTTP 400 `must provide org_id or org_slug`. Both examples
> build the client with `.tenant_slug(...)` **and** `.org_slug(...)`.
