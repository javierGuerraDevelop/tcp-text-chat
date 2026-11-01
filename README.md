# tcp-text-chat

A C++20 desktop text chat project with a Qt 6 client, a headless server, TLS
transport, and SQLite persistence. The first release provides one shared room,
username/password accounts, and Google/GitHub sign-in. The current targets establish
the common, client, server, and test build boundaries. The versioned TCP wire
contract is documented in `docs/protocol.md`.

## Requirements

Linux is the initial supported development platform. Use:

- CMake 3.24 or newer and Ninja.
- GCC 12+ or Clang 16+.
- Qt 6.8 or newer, with Core, Gui, Widgets, Network, Sql, NetworkAuth, and Test.
  The source retains Qt 6.5 as its minimum API level.
- libsodium 1.0.19 or newer for Argon2id password hashing.

Install dependencies with system packages. For Arch Linux and derivatives:

```bash
sudo pacman -S --needed base-devel cmake ninja clang qt6-base qt6-networkauth libsodium
```

For Fedora:

```bash
sudo dnf install cmake ninja-build gcc-c++ clang clang-tools-extra libasan libubsan qt6-qtbase-devel qt6-qtnetworkauth-devel libsodium-devel
```

Qt Network and the system TLS backend provide encrypted client/server transport.
Local authentication uses Argon2id password hashes and opaque, expiring session
tokens; only token digests are stored in SQLite. Password work runs in a bounded
worker pool. Browser OAuth uses an HTTPS callback server, expiring flows, PKCE,
and short-lived single-use handoffs. The client opens the system browser and keeps
chat session tokens in memory. Provider access/refresh tokens are not persisted.
Google and GitHub use authorization-code OAuth 2.0 with authenticated UserInfo
APIs over Qt Network; neither provider requires an ID token for sign-in.

## Build and test

```bash
cmake --preset dev
cmake --build --preset dev
ctest --preset dev
```

Executables are written to `build/bin/`. Both applications support `--help` and
`--version`.

For an AddressSanitizer and UndefinedBehaviorSanitizer build with warnings as errors:

```bash
cmake --preset sanitizers
cmake --build --preset sanitizers
ctest --preset sanitizers
```

For a release build:

```bash
cmake --preset release
cmake --build --preset release
ctest --preset release
```

Run clang-format on changed C++ files and verify them with:

```bash
clang-format --dry-run --Werror <changed-files>
```

Tests are deterministic and run without internet access, OAuth credentials, or a
display server.

## Desktop appearance

Run `build/bin/tcp_chat_client` to open the Qt Widgets application shell. It provides
welcome, connecting, chat-empty, and recoverable error states with keyboard-accessible
controls. Authentication controls are not yet connected to the server.

The **Appearance** selector offers Auto, Light, and Dark. Auto follows Qt's system
color-scheme notifications without a restart, falling back to Light when the platform
reports no preference. Fusion, a shared semantic palette, and a packaged stylesheet
keep application colors consistent. Only the selected appearance is saved in the
client's `QSettings`; credentials and chat session tokens are never persisted there.

## Security and configuration

TLS private keys, OAuth client secrets, session tokens, local databases, and `.env`
files must never be committed. Production OAuth secrets belong only in server-side
environment or secret-store configuration. Non-production TLS fixtures must be
clearly isolated from deployment configuration. The keys under
`tests/tls_fixtures/` are exclusively for offline loopback tests; never install
their CAs or deploy them. See that directory's README for regeneration instructions.

OAuth is coordinated by the server with a separately configured HTTPS callback and
canonical provider settings. Provider secrets stay in server environment or secret
store configuration and are never included in the desktop client. Exact redirect
URLs, state, PKCE, and signed-token claims where applicable protect browser flows.
The default test suite uses fake providers and loopback HTTPS.

Configure Google and GitHub independently with these server environment pairs:

- `TCP_CHAT_GOOGLE_CLIENT_ID` and `TCP_CHAT_GOOGLE_CLIENT_SECRET`
- `TCP_CHAT_GITHUB_CLIENT_ID` and `TCP_CHAT_GITHUB_CLIENT_SECRET`

Both values in a pair must be nonempty. Unset pairs remain unconfigured; incomplete
or invalid pairs fail configuration with an actionable error. Provider endpoints
are fixed in server code, and client secrets are not placed in authorization URLs.
Google requests only the profile scope and uses its stable UserInfo `id`. GitHub
requests `read:user` and uses its numeric UserInfo `id`. Neither flow requests
offline access or an ID token. Access and refresh tokens are discarded after
UserInfo validation and are never persisted.

Real-provider smoke tests are separate from the default suite. Build them with:

```bash
cmake -B build-smoke -S . -G Ninja -DTCP_CHAT_ENABLE_OAUTH_SMOKE_TESTS=ON -DTCP_CHAT_WARNINGS_AS_ERRORS=ON
cmake --build build-smoke --target tcp_chat_oauth_smoke_tests
```

Set `TCP_CHAT_OAUTH_SMOKE=1`, `TCP_CHAT_OAUTH_SMOKE_PROVIDER` to `google` or
`github`, and the selected provider's credential pair. Supply a fresh manually
authorized `TCP_CHAT_OAUTH_SMOKE_CODE`, its `TCP_CHAT_OAUTH_SMOKE_VERIFIER`, and
the exact `TCP_CHAT_OAUTH_SMOKE_REDIRECT_URI`. Then run
`ctest --test-dir build-smoke -R '^oauth_smoke$' --output-on-failure`. These
short-lived values and real provider responses must never be committed or logged.
Without the explicit opt-in and complete configuration, the smoke test skips and
makes no external request.

## License

This project is licensed under the GNU General Public License version 2. See
`LICENSE` for the full text.
