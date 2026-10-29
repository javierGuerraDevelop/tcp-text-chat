# AGENTS.md (root)

Cross-cutting instructions for agents working anywhere in the tcp-text-chat
repository. If a component subfolder later gets its own `AGENTS.md`, that file owns
stack-specific rules; this file owns what applies everywhere.

## Project overview

- tcp-text-chat is a C++20 desktop TCP chat application: a Qt 6 client, a headless
  C++ server, and SQLite persistence. Clients never access the server database
  directly.
- Shared protocol and domain code lives in `include/tcp_chat/` and `src/common/`.
  Client code lives in `src/client/`; server code lives in `src/server/`. Tests live
  in `tests/`, SQL migrations in `migrations/`, and Qt resources in `resources/`.
- Keep shared protocol code independent of Qt Widgets and server storage. Keep UI,
  socket, and database I/O outside domain logic so it remains deterministic and
  testable.
- Protocol changes are cross-component: update the shared codec, client, server,
  protocol documentation, and affected tests together. Database migrations must be
  forward-only once merged.

## Implementation workflow

1. Inspect `git status`, the relevant code, and the existing tests before editing.
2. Make a short checklist for substantial work, then implement a runnable increment.
3. Preserve public interfaces, protocol compatibility, migration history, and CMake
   targets unless the task changes them. Report conflicts rather than silently
   redesigning shared surfaces.
4. Build, run focused tests, inspect the diff, and fix relevant failures.
5. Run the full verification suite, then report what changed, what was actually
   verified, and what remains unverified.

Tests must not require internet access, real Google/GitHub credentials, or a display
server. Use local fake OAuth providers, loopback servers, temporary databases, and
Qt's offscreen platform where appropriate. Keep real-provider smoke tests separate
and explicitly configured. Continue independent work when credentials are missing.

## Build, test, lint, sanitizers

Use the documented CMake presets when available, or these equivalent commands:

```bash
cmake -B build -S . -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure
```

For ASan and UBSan with warnings as errors:

```bash
cmake -B build-san -S . -DTCP_CHAT_ENABLE_SANITIZERS=ON -DTCP_CHAT_WARNINGS_AS_ERRORS=ON
cmake --build build-san -j"$(nproc)"
ctest --test-dir build-san --output-on-failure
```

For formatting:

```bash
clang-format -i <changed-files>
clang-format --dry-run --Werror <changed-files>
```

Use separate build directories for concurrent builds. Do not modify `.clang-format`.

## CI: what "green" means

Every change must pass GitHub Actions, or the exact local equivalent when CI is
unavailable:

1. Configure and build with warnings as errors using Linux GCC 12+ and Clang 16+.
2. Run `ctest --output-on-failure`.
3. Run separate ASan/UBSan and, for concurrency changes, TSan builds on Linux.
4. Run `clang-format --dry-run --Werror` over touched C++ files.
5. Keep configured clang-tidy diagnostics clean.

Never silence warnings, disable sanitizers, relax assertions, or skip tests to make
CI pass. Never report completion with failing tests, sanitizer errors, new warnings,
or formatting violations. Do not combine TSan with ASan/UBSan. Keep builds
reproducible using only approved system packages with documented minimum versions
and a pinned CI runner/container.

## Code style

### Language and dependencies

- Use C++20. Do not raise the minimum silently.
- Approved third-party components are Qt 6 Core/Gui/Widgets/Network/Sql/NetworkAuth,
  SQLite through the Qt SQL SQLite driver, libsodium for Argon2id, and Qt Test.
- Use documented system packages. Do not add another dependency or package manager
  without approval, and keep license compatibility with the repository in view.
- Prefer Qt and standard-library facilities already in the project over another
  library that provides the same capability.

### Initialization

- Prefer copy initialization with `=` over brace initialization `{}` for values.
  - Use `int x = 0;`, `Node* p = head;`, and `auto total = compute();`.
- For direct construction, prefer `T value{args};` over `T value(args);` when the
  braced form is needed.
- If default initialization is needed, prefer `T x{};` over `T x = {};`.
- Use `{}` only for aggregate/array initialization, disambiguating the most vexing
  parse, intentional `initializer_list` construction, required explicit-constructor
  return/argument contexts, or value-initialization where `=` would be ambiguous.
- Never use `{}` purely as a stylistic default or convert existing `=` initialization
  to `{}` in unrelated refactors.

### Ownership and safety

- RAII everywhere; no owning raw pointers and no manual `new`/`delete`. Qt parent
  ownership must be explicit and must not be mixed with incompatible smart-pointer
  ownership.
- Maintain const correctness. No C-style casts and no `using namespace` in headers.
- Prefer `std::optional`, `std::string_view`, `std::span`, and `std::chrono` at
  interfaces where they fit Qt's ownership and API model.
- Do not copy immutable global data; use pointers, spans, or views.

### Qt, API design, and concurrency

- Keep public APIs minimal. Lock-assuming handlers must be private; only synchronized
  entry points are public.
- Respect QObject thread affinity. Update UI and socket objects only on their owning
  thread; use queued signals for worker results.
- Never block the GUI thread. Use asynchronous Qt sockets and bounded workers for
  expensive password hashing or other blocking work.
- Use a `QSqlDatabase` connection only on the thread that created it. Use bound query
  parameters, transactions, and explicit error propagation; never interpolate user
  input into SQL.
- Keep callbacks and file/socket/database I/O outside locks. Bound connection queues,
  output buffers, worker queues, frame sizes, and request deadlines.

### Formatting and comments

- Four-space indentation; `.clang-format` is the source of truth.
- One concise doc comment per function/type explaining behavior and non-obvious
  constraints such as thread affinity or required locks.
- No comments that restate code, commented-out code, or TODOs. Inline comments are
  for non-obvious protocol, security, timing, database, and concurrency rationale.

### Authentication and transport security

- Use libsodium's Argon2id implementation with unique salts and documented cost
  parameters. Never invent password hashing or compare secrets with early-exit
  comparisons.
- Store only hashes of high-entropy chat session tokens. Keep client session tokens
  out of logs and persistent plaintext settings.
- OAuth uses state and PKCE where supported, exact server HTTPS redirect URIs, and
  provider issuer, audience, signature, and nonce validation as applicable. Never
  hardcode provider secrets in source, resources, or client binaries.
- Provider secrets are server-only environment/secret-store configuration. Do not
  store provider access/refresh tokens unless a separately approved feature needs
  them.
- Validate frame lengths, UTF-8, message sizes, authentication state, and permissions
  at server boundaries. Rate-limit authentication and message sending.
- All client/server chat connections require TLS. Never add plaintext fallback,
  disable certificate verification, or ignore TLS errors.

### Tests

- Use Qt Test and CTest. Tests must be deterministic and offline; use `QSignalSpy`,
  fake clocks, temporary directories, local fake providers, and loopback transports.
  Never use real sleeps to advance time.
- Cover fragmented/coalesced/malformed frames, migration and constraint behavior,
  authentication/session expiry, OAuth callback validation, reconnect/history, and
  theme changes. A bug fix starts with a regression test that reproduces the bug.
- Keep external-provider tests separate from the default suite and never commit real
  callback responses, tokens, or credentials.

## Repository boundaries and handoff

- Never commit real secrets, `.env` files, provider client secrets, chat session
  tokens, production TLS private keys, captured credentials, or production databases.
  Only clearly labeled non-production test keys may be committed for deterministic
  TLS fixtures; never reuse them outside tests.
- Never commit generated artifacts such as `build*/`, `_deps/`, generated
  `compile_commands.json`, CMake cache/output, Qt Creator user files, test output,
  logs, or local SQLite files.
- Preserve user and teammate changes. Do not switch a shared checkout's branch while
  another agent is working. Commit, push, and open PRs only when authorized.
- One writer per file. Shared protocol, root build files, and migration history have
  one owner. Use separate build directories for concurrent builds.
- Handoff must state what changed, exact commands and results, and unverified behavior.

## Commit and PR hygiene

- Keep each PR small, coherent, and independently reviewable. Split it into multiple
  logical commits unless the change is genuinely trivial.
- Use descriptive Conventional Commits with imperative subjects, such as
  `feat(auth): add expiring server sessions`.
- Commit and PR text describes only the code, rationale, tests, and follow-ups in an
  ordinary engineering voice. Do not use process meta-language or AI attribution.
- Show the diff and commit list for review and wait for approval before merging.

## Parallel agents

- Delegate only substantial independent work, with clear file ownership, interface
  constraints, and acceptance checks. Do not split one protocol or migration change
  across writers.
- Useful boundaries are client UI versus server transport, protocol implementation
  versus independent fixtures, and separate provider integrations. The primary agent
  reviews and verifies the integrated result.
- If delegation is unavailable, continue sequentially and report that in the handoff.
