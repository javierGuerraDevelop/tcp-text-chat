# tcp-text-chat

A C++20 desktop text chat project with a Qt 6 client, a headless server, TLS
transport, and SQLite persistence. The first release provides one shared room,
username/password accounts, and Google/GitHub sign-in. The current targets establish
the common, client, server, and test build boundaries.

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
sudo dnf install cmake ninja-build gcc-c++ clang clang-tools-extra qt6-qtbase-devel qt6-qtnetworkauth-devel libsodium-devel
```

The OAuth implementation requires Qt NetworkAuth; the build foundation itself uses
only Qt Core, Gui, Widgets, and Test.

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

## Security and configuration

TLS private keys, OAuth client secrets, session tokens, local databases, and `.env`
files must never be committed. Production OAuth secrets belong only in server-side
environment or secret-store configuration. Non-production TLS fixtures must be
clearly isolated from deployment configuration.

## License

This project is licensed under the GNU General Public License version 2. See
`LICENSE` for the full text.
