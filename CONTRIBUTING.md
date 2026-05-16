# Contributing to Neuro-Mesh

Thank you for your interest in contributing to Neuro-Mesh. This document provides guidelines and instructions for contributing.

## Development Setup

### Prerequisites

- **Compiler**: Clang 18+ or GCC 14+ (C++20 required)
- **Build tools**: `make`, `bpftool` 7.0+
- **Libraries**: OpenSSL 3.0+, libbpf, libseccomp, ONNX Runtime 1.17+
- **Python**: 3.12+ (for tooling and ML model training)
- **Optional**: Docker Compose (for integration testing)

### Quick Start

```bash
# Clone and build
git clone https://github.com/your-org/neuro-mesh.git
cd neuro-mesh
make clean && make -j$(nproc)

# Run tests
make test

# Build with sanitizers (development)
make clean && make SANITIZE=1

# Build debug (no optimization, full symbols)
make clean && make DEBUG=1
```

## Code Style

### C++ Code

- **Style**: Google C++ Style Guide (enforced by `.clang-format`)
- **Formatting**: Run `clang-format -i <file>` before committing
- **Naming**:
  - Classes/structs: `CamelCase`
  - Functions/methods: `snake_case`
  - Member variables: `m_snake_case`
  - Constants: `kSnakeCase` or `UPPER_SNAKE_CASE`
  - Namespaces: `lowercase`
- **Headers**: Include guards or `#pragma once`
- **Error handling**: Use `Result<T, E>` for recoverable errors, exceptions for fatal errors

### Python Code

- **Style**: PEP 8 (enforced by `ruff`)
- **Formatting**: `ruff format <file>`
- **Typing**: Use type hints for all function signatures
- **No `os.system()`**: Use `subprocess.run([...], check=True)`
- **No bare `except`**: Always catch specific exceptions

### Shell Scripts

- **Linting**: `shellcheck` (enforced in CI)
- **Shebang**: `#!/usr/bin/env bash`
- **Error handling**: `set -euo pipefail`

## Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `perf`, `security`

Examples:
```
fix(consensus): capture TLS connect FD return value
feat(telemetry): add JSON escaping for audit log fields
test(pbft): add equivocation detection unit test
security(enforcer): add integer overflow guard in extract_int
```

## Pull Request Process

1. **Create a branch** from `main` with a descriptive name
2. **Write tests** for new functionality
3. **Run the full test suite**: `make test`
4. **Run linters**: `make lint` (clang-tidy), `ruff check` (Python)
5. **Update documentation** if behavior changes
6. **Open a PR** with a clear description of changes

### PR Checklist

- [ ] Tests pass (`make test`)
- [ ] No new compiler warnings (`make clean && make`)
- [ ] clang-tidy passes (`make lint`)
- [ ] Python linting passes (`ruff check`)
- [ ] Commit messages follow Conventional Commits
- [ ] Documentation updated (if applicable)

## Testing

### Unit Tests

```bash
make test          # Run all unit tests
./bin/test_crypto  # Run specific test
```

### Integration Tests

```bash
# Docker-based integration test
docker compose up -d
sleep 20
./bin/inject_event --node CHARLIE --target ALPHA --event entropy_spike --verdict CRITICAL

# Run the full integration test script
bash tests/integration_test.sh
```

### Sanitizer Testing

```bash
# AddressSanitizer + UndefinedBehaviorSanitizer
make clean && make SANITIZE=1
make test

# ThreadSanitizer
make clean && make THREAD=1
make test
```

## Architecture Overview

```
kernel/sensor.bpf.c  →  cell/NodeAgent  →  cell/InferenceEngine
       ↓                      ↓                    ↓
eBPF kernel probe      Ring buffer poller    Entropy analysis
       ↓                      ↓                    ↓
consensus/MeshNode  →  consensus/PBFT  →  enforcer/PolicyEnforcer
       ↓                      ↓                    ↓
P2P UDP/TLS mesh       Byzantine consensus    iptables isolation
       ↓
telemetry/TelemetryBridge  →  Dashboard (WebSocket)
```

See `ARCHITECTURE.md` for detailed documentation.

## Adding a New Module

1. Create the header and source files in the appropriate directory
2. Add the source file to `AGENT_SRCS` in the Makefile
3. Write unit tests in `tools/test_<module>.cpp`
4. Register the test target in the Makefile
5. Update `CLAUDE.md` if the module changes the architecture

## Security Guidelines

- **Never** use `system()`, `gets()`, `strcpy()`, `strcat()`, `sprintf()`, `scanf()`
- **Never** use `os.system()`, `eval()`, `exec()` in Python
- **Always** validate input from network, files, and environment variables
- **Always** use `fork`+`exec` for external commands (never shell)
- **Always** check return values of security-critical operations
- **Never** commit secrets, keys, or credentials

## Getting Help

- **Architecture questions**: Read `CLAUDE.md` and `ARCHITECTURE.md`
- **Build issues**: Check the Makefile and prerequisites section above
- **Security concerns**: See `SECURITY.md`
