# AGENTS.md — Project Guidelines for AI Agents

## Project Overview
**Passman** is a secure CLI password manager written in Go. It stores passwords in local JSON files, encrypted with AES-256-CBC. Master passwords are hashed using SHA-256.

## Tech Stack
- **Language**: Go 1.23+
- **Module**: `github.com/kapralovs/passman`
- **Dependencies**: `golang.org/x/term` (secure password input)
- **Build Tool**: Makefile (`make build`, `make test`, etc.)

## Architecture
Passman follows **Clean Architecture** principles. Dependencies point inward.

```
cmd/passman/main.go          # Entry point (frameworks/drivers)
       │
internal/app/                # Orchestration (DI, App.Run)
       │
internal/controllers/        # Adapters (CLI args -> use cases)
       │
internal/usecase/            # Business logic (interfaces + cases)
       │
internal/repository/         # Storage interfaces & implementations
internal/crypto/             # Encryption/Decryption interfaces & impl
       │
internal/entities/           # Pure data structures
```

### Key Rules
- **Dependency Rule**: Outer layers depend on inner layers via interfaces.
- **No Global State**: Use Dependency Injection (DI) via constructors.
- **Interfaces**: Defined in the consumer package (Near Client Pattern).

## Project Structure
```
cmd/passman/main.go          # Entry point
internal/
  app/                       # App struct, Run() method
  config/                    # Config loading
  controllers/               # CLI handling, UseCases struct
  crypto/                    # AES-256-CBC implementation
  entities/                  # UserData, PasswordEntry structs
  repository/                # File storage, Vault, Session repos
  session/                   # Session entity
  usecase/                   # Business logic (Init, SignUp, Login, Add, Get, Update)
```

## Quick Start
Use `make` commands for common tasks:
- `make build` — Compile binary
- `make test` — Run all tests
- `make vet` — Static analysis
- `make clean` — Remove binary
- `make run ARGS="..."` — Build and run with arguments

## Development Guidelines
1. **Naming**: camelCase for internal, PascalCase for exported.
2. **DI**: Inject dependencies via constructors. No globals.
3. **Error Handling**: Return `error`, do not panic.
4. **Testing**: Write tests for new logic. Place in `_test.go` files.
5. **Comments**: Rare, focus on "why", not "what".

## Security
- **Encryption**: AES-256-CBC with PKCS7 padding. Random IV per entry.
- **Hashing**: SHA-256 for master password (TODO: migrate to bcrypt/scrypt).
- **File Permissions**: `0600` for sensitive files.
- **No Secrets**: Never log or commit keys/passwords.

## Adding a New Command (Pattern)
When adding a new feature (e.g., `update` command), follow this pattern:

1. **Use Case**: Create `internal/usecase/new_feature.go`
   - Define struct with dependencies (`VaultRepo`, `Crypto`, etc.)
   - Implement `Execute(sess, args...)` method
   - Validate session TTL
   - Perform business logic
   - Return updated data or error

2. **Controller**: Update `internal/controllers/controller.go`
   - Add use case to `UseCases` struct
   - Add case to `Execute` switch
   - Implement `handleNewFeature` method
   - Parse flags, load session, call use case, save vault

3. **DI**: Update `internal/app/app.go`
   - Instantiate new use case
   - Pass to `NewController`

4. **Tests**: Add tests in `internal/usecase/new_feature_test.go`

5. **Verify**: Run `make test` and `make vet`

## What NOT to Touch
- **`internal/entities/`**: Do not modify data structures without explicit request.
- **`internal/repository/` interfaces**: Do not change method signatures without planning.
- **`internal/crypto/`**: Core encryption logic is stable.
- **`Makefile`**: Unless adding new build targets.
