# Project Overview

Apache Sling Commons Crypto is an OSGi bundle that provides a pluggable encryption/decryption API for Apache Sling applications. The public API consists of four service interfaces (`CryptoService`, `PasswordProvider`, `SaltProvider`, `SecretKeyProvider`) in `org.apache.sling.commons.crypto`. Implementations live in sub-packages under `internal` and use OSGi Declarative Services R7 annotations. The Jasypt library provides the primary `CryptoService` implementation (`JasyptStandardPbeStringCryptoService`). An optional Felix Web Console plugin (`EncryptWebConsolePlugin`) is included for manual encryption in dev environments. Jasypt and servlet packages are dynamically imported in `bnd.bnd` so the bundle deploys without them if unused.

# Core Commands

- **Build**: `mvn clean install`
- **Build (skip tests)**: `mvn clean install -DskipTests`
- **Run all tests**: `mvn verify`
- **Run unit tests only**: `mvn test`
- **Run integration tests only**: `mvn failsafe:integration-test failsafe:verify`
- **Run a single unit test class**: `mvn test -Dtest=FilePasswordProviderTest`
- **Run a single IT class**: `mvn verify -Dit.test=FilePasswordProviderIT`
- **Checkstyle**: checked automatically during `validate` phase; run explicitly with `mvn checkstyle:check`
- **PMD**: `mvn pmd:check`
- **SpotBugs**: `mvn spotbugs:check`
- **All static analysis** runs as part of `mvn verify`

No dev server — this is a library bundle deployed into an OSGi container.

# Project Layout

```
pom.xml                        Maven build; Java 17; sling-bundle-parent
bnd.bnd                        OSGi bundle metadata and dynamic import directives
checkstyle-suppressions.xml    Checkstyle suppression rules
pmd-exclude.properties         PMD exclusions
spotbugs-exclude.xml           SpotBugs exclusions
src/
  main/java/org/apache/sling/commons/crypto/
    CryptoService.java         Public API: encrypt/decrypt
    PasswordProvider.java      Public API: supply passwords
    SaltProvider.java          Public API: supply salts
    SecretKeyProvider.java     Public API: supply secret keys
    internal/                  Core implementations (PasswordProvider, SaltProvider, SecretKeyProvider)
    jasypt/internal/           Jasypt-based CryptoService + registrar components
    webconsole/internal/       Felix Web Console plugin for manual encryption
  test/java/org/apache/sling/commons/crypto/
    internal/                  JUnit 4 unit tests (Mockito + Hamcrest)
    jasypt/internal/           Unit tests for Jasypt components
    webconsole/internal/       Unit tests for Web Console plugin
    it/tests/                  Pax Exam OSGi integration tests (*IT.java)
  test/resources/              Password fixture files used by file-based provider tests
```

# Development Patterns & Constraints

- **Java 17**, 4-space indentation, Apache license header on every file.
- All internal implementation classes go under an `internal` sub-package; never reference `internal` types from the public API.
- OSGi components use `org.osgi.service.component.annotations` (`@Component`, `@Activate`, `@Modified`, `@Deactivate`, `@Reference`). Do not use legacy Felix SCR annotations.
- `@NotNull` / `@Nullable` from `org.jetbrains.annotations` for nullability contracts.
- Companion `*Configuration` annotation interface (OSGi metatype) for every `@Component` that exposes configuration.
- `package-info.java` with `@Version` must exist for every exported package.
- Dynamic imports in `bnd.bnd` are intentional — do not add static `Import-Package` entries for Jasypt or servlet APIs.
- Checkstyle, PMD, and SpotBugs are enforced at build time; suppressions require a corresponding entry in the respective XML/properties file.
- The `--add-opens java.base/java.util=ALL-UNNAMED` JVM arg is applied to Surefire via the `jpms` profile (active by default).

# Git Workflow

- Follow the [Apache Sling contribution guide](https://sling.apache.org/contributing.html).
- Upstream is the Apache Gitbox mirror; GitHub PRs are accepted.
- Commit message: short imperative summary (≤72 chars), reference a Jira issue (`SLING-XXXXX`) where applicable.
- Branches: `feature/SLING-XXXXX-short-description` or `fix/SLING-XXXXX-short-description`.
- Sign off commits per ASF policy. Include `Co-authored-by` trailers when applicable.

# Testing Guidelines

- **Unit tests**: JUnit 4, Mockito, Hamcrest. File naming: `*Test.java`. Placed under `src/test/java` mirroring the `src/main/java` package structure.
- **Integration tests**: Pax Exam 4 with forked OSGi container. File naming: `*IT.java`. Placed under `src/test/java/.../it/tests/`. Run via `maven-failsafe-plugin`.
- Prefer unit tests for logic; use ITs only to verify OSGi wiring and component lifecycle.
- Test resources (password files, etc.) go under `src/test/resources/`.
- No explicit coverage tool configured; coverage is not enforced at build time.

# Gotchas

- **ITs require a full `mvn verify`** — running `mvn test` alone skips all `*IT.java` tests.
- Jasypt and servlet packages are `resolution:=dynamic` in `bnd.bnd`. Tests that exercise Jasypt paths need the Jasypt bundles provisioned in the Pax Exam container (see `JasyptCryptoTestSupport`).
- The `jpms` profile is active by default and adds `--add-opens` to Surefire; removing it breaks reflection-based tests on Java 17+.
- `FilePasswordProvider` trims trailing newlines from password files — test fixtures in `src/test/resources/` include edge-case variants (`password.ascii85_newline`, `password.ascii85_newlines`).
- Static analysis phases (`checkstyle`, `pmd`, `spotbugs`) run during `validate`/`process-classes`, so a `mvn compile` failure may surface linting errors before compilation errors.
