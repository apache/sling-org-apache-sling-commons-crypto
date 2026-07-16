# Security

<!-- sling-security-default:start -->
The threat model for this project is https://github.com/apache/sling/blob/master/docs/threat-model.md .
<!-- sling-security-default:end -->

## Project overview

This repository contains the Apache Sling Commons Crypto bundle:

- Public crypto APIs in `src/main/java/org/apache/sling/commons/crypto`
- Optional Jasypt-based implementation in `src/main/java/org/apache/sling/commons/crypto/jasypt/internal`
- Web Console encryption plugin in `src/main/java/org/apache/sling/commons/crypto/webconsole/internal`

## Build and test

Use Maven for all build and test workflows.

- Full build and verification: `mvn clean verify`
- Unit tests only: `mvn test`
- Integration tests run via Failsafe during `verify` (`integration-test` + `verify` goals)

## Runtime and build conventions

- Java version: 17 (`sling.java.version`)
- Parent POM: `org.apache.sling:sling-bundle-parent:66`
- OSGi bundle metadata is managed with `bnd-maven-plugin` and `bnd.bnd`
- JPMS-related test JVM argument is configured in the default-active `jpms` profile:
  `--add-opens java.base/java.util=ALL-UNNAMED`

## Key dependencies and tooling

- Optional runtime crypto backend: `org.apache.servicemix.bundles.jasypt`
- OSGi annotations/components from `org.osgi.*`
- Test/runtime support includes Pax Exam, Felix framework/HTTP/Web Console, and Bouncy Castle (test scope)
- Static analysis and quality plugins: Checkstyle, PMD, SpotBugs (+ FindSecBugs), RAT
