[![Apache Sling](https://sling.apache.org/res/logos/sling.png)](https://sling.apache.org)

&#32;[![Build Status](https://ci-builds.apache.org/job/Sling/job/modules/job/sling-org-apache-sling-commons-crypto/job/master/badge/icon)](https://ci-builds.apache.org/job/Sling/job/modules/job/sling-org-apache-sling-commons-crypto/job/master/)&#32;[![Test Status](https://img.shields.io/jenkins/tests.svg?jobUrl=https://ci-builds.apache.org/job/Sling/job/modules/job/sling-org-apache-sling-commons-crypto/job/master/)](https://ci-builds.apache.org/job/Sling/job/modules/job/sling-org-apache-sling-commons-crypto/job/master/test/?width=800&height=600)&#32;[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=apache_sling-org-apache-sling-commons-crypto&metric=coverage)](https://sonarcloud.io/dashboard?id=apache_sling-org-apache-sling-commons-crypto)&#32;[![Sonarcloud Status](https://sonarcloud.io/api/project_badges/measure?project=apache_sling-org-apache-sling-commons-crypto&metric=alert_status)](https://sonarcloud.io/dashboard?id=apache_sling-org-apache-sling-commons-crypto)&#32;[![JavaDoc](https://www.javadoc.io/badge/org.apache.sling/org.apache.sling.commons.crypto.svg)](https://www.javadoc.io/doc/org.apache.sling/org.apache.sling.commons.crypto)&#32;[![Maven Central](https://maven-badges.herokuapp.com/maven-central/org.apache.sling/org.apache.sling.commons.crypto/badge.svg)](https://search.maven.org/#search%7Cga%7C1%7Cg%3A%22org.apache.sling%22%20a%3A%22org.apache.sling.commons.crypto%22) [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

# Apache Sling Commons Crypto

This module is part of the [Apache Sling](https://sling.apache.org) project.

This module provides a simple crypto API and OSGi service contracts:

- `CryptoService`
- `PasswordProvider`
- `SaltProvider`
- `SecretKeyProvider`

The default implementation is extensible and optional, based on [Jasypt](https://github.com/jasypt/jasypt). The bundle also includes an optional Felix Web Console plugin (`sling-commons-crypto-encrypt`) for manual message encryption.

## Build and test

- Build: `mvn clean install`
- Build without tests: `mvn clean install -DskipTests`
- Run unit tests: `mvn test`
- Run all verification (unit tests, integration tests, checkstyle, PMD, SpotBugs): `mvn verify`
- Run integration tests only: `mvn failsafe:integration-test failsafe:verify`

## Runtime and implementation notes

- Java baseline: **17**
- OSGi Declarative Services (R7 annotations) are used throughout implementations.
- Jasypt and servlet packages are imported dynamically in `bnd.bnd`, so the bundle can be deployed even when those optional dependencies are not present.
- The Web Console plugin is compatible with HTTP Whiteboard-based Web Console setups.

## Source layout

- Public API: `src/main/java/org/apache/sling/commons/crypto/`
- Core providers: `src/main/java/org/apache/sling/commons/crypto/internal/`
- Jasypt-based implementation: `src/main/java/org/apache/sling/commons/crypto/jasypt/internal/`
- Web Console plugin: `src/main/java/org/apache/sling/commons/crypto/webconsole/internal/`
- Unit tests: `src/test/java/.../*Test.java`
- Integration tests (Pax Exam): `src/test/java/org/apache/sling/commons/crypto/it/tests/**/*IT.java`

See [Sling's documentation for Commons Crypto](https://sling.apache.org/documentation/bundles/commons-crypto.html) for usage and configuration details.
