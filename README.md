[![Apache Sling](https://sling.apache.org/res/logos/sling.png)](https://sling.apache.org)

&#32;[![Build Status](https://ci-builds.apache.org/job/Sling/job/modules/job/sling-org-apache-sling-commons-crypto/job/master/badge/icon)](https://ci-builds.apache.org/job/Sling/job/modules/job/sling-org-apache-sling-commons-crypto/job/master/)&#32;[![Test Status](https://img.shields.io/jenkins/tests.svg?jobUrl=https://ci-builds.apache.org/job/Sling/job/modules/job/sling-org-apache-sling-commons-crypto/job/master/)](https://ci-builds.apache.org/job/Sling/job/modules/job/sling-org-apache-sling-commons-crypto/job/master/test/?width=800&height=600)&#32;[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=apache_sling-org-apache-sling-commons-crypto&metric=coverage)](https://sonarcloud.io/dashboard?id=apache_sling-org-apache-sling-commons-crypto)&#32;[![Sonarcloud Status](https://sonarcloud.io/api/project_badges/measure?project=apache_sling-org-apache-sling-commons-crypto&metric=alert_status)](https://sonarcloud.io/dashboard?id=apache_sling-org-apache-sling-commons-crypto)&#32;[![JavaDoc](https://www.javadoc.io/badge/org.apache.sling/org.apache.sling.commons.crypto.svg)](https://www.javadoc.io/doc/org.apache.sling/org.apache.sling.commons.crypto)&#32;[![Maven Central](https://maven-badges.herokuapp.com/maven-central/org.apache.sling/org.apache.sling.commons.crypto/badge.svg)](https://search.maven.org/#search%7Cga%7C1%7Cg%3A%22org.apache.sling%22%20a%3A%22org.apache.sling.commons.crypto%22) [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

# Apache Sling Commons Crypto

This module is part of the [Apache Sling](https://sling.apache.org) project.

This module contains a simple crypto API and two implementations:

- A [Java Cryptographic Architecture(JCA)](https://docs.oracle.com/en/java/javase/11/security/java-cryptography-architecture-jca-reference-guide.html) based one
- A **deprecated** one based on the no longer maintained library [Jasypt](https://github.com/jasypt/jasypt). **It is strongly recommended to migrate to the JCA one with a strong cipher**.

In addition it exposes two plugin for Felix Web Console:

1. To encrypt messages
2. To list all registered JCA algorithms of all registered JCA providers

See [Sling's documentation for Commons Crypto](https://sling.apache.org/documentation/bundles/commons-crypto.html) for details.
