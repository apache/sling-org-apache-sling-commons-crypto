/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sling.commons.crypto.it.tests;

import org.apache.sling.testing.paxexam.TestSupport;
import org.ops4j.pax.exam.options.ModifiableCompositeOption;

import static org.apache.sling.testing.paxexam.SlingOptions.paxUrlWrap;
import static org.apache.sling.testing.paxexam.SlingOptions.scr;
import static org.ops4j.pax.exam.CoreOptions.composite;
import static org.ops4j.pax.exam.CoreOptions.junitBundles;
import static org.ops4j.pax.exam.CoreOptions.mavenBundle;
import static org.ops4j.pax.exam.CoreOptions.wrappedBundle;

public abstract class CryptoTestSupport extends TestSupport {

    public ModifiableCompositeOption baseConfiguration() {
        return composite(
            super.baseConfiguration(),
            // Sling Commons Crypto
            testBundle("bundle.filename"),
            mavenBundle().groupId("org.apache.commons").artifactId("commons-lang3").versionAsInProject(),
            scr(),
            // testing
            junitBundles(),
            paxUrlWrap(),
            wrappedBundle(mavenBundle().groupId("com.google.truth").artifactId("truth").versionAsInProject()),
            mavenBundle().groupId("com.google.guava").artifactId("guava").versionAsInProject(),
            mavenBundle().groupId("com.google.guava").artifactId("failureaccess").versionAsInProject(),
            mavenBundle().groupId("com.googlecode.java-diff-utils").artifactId("diffutils").versionAsInProject(),
            vmOption(System.getProperty("jacoco.command"))
        );
    }

}
