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

import javax.inject.Inject;

import org.apache.sling.commons.crypto.PasswordProvider;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ops4j.pax.exam.Configuration;
import org.ops4j.pax.exam.Option;
import org.ops4j.pax.exam.junit.PaxExam;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerClass;
import org.ops4j.pax.exam.util.Filter;

import static com.github.stefanbirkner.systemlambda.SystemLambda.withEnvironmentVariable;
import static com.google.common.truth.Truth.assertThat;
import static org.ops4j.pax.exam.CoreOptions.mavenBundle;
import static org.ops4j.pax.exam.CoreOptions.options;
import static org.ops4j.pax.exam.CoreOptions.wrappedBundle;
import static org.ops4j.pax.exam.cm.ConfigurationAdminOptions.factoryConfiguration;

@RunWith(PaxExam.class)
@ExamReactorStrategy(PerClass.class)
public class EnvironmentVariablePasswordProviderIT extends CryptoTestSupport {

    private static final String ENVIRONMENT_VARIABLE_NAME = "SLING_CRYPTO_PASSWORD";

    private static final String ENVIRONMENT_VARIABLE_VALUE = " Napøleøn Sølø (DK) \uD83C\uDFC1\uD83C\uDDE9\uD83C\uDDF0";

    @Inject
    @Filter(value = "(names=environment)")
    private PasswordProvider passwordProvider;

    @Configuration
    public Option[] configuration() {
        return options(
            baseConfiguration(),
            wrappedBundle(mavenBundle().groupId("com.github.stefanbirkner").artifactId("system-lambda").versionAsInProject()),
            factoryConfiguration("org.apache.sling.commons.crypto.internal.EnvironmentVariablePasswordProvider")
                .put("names", new String[]{"environment"})
                .put("name", ENVIRONMENT_VARIABLE_NAME)
                .asOption()
        );
    }

    @Test
    public void testPasswordProvider() {
        assertThat(passwordProvider).isNotNull();
    }

    @Test
    public void testPassword() throws Exception {
        final char[] password = withEnvironmentVariable(ENVIRONMENT_VARIABLE_NAME, ENVIRONMENT_VARIABLE_VALUE)
            .execute(() ->
                passwordProvider.getPassword()
            );
        assertThat(password).isEqualTo(ENVIRONMENT_VARIABLE_VALUE.toCharArray());
    }

    @Test(expected = RuntimeException.class)
    public void testEnvironmentVariableNotSet() throws Exception {
        passwordProvider.getPassword();
    }

}