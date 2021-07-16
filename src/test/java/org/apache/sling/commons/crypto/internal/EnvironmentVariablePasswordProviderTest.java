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
package org.apache.sling.commons.crypto.internal;

import org.apache.commons.lang3.reflect.MethodUtils;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static com.github.stefanbirkner.systemlambda.SystemLambda.withEnvironmentVariable;
import static com.google.common.truth.Truth.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class EnvironmentVariablePasswordProviderTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void testMissingConfiguration() {
        final EnvironmentVariablePasswordProvider provider = new EnvironmentVariablePasswordProvider();
        exception.expect(NullPointerException.class);
        exception.expectMessage("Configuration must not be null");
        provider.getPassword();
    }

    @Test
    public void testComponentLifecycle() throws Exception {
        final EnvironmentVariablePasswordProvider provider = new EnvironmentVariablePasswordProvider();
        { // activate
            final EnvironmentVariablePasswordProviderConfiguration configuration = mock(EnvironmentVariablePasswordProviderConfiguration.class);
            when(configuration.name()).thenReturn("password_ascii85");
            MethodUtils.invokeMethod(provider, true, "activate", configuration);
            final char[] password = withEnvironmentVariable("password_ascii85", "+AQ?aDes!'DBMkrCi:FE6q\\sOn=Pbmn=PK8n=PK?").execute(provider::getPassword);
            assertThat(password).isEqualTo("+AQ?aDes!'DBMkrCi:FE6q\\sOn=Pbmn=PK8n=PK?".toCharArray());
        }
        { // modified
            final EnvironmentVariablePasswordProviderConfiguration configuration = mock(EnvironmentVariablePasswordProviderConfiguration.class);
            when(configuration.name()).thenReturn("password_utf8");
            MethodUtils.invokeMethod(provider, true, "modified", configuration);
            final char[] password = withEnvironmentVariable("password_utf8", " Napøleøn Sølø (DK) 🏁🇩🇰").execute(provider::getPassword);
            assertThat(password).isEqualTo(" Napøleøn Sølø (DK) 🏁🇩🇰".toCharArray());
        }
        { // deactivate
            MethodUtils.invokeMethod(provider, true, "deactivate");
            final char[] password = withEnvironmentVariable("password_utf8", " Napøleøn Sølø (DK) 🏁🇩🇰").execute(provider::getPassword);
            assertThat(password).isEqualTo(" Napøleøn Sølø (DK) 🏁🇩🇰".toCharArray());
        }
    }

}
