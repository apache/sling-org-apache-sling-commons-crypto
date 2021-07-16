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

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.lang3.reflect.MethodUtils;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static com.google.common.truth.Truth.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SecureRandomSaltProviderTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void testMissingConfiguration() throws IOException, NoSuchAlgorithmException {
        final SecureRandomSaltProvider provider = new SecureRandomSaltProvider();
        exception.expect(NullPointerException.class);
        exception.expectMessage("Configuration must not be null");
        provider.getSalt();
    }

    @Test
    public void testComponentLifecycle() throws Exception {
        final SecureRandomSaltProvider provider = new SecureRandomSaltProvider();
        { // activate
            final SecureRandomSaltProviderConfiguration configuration = mock(SecureRandomSaltProviderConfiguration.class);
            when(configuration.algorithm()).thenReturn("SHA1PRNG");
            when(configuration.keyLength()).thenReturn(8);
            MethodUtils.invokeMethod(provider, true, "activate", configuration);
            assertThat(provider.getSalt()).hasLength(8);
        }
        { // modified
            final SecureRandomSaltProviderConfiguration configuration = mock(SecureRandomSaltProviderConfiguration.class);
            when(configuration.algorithm()).thenReturn("SHA1PRNG");
            when(configuration.keyLength()).thenReturn(16);
            MethodUtils.invokeMethod(provider, true, "modified", configuration);
            assertThat(provider.getSalt()).hasLength(16);
        }
        { // deactivate
            MethodUtils.invokeMethod(provider, true, "deactivate");
            assertThat(provider.getSalt()).hasLength(16);
        }
    }

}
