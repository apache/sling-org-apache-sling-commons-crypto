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

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

import org.apache.sling.commons.crypto.PasswordProvider;
import org.apache.sling.commons.crypto.SaltProvider;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static com.google.common.truth.Truth.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class PBESecretKeyProviderTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void testMissingConfiguration() {
        final PBESecretKeyProvider provider = new PBESecretKeyProvider();
        exception.expect(NullPointerException.class);
        exception.expectMessage("Configuration must not be null");
        provider.getSecretKey();
    }

    @Test
    public void testInvalidAlgorithm() throws NoSuchAlgorithmException {
        final PBESecretKeyProvider provider = new PBESecretKeyProvider();
        final PBESecretKeyProviderConfiguration configuration = mock(PBESecretKeyProviderConfiguration.class);
        when(configuration.algorithm()).thenReturn("Invalid");
        exception.expect(NoSuchAlgorithmException.class);
        provider.activate(configuration);
    }

    @Test
    public void testInvalidKeySpec() throws NoSuchAlgorithmException {
        final PasswordProvider passwordProvider = mock(PasswordProvider.class);
        when(passwordProvider.getPassword()).thenReturn("+AQ?aDes!'DBMkrCi:FE6q\\sOn=Pbmn=PK8n=PK?".toCharArray());
        final SaltProvider saltProvider = mock(SaltProvider.class);
        when(saltProvider.getSalt()).thenReturn("CAFEBABECAFEDEAD".getBytes(StandardCharsets.UTF_8));
        final PBESecretKeyProvider provider = new PBESecretKeyProvider();
        provider.passwordProvider = passwordProvider;
        provider.saltProvider = saltProvider;

        final PBESecretKeyProviderConfiguration configuration = mock(PBESecretKeyProviderConfiguration.class);
        when(configuration.algorithm()).thenReturn("PBKDF2WithHmacSHA1");
        when(configuration.iterationCount()).thenReturn(-1);
        when(configuration.keyLength()).thenReturn(-1);
        provider.activate(configuration);

        exception.expect(IllegalArgumentException.class);
        provider.getSecretKey();
    }

    @Test
    public void testComponentLifecycle() throws NoSuchAlgorithmException {
        final PasswordProvider passwordProvider = mock(PasswordProvider.class);
        when(passwordProvider.getPassword()).thenReturn("+AQ?aDes!'DBMkrCi:FE6q\\sOn=Pbmn=PK8n=PK?".toCharArray());
        final SaltProvider saltProvider = mock(SaltProvider.class);
        when(saltProvider.getSalt()).thenReturn("CAFEBABECAFEDEAD".getBytes(StandardCharsets.UTF_8));
        final PBESecretKeyProvider provider = new PBESecretKeyProvider();
        provider.passwordProvider = passwordProvider;
        provider.saltProvider = saltProvider;
        { // activate
            final PBESecretKeyProviderConfiguration configuration = mock(PBESecretKeyProviderConfiguration.class);
            when(configuration.algorithm()).thenReturn("PBKDF2WithHmacSHA1");
            when(configuration.iterationCount()).thenReturn(1024);
            when(configuration.keyLength()).thenReturn(128);
            provider.activate(configuration);
            assertThat(provider.getSecretKey().getAlgorithm()).isEqualTo("PBKDF2WithHmacSHA1");
        }
        { // modified
            final PBESecretKeyProviderConfiguration configuration = mock(PBESecretKeyProviderConfiguration.class);
            when(configuration.algorithm()).thenReturn("PBKDF2WithHmacSHA256");
            when(configuration.iterationCount()).thenReturn(2048);
            when(configuration.keyLength()).thenReturn(256);
            provider.modified(configuration);
            assertThat(provider.getSecretKey().getAlgorithm()).isEqualTo("PBKDF2WithHmacSHA256");
        }
        { // deactivate
            provider.deactivate();
            assertThat(provider.getSecretKey().getAlgorithm()).isEqualTo("PBKDF2WithHmacSHA256");
        }
    }

}
