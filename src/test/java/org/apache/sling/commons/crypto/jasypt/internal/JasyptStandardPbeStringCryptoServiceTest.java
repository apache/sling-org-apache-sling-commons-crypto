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
package org.apache.sling.commons.crypto.jasypt.internal;

import java.security.Provider;
import java.security.Security;

import org.apache.commons.lang3.reflect.FieldUtils;
import org.apache.commons.lang3.reflect.MethodUtils;
import org.apache.sling.commons.crypto.PasswordProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jasypt.iv.RandomIvGenerator;
import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.jasypt.commons.CommonUtils.STRING_OUTPUT_TYPE_BASE64;
import static org.jasypt.commons.CommonUtils.STRING_OUTPUT_TYPE_HEXADECIMAL;
import static org.jasypt.encryption.pbe.StandardPBEByteEncryptor.DEFAULT_KEY_OBTENTION_ITERATIONS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class JasyptStandardPbeStringCryptoServiceTest {

    private static final String MESSAGE = "Rudy, a Message to You";

    @Test
    public void testComponentLifecycle() throws Exception {
        final PasswordProvider passwordProvider = mock(PasswordProvider.class);
        when(passwordProvider.getPassword()).thenReturn("+AQ?aDes!'DBMkrCi:FE6q\\sOn=Pbmn=PK8n=PK?".toCharArray());
        final JasyptStandardPbeStringCryptoService service = new JasyptStandardPbeStringCryptoService();
        FieldUtils.writeDeclaredField(service, "passwordProvider", passwordProvider, true);
        FieldUtils.writeDeclaredField(service, "ivGenerator", new RandomIvGenerator(), true);
        { // activate
            final JasyptStandardPbeStringCryptoServiceConfiguration configuration = mock(JasyptStandardPbeStringCryptoServiceConfiguration.class);
            when(configuration.algorithm()).thenReturn("PBEWITHHMACSHA512ANDAES_256");
            when(configuration.keyObtentionIterations()).thenReturn(DEFAULT_KEY_OBTENTION_ITERATIONS);
            when(configuration.securityProviderName()).thenReturn(null);
            when(configuration.stringOutputType()).thenReturn(STRING_OUTPUT_TYPE_BASE64);
            MethodUtils.invokeMethod(service, true, "activate", configuration);
            final String ciphertext = service.encrypt(MESSAGE);
            final String message = service.decrypt(ciphertext);
            assertThat(message, is(MESSAGE));
        }
        { // modified
            final JasyptStandardPbeStringCryptoServiceConfiguration configuration = mock(JasyptStandardPbeStringCryptoServiceConfiguration.class);
            when(configuration.algorithm()).thenReturn("PBEWITHHMACSHA512ANDAES_256");
            when(configuration.keyObtentionIterations()).thenReturn(1);
            when(configuration.securityProviderName()).thenReturn("");
            when(configuration.stringOutputType()).thenReturn(STRING_OUTPUT_TYPE_HEXADECIMAL);
            MethodUtils.invokeMethod(service, true, "modified", configuration);
            final String ciphertext = service.encrypt(MESSAGE);
            final String message = service.decrypt(ciphertext);
            assertThat(message, is(MESSAGE));
        }
        { // deactivate
            MethodUtils.invokeMethod(service, true, "deactivate");
            final String ciphertext = service.encrypt(MESSAGE);
            final String message = service.decrypt(ciphertext);
            assertThat(message, is(MESSAGE));
        }
    }

    @Test
    public void testProviderName() throws Exception {
        final Provider securityProvider = new BouncyCastleProvider();
        Security.addProvider(securityProvider);
        final PasswordProvider passwordProvider = mock(PasswordProvider.class);
        when(passwordProvider.getPassword()).thenReturn("+AQ?aDes!'DBMkrCi:FE6q\\sOn=Pbmn=PK8n=PK?".toCharArray());
        final JasyptStandardPbeStringCryptoService service = new JasyptStandardPbeStringCryptoService();
        FieldUtils.writeDeclaredField(service, "passwordProvider", passwordProvider, true);
        FieldUtils.writeDeclaredField(service, "ivGenerator", new RandomIvGenerator(), true);

        final JasyptStandardPbeStringCryptoServiceConfiguration configuration = mock(JasyptStandardPbeStringCryptoServiceConfiguration.class);
        when(configuration.algorithm()).thenReturn("PBEWITHSHA256AND128BITAES-CBC-BC");
        when(configuration.keyObtentionIterations()).thenReturn(DEFAULT_KEY_OBTENTION_ITERATIONS);
        when(configuration.securityProviderName()).thenReturn("BC");
        when(configuration.stringOutputType()).thenReturn(STRING_OUTPUT_TYPE_BASE64);
        MethodUtils.invokeMethod(service, true, "activate", configuration);
        final String ciphertext = service.encrypt(MESSAGE);
        final String message = service.decrypt(ciphertext);
        assertThat(message, is(MESSAGE));
    }

    @Test
    public void testProvider() throws Exception {
        final Provider securityProvider = new BouncyCastleProvider();
        final PasswordProvider passwordProvider = mock(PasswordProvider.class);
        when(passwordProvider.getPassword()).thenReturn("+AQ?aDes!'DBMkrCi:FE6q\\sOn=Pbmn=PK8n=PK?".toCharArray());
        final JasyptStandardPbeStringCryptoService service = new JasyptStandardPbeStringCryptoService();
        FieldUtils.writeDeclaredField(service, "passwordProvider", passwordProvider, true);
        FieldUtils.writeDeclaredField(service, "ivGenerator", new RandomIvGenerator(), true);
        FieldUtils.writeDeclaredField(service, "securityProvider", securityProvider, true);

        final JasyptStandardPbeStringCryptoServiceConfiguration configuration = mock(JasyptStandardPbeStringCryptoServiceConfiguration.class);
        when(configuration.algorithm()).thenReturn("PBEWITHSHA256AND128BITAES-CBC-BC");
        when(configuration.keyObtentionIterations()).thenReturn(DEFAULT_KEY_OBTENTION_ITERATIONS);
        when(configuration.securityProviderName()).thenReturn(null);
        when(configuration.stringOutputType()).thenReturn(STRING_OUTPUT_TYPE_BASE64);
        MethodUtils.invokeMethod(service, true, "activate", configuration);
        final String ciphertext = service.encrypt(MESSAGE);
        final String message = service.decrypt(ciphertext);
        assertThat(message, is(MESSAGE));
    }

}
