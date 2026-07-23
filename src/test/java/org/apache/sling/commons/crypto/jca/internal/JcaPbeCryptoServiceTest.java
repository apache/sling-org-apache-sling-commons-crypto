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
package org.apache.sling.commons.crypto.jca.internal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import javax.crypto.NoSuchPaddingException;

import org.apache.sling.commons.crypto.PasswordProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;
import org.osgi.util.converter.Converters;

public class JcaPbeCryptoServiceTest {

    private static final String MESSAGE = "Rudy, a Message to You üøoøøt";

    private PasswordProvider passwordProvider;
    private byte[] salt;

    @Before
    public void setUp() {
        passwordProvider = mock(PasswordProvider.class);
        when(passwordProvider.getPassword()).thenReturn("+AQ?aDes!'DBMkrCi:FE6q\\sOn=Pbmn=PK8n=PK?".toCharArray());
        salt = new byte[16];
        Random random = new Random();
        random.nextBytes(salt);
    }

    @Test
    public void testCryptoRoundtrip() throws Exception {
        Map<String, Object> properties = new HashMap<>();
        JcaPbeCryptoServiceConfiguration configuration = Converters.standardConverter().convert(properties).to(JcaPbeCryptoServiceConfiguration.class);
        final JcaPbeCryptoService service = new JcaPbeCryptoService(configuration, salt, passwordProvider);
        final String ciphertext = service.encrypt(MESSAGE);
        final String message = service.decrypt(ciphertext);
        assertEquals(MESSAGE, message);
    }

    @Test
    public void testCryptoRoundtripWithDifferentCryptoServices() throws Exception {
        Map<String, Object> properties = new HashMap<>();
        JcaPbeCryptoServiceConfiguration configuration = Converters.standardConverter().convert(properties).to(JcaPbeCryptoServiceConfiguration.class);
        final JcaPbeCryptoService service = new JcaPbeCryptoService(configuration, salt, passwordProvider);
        final String ciphertext = service.encrypt(MESSAGE);
        // must be same salt
        final JcaPbeCryptoService service2 = new JcaPbeCryptoService(configuration, salt, passwordProvider);
        final String message = service2.decrypt(ciphertext);
        assertEquals(MESSAGE, message);
        // now use different salt, should fail
        new Random().nextBytes(salt);
        final JcaPbeCryptoService service3 = new JcaPbeCryptoService(configuration, salt, passwordProvider);
        assertThrows(IllegalArgumentException.class, () -> service3.decrypt(ciphertext));
    }

    @Test
    public void testSameMessageDifferentCipher() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidParameterSpecException, InvalidKeySpecException {
        Map<String, Object> properties = new HashMap<>();
        JcaPbeCryptoServiceConfiguration configuration = Converters.standardConverter().convert(properties).to(JcaPbeCryptoServiceConfiguration.class);
        final JcaPbeCryptoService service = new JcaPbeCryptoService(configuration, salt, passwordProvider);
        final String ciphertext1 = service.encrypt(MESSAGE);
        final String ciphertext2 = service.encrypt(MESSAGE);
        assertEquals(MESSAGE, service.decrypt(ciphertext1));
        assertEquals(MESSAGE, service.decrypt(ciphertext2));
        // The ciphertexts should be different due to the use of a random IV
        assert(!ciphertext1.equals(ciphertext2));
    }

    @Test
    public void testCryptoRoundtripWithBouncycastle() throws Exception {
        // register BouncyCastle provider
        Security.addProvider(new BouncyCastleProvider());
        Map<String, Object> properties = new HashMap<>();
        properties.put("securityProviderName", "BC");
        JcaPbeCryptoServiceConfiguration configuration = Converters.standardConverter().convert(properties).to(JcaPbeCryptoServiceConfiguration.class);
        final JcaPbeCryptoService service = new JcaPbeCryptoService(configuration, salt, passwordProvider);
        final String ciphertext = service.encrypt(MESSAGE);
        final String message = service.decrypt(ciphertext);
        assertEquals(MESSAGE, message);
    }

}
