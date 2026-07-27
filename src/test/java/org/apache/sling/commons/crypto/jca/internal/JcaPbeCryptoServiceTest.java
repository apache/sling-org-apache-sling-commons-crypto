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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
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
import java.util.stream.Stream;

import javax.crypto.NoSuchPaddingException;

import org.apache.sling.commons.crypto.PasswordProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.Parameter;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.osgi.util.converter.Converters;

@ParameterizedClass(name="{index} => {0}")
@MethodSource("provideAlgorithms")
class JcaPbeCryptoServiceTest {

    // returns a stream of each 4 parameters: name, providerName, secretKeyFactoryAlgorithm, cipherAlgorithm
    private static Stream<Arguments> provideAlgorithms() {
        return Stream.of(
          Arguments.of("Default (PBKDF2 with AES cipher)", "", "", ""), // empty means default algorithms
          Arguments.of("PBES1 (PBEWithMD5AndDES)", "", "PBEWithMD5AndDES", "PBEWithMD5AndDES"),
          Arguments.of("PBES2 (PBEWithHmacSHA256AndAES_128)", "", "PBEWithHmacSHA256AndAES_128", "PBEWithHmacSHA256AndAES_128"),
          Arguments.of("BC: (PBKDF2 with ChaCha20)", "BC", "PBKDF2", "CHACHA20-POLY1305")
          // Arguments.of("BC: SCRIPT with BLOWFISH", "BC", "SCRYPT", "BLOWFISH"), fails as requiring ScryptKeySpec
          // Arguments.of("BC: ARGON2 with BLOWFISH", "BC", "ARGON2", "BLOWFISH"), fails as requiring Argon2KeySpec
        );
    }

    @Parameter(0)
    String name;

    @Parameter(1)
    String providerName;

    @Parameter(2)
    String secretKeyFactoryAlgorithm;
    
    @Parameter(3)
    String cipherAlgorithm;

    private static final String MESSAGE = "Rudy, a Message to You üøoøøt";

    private PasswordProvider passwordProvider;
    private byte[] salt;
    private JcaPbeCryptoServiceConfiguration configuration;
    private JcaPbeCryptoService service;

    @BeforeEach
    void setUp() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidParameterSpecException, InvalidKeySpecException {
        passwordProvider = mock(PasswordProvider.class);
        when(passwordProvider.getPassword()).thenReturn("+AQ?aDes!'DBMkrCi:FE6q\\sOn=Pbmn=PK8n=PK?".toCharArray());
        salt = new byte[16];
        Random random = new Random();
        random.nextBytes(salt);
        Map<String, Object> properties = new HashMap<>();
        if (!providerName.isEmpty()) {
            properties.put("securityProviderName", providerName);
            if (providerName.equals("BC") && Security.getProvider("BC") == null) {
                Security.addProvider(new BouncyCastleProvider());
            }
        }
        if (!secretKeyFactoryAlgorithm.isEmpty()) {
            properties.put("secretKeyFactoryAlgorithm", secretKeyFactoryAlgorithm);
        }
        if (!cipherAlgorithm.isEmpty()) {
            properties.put("cipherAlgorithm", cipherAlgorithm);
        }
        configuration = Converters.standardConverter().convert(properties).to(JcaPbeCryptoServiceConfiguration.class);
        service = new JcaPbeCryptoService(configuration, salt, passwordProvider);
    }

    @Test
    void testCryptoRoundtrip() {
        final String ciphertext = service.encrypt(MESSAGE);
        final String message = service.decrypt(ciphertext);
        assertEquals(MESSAGE, message);
    }

    @Test
    void testCryptoRoundtripWithCryptoServicesHavingDifferentSalts() throws Exception {
        assumeFalse(service.createDefaultAlgorithmParameters().getAlgorithm().startsWith("PBE"), "Skipping test for PBE algorithms as they transmit the salt in the crypto parameters");
        final String ciphertext = service.encrypt(MESSAGE);
        final JcaPbeCryptoService service2 = new JcaPbeCryptoService(configuration, salt, passwordProvider);
        final String message = service2.decrypt(ciphertext);
        assertEquals(MESSAGE, message);
        // now use different salt, should fail
        new Random().nextBytes(salt);
        final JcaPbeCryptoService service3 = new JcaPbeCryptoService(configuration, salt, passwordProvider);
        assertThrows(IllegalArgumentException.class, () -> service3.decrypt(ciphertext));
    }

    @Test
    void testSameMessageDifferentCipher() {
        final String ciphertext1 = service.encrypt(MESSAGE);
        final String ciphertext2 = service.encrypt(MESSAGE);
        assertEquals(MESSAGE, service.decrypt(ciphertext1));
        assertEquals(MESSAGE, service.decrypt(ciphertext2));
        // The ciphertexts should be different due to the use of a random IV
        assert(!ciphertext1.equals(ciphertext2));
    }

}
