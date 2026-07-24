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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Objects;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;

import org.apache.sling.commons.crypto.CryptoService;
import org.apache.sling.commons.crypto.PasswordProvider;
import org.apache.sling.commons.crypto.SaltProvider;
import org.jetbrains.annotations.NotNull;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Constants;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.metatype.annotations.Designate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Service for encrypting messages and decrypting ciphertexts using Java Crypto Architecture API.
 * It relies on SecretKeyFactory with PBEKeySpec for key derivation and a symmetric cipher for encryption and decryption.
 * 
 * @see <a href="https://www.rfc-editor.org/info/rfc8018/#section-6.2">RFC 8018 - PBES2</a>
 * @see <a href="https://docs.oracle.com/en/java/javase/21/security/java-cryptography-architecture-jca-reference-guide.html">Java Cryptography Architecture (JCA) Reference Guide</a>
 *
 */
@Component(
    property = {
        Constants.SERVICE_DESCRIPTION + "=Apache Sling Commons Crypto – JCA PBE String Crypto Service",
        Constants.SERVICE_VENDOR + "=The Apache Software Foundation"
    }
)
@Designate(
    ocd = JcaPbeCryptoServiceConfiguration.class,
    factory = true
)
@SuppressWarnings({"java:S1117", "java:S3077", "java:S6212"})
public final class JcaPbeCryptoService implements CryptoService {

    // TODO: bind to a specific password provider
    private final PasswordProvider passwordProvider;

    private final SecureRandom secureRandom;
    private final SecretKey key;

    private final JcaPbeCryptoServiceConfiguration configuration;

    protected static byte[] getOrCreateSalt(BundleContext bundleContext, final SaltProvider saltProvider) throws IOException {
        File file = bundleContext.getDataFile("salt.bin");
        if (file == null) {
            throw new IllegalStateException("Could not access bundle data file for salt");
        }
        byte[] salt;
        if (!file.exists()) {
            // Generate a new salt and persist it
            salt = saltProvider.getSalt();
            try (FileOutputStream fos = new FileOutputStream(file)) {
                fos.write(salt);
            }
        } else {
            // Read the existing salt from the file
            try (var fis = new java.io.FileInputStream(file)) {
                salt = fis.readAllBytes();
            }
        }
        return salt;
    }

    @Activate
    public JcaPbeCryptoService(final JcaPbeCryptoServiceConfiguration configuration, BundleContext bundleContext, @Reference PasswordProvider passwordProvider, @Reference SaltProvider saltProvider) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidParameterSpecException, InvalidKeySpecException, IOException { //
        this(configuration, getOrCreateSalt(bundleContext, saltProvider), passwordProvider);
        // TODO: bind specific password provider and salt provider
    }

    public JcaPbeCryptoService(final JcaPbeCryptoServiceConfiguration configuration, byte[] salt, PasswordProvider passwordProvider) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidParameterSpecException, InvalidKeySpecException { //
        this.configuration = configuration;
        this.passwordProvider = passwordProvider;
        if (configuration.secureRandomAlgorithm() != null && !configuration.secureRandomAlgorithm().isBlank()) {
            this.secureRandom = SecureRandom.getInstance(configuration.secureRandomAlgorithm());
        } else {
            this.secureRandom = new SecureRandom();
        }
        // TODO: keep in RAM or rather create on demand?
        this.key = this.createKey(configuration, salt);
    }

    @Deactivate
    @SuppressWarnings("unused")
    private void deactivate() throws DestroyFailedException {
        this.key.destroy();
    }

    
    private SecretKey createKey(final JcaPbeCryptoServiceConfiguration configuration, byte[] salt) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidParameterSpecException, InvalidKeySpecException {
        Provider provider = Security.getProvider(configuration.securityProviderName());
        if (provider == null) {
            throw new IllegalStateException("Security provider " + configuration.securityProviderName() + " not found");
        }
        final char[] password = passwordProvider.getPassword();
        // for regular PBE key this is completely ignored (as all logic is encapsulated in the actual cipher implementation, see https://github.com/openjdk/jdk/blob/master/src/java.base/share/classes/com/sun/crypto/provider/PBEKeyFactory.java
        KeySpec keySpec = new PBEKeySpec(
                password,
                salt,
                configuration.numKeyIterations(),
                configuration.keyLengthBits()
                );
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(configuration.secretKeyFactoryAlgorithm(), provider);
        SecretKey originalKey = secretKeyFactory.generateSecret(keySpec);
        if (configuration.secretKeyFactoryAlgorithm().equals(configuration.cipherAlgorithm())) {
            // if the cipher algorithm is the same as the secret key factory algorithm then the cipher takes care of the actual logic and uses the key as is.
            return originalKey;
        } else {
            // wrap as key for the proper cipher algorithm (e.g., AES) instead of the PBE algorithm (e.g., PBKDF2WithHmacSHA512)
            return new SecretKeySpec(originalKey.getEncoded(), extractAlgorithmName(configuration.cipherAlgorithm()));
        }
    }

    /**
     * Extracts the algorithm name from the cipher algorithm string.
     * @param cipherAlgorithm the cipher algorithm string (e.g., "AES/CBC/PKCS5Padding")
     * @return the algorithm name (e.g., "AES")
     */
    protected static String extractAlgorithmName(String cipherAlgorithm) {
        // Extract the algorithm name from the cipher algorithm string
        // For example, if cipherAlgorithm is "AES/CBC/PKCS5Padding", return "AES"
        int slashIndex = cipherAlgorithm.indexOf('/');
        if (slashIndex > 0) {
            return cipherAlgorithm.substring(0, slashIndex);
        } else {
            return cipherAlgorithm; // No mode/padding specified, return as is
        }
    }

    /**
     * @param paramsName the name of the algorithm parameters (e.g., "AES"), {@code null} if cipher should be used for encryption and default parameters should be generated (e.g., random IV for AES/CBC)
     * @param encodedParams the encoded algorithm parameters (e.g., IV for AES/CBC)
     * @return a Cipher instance initialized for encryption or decryption
     * @throws NoSuchPaddingException 
     * @throws NoSuchAlgorithmException 
     * @throws InvalidKeyException 
     * @throws InvalidAlgorithmParameterException 
     * @throws IOException 
     */
    private Cipher createCipher(String paramsName, byte[] encodedParams) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
        Provider provider = Security.getProvider(configuration.securityProviderName());
        Cipher cipher = Cipher.getInstance(configuration.cipherAlgorithm(), provider);
        
        if (encodedParams == null) {
            // rely on default parameters generated by the cipher (e.g., random IV for AES/CBC)
            cipher.init(Cipher.ENCRYPT_MODE, key, secureRandom);
        } else {
            Objects.requireNonNull(paramsName, "paramsName must not be null when encodedParams is provided");
            if (paramsName.isBlank()) {
                cipher.init(Cipher.DECRYPT_MODE, key, secureRandom);
            } else {
                // create a new AlgorithmParameters instance for the cipher algorithm and initialize it with the encoded parameters
                AlgorithmParameters params = AlgorithmParameters.getInstance(paramsName, provider);
                params.init(encodedParams);
                cipher.init(Cipher.DECRYPT_MODE, key, params, secureRandom);
            }
        }
        return cipher;
    }

    protected AlgorithmParameters createDefaultAlgorithmParameters() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException {
        Cipher cipher = createCipher(null, null);
        return cipher.getParameters();
    }

    private static void writeIntToBytes(int value, byte[] dest, int offset) {
        dest[offset] = (byte) (value >>> 24);
        dest[offset + 1] = (byte) (value >>> 16);
        dest[offset + 2] = (byte) (value >>> 8);
        dest[offset + 3] = (byte) value;
    }

    private static int bytesToInt(byte[] src, int offset) {
        return ((src[offset] & 0xFF) << 24) |
               ((src[offset + 1] & 0xFF) << 16) |
               ((src[offset + 2] & 0xFF) << 8) |
               (src[offset + 3] & 0xFF);
    }

    @Override
    public @NotNull String encrypt(@NotNull final String message) {
        byte[] cipherTextBytes;
        try {
            Cipher cipherEncrypt = createCipher(null, null);
            final byte[] params;
            final byte[] paramsName;
            if (cipherEncrypt.getParameters() == null) {
                params = new byte[0];
                paramsName = new byte[0];
            } else {
                params = cipherEncrypt.getParameters().getEncoded();
                paramsName = cipherEncrypt.getParameters().getAlgorithm().getBytes(StandardCharsets.UTF_8);
            }
            int paramLength = params.length;
            cipherTextBytes = cipherEncrypt.doFinal(message.getBytes(StandardCharsets.UTF_8));
            
            final byte[] result;
            // Combine parameters + ciphertext into single array
            result = new byte[Integer.BYTES + paramsName.length + Integer.BYTES + paramLength + cipherTextBytes.length];
            int offset = 0;
            writeIntToBytes(paramsName.length, result, 0);
            offset += Integer.BYTES;
            System.arraycopy(paramsName, 0, result, offset, paramsName.length);
            offset += paramsName.length;
            writeIntToBytes(paramLength, result, offset);
            offset += Integer.BYTES;
            System.arraycopy(params, 0, result, offset, params.length);
            offset += params.length;
            System.arraycopy(cipherTextBytes, 0, result, offset, cipherTextBytes.length);
            return Base64.getEncoder().encodeToString(result);
        } catch (IllegalBlockSizeException|BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException|InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new IllegalArgumentException("Could not encrypt", e);
        } catch (IOException e) {
            throw new IllegalStateException("Could not encode cipher parameters", e);
        }
    }

    @Override
    public @NotNull String decrypt(@NotNull final String cipherText) {
        byte[] plainTextBytes;
        try {
            byte[] encryptedData = Base64.getDecoder().decode(cipherText);
            final byte[] cipherData;
            final Cipher cipher;
            // Split up into paramsName, params, and cipherData
            int offset = 0;
            int paramsNameLength = bytesToInt(encryptedData, offset);
            offset += Integer.BYTES;
            byte[] paramsName = new byte[paramsNameLength];
            System.arraycopy(encryptedData, offset, paramsName, 0, paramsNameLength);
            String paramsNameStr = new String(paramsName, StandardCharsets.UTF_8);
            offset += paramsNameLength;
            int paramsLength = bytesToInt(encryptedData, offset);
            offset += Integer.BYTES;
            byte[] params = new byte[paramsLength];
            System.arraycopy(encryptedData, offset, params, 0, paramsLength);
            offset += paramsLength;
            cipherData = new byte[encryptedData.length - offset];
            System.arraycopy(encryptedData, offset, cipherData, 0, cipherData.length);
            cipher = createCipher(paramsNameStr, params);
            plainTextBytes = cipher.doFinal(cipherData);
        } catch (IllegalBlockSizeException|BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IOException e) {
            throw new IllegalArgumentException("Invalid ciphertext", e);
        }
        return new String(plainTextBytes, StandardCharsets.UTF_8);
    }

    @Override
    public String toString() {
        return "JcaPbeCryptoService [KDF=" + configuration.secretKeyFactoryAlgorithm() + ", cipher=" + configuration.cipherAlgorithm() + ", provider=" + configuration.securityProviderName() + "]";
    }
}
