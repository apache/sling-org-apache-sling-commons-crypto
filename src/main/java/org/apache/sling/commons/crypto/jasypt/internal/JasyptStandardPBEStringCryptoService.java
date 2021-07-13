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
import java.util.Arrays;
import java.util.Objects;
import java.util.Set;

import org.apache.sling.commons.crypto.CryptoService;
import org.apache.sling.commons.crypto.PasswordProvider;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.iv.IvGenerator;
import org.jasypt.registry.AlgorithmRegistry;
import org.jasypt.salt.SaltGenerator;
import org.jetbrains.annotations.NotNull;
import org.osgi.framework.Constants;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.metatype.annotations.Designate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component(
    property = {
        Constants.SERVICE_DESCRIPTION + "=Apache Sling Commons Crypto – Jasypt Standard PBE String Crypto Service",
        Constants.SERVICE_VENDOR + "=The Apache Software Foundation"
    }
)
@Designate(
    ocd = JasyptStandardPBEStringCryptoServiceConfiguration.class,
    factory = true
)
@SuppressWarnings({"java:S1117", "java:S3077", "java:S6212"})
public final class JasyptStandardPBEStringCryptoService implements CryptoService {

    @Reference
    private volatile PasswordProvider passwordProvider;

    @Reference
    private volatile IvGenerator ivGenerator;

    @Reference(
        cardinality = ReferenceCardinality.OPTIONAL
    )
    private volatile Provider securityProvider;

    @Reference(
        cardinality = ReferenceCardinality.OPTIONAL
    )
    private volatile SaltGenerator saltGenerator;

    private StandardPBEStringEncryptor encryptor;

    private final Logger logger = LoggerFactory.getLogger(JasyptStandardPBEStringCryptoService.class);

    public JasyptStandardPBEStringCryptoService() { //
    }

    @Activate
    protected void activate(final JasyptStandardPBEStringCryptoServiceConfiguration configuration) {
        logger.debug("activating");
        setupEncryptor(configuration);
    }

    @Modified
    protected void modified(final JasyptStandardPBEStringCryptoServiceConfiguration configuration) {
        logger.debug("modifying");
        setupEncryptor(configuration);
    }

    @Deactivate
    protected void deactivate() {
        logger.debug("deactivating");
    }

    private void setupEncryptor(final JasyptStandardPBEStringCryptoServiceConfiguration configuration) {
        final String algorithm = configuration.algorithm();
        final Set<?> algorithms = AlgorithmRegistry.getAllPBEAlgorithms();
        if (!algorithms.contains(algorithm)) {
            logger.warn("Configured algorithm {} for password based encryption is not available. {}", algorithm, algorithms);
        }
        final StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
        // mandatory
        encryptor.setAlgorithm(algorithm);
        final IvGenerator ivGenerator = this.ivGenerator;
        encryptor.setIvGenerator(ivGenerator);
        // optional
        encryptor.setKeyObtentionIterations(configuration.keyObtentionIterations());
        encryptor.setStringOutputType(configuration.stringOutputType());
        final String securityProviderName = configuration.securityProviderName();
        if (Objects.nonNull(securityProviderName) && !securityProviderName.isBlank()) {
            encryptor.setProviderName(securityProviderName);
        }
        final Provider provider = this.securityProvider;
        if (Objects.nonNull(provider)) {
            encryptor.setProvider(provider);
        }
        final SaltGenerator saltGenerator = this.saltGenerator;
        if (Objects.nonNull(saltGenerator)) {
            encryptor.setSaltGenerator(saltGenerator);
        }
        // set mandatory password, initialize encryptor, clear password
        final char[] password = passwordProvider.getPassword();
        encryptor.setPasswordCharArray(password);
        encryptor.initialize();
        Arrays.fill(password, '0');
        this.encryptor = encryptor;
    }

    @Override
    public @NotNull String encrypt(@NotNull final String message) {
        return encryptor.encrypt(message);
    }

    @Override
    public @NotNull String decrypt(@NotNull final String ciphertext) {
        return encryptor.decrypt(ciphertext);
    }

}
