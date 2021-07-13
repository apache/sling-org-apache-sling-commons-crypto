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

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Objects;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.apache.sling.commons.crypto.PasswordProvider;
import org.apache.sling.commons.crypto.SaltProvider;
import org.apache.sling.commons.crypto.SecretKeyProvider;
import org.jetbrains.annotations.NotNull;
import org.osgi.framework.Constants;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.metatype.annotations.Designate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component(
    property = {
        Constants.SERVICE_DESCRIPTION + "=Apache Sling Commons Crypto – PBE SecretKey Provider",
        Constants.SERVICE_VENDOR + "=The Apache Software Foundation"
    }
)
@Designate(
    ocd = PBESecretKeyProviderConfiguration.class,
    factory = true
)
@SuppressWarnings({"java:S1117", "java:S3077"})
public final class PBESecretKeyProvider implements SecretKeyProvider {

    @Reference
    private volatile PasswordProvider passwordProvider;

    @Reference
    private volatile SaltProvider saltProvider;

    private PBESecretKeyProviderConfiguration configuration;

    private SecretKeyFactory factory;

    private final Logger logger = LoggerFactory.getLogger(PBESecretKeyProvider.class);

    public PBESecretKeyProvider() { //
    }

    @Activate
    protected void activate(final PBESecretKeyProviderConfiguration configuration) throws NoSuchAlgorithmException {
        logger.debug("activating");
        this.configuration = configuration;
        factory = SecretKeyFactory.getInstance(configuration.algorithm());
    }

    @Modified
    protected void modified(final PBESecretKeyProviderConfiguration configuration) throws NoSuchAlgorithmException {
        logger.debug("modifying");
        this.configuration = configuration;
        factory = SecretKeyFactory.getInstance(configuration.algorithm());
    }

    @Deactivate
    protected void deactivate() {
        logger.debug("deactivating");
    }

    @Override
    public @NotNull SecretKey getSecretKey() {
        final var configuration = this.configuration;
        Objects.requireNonNull(configuration, "Configuration must not be null");
        try {
            final KeySpec keySpec = new PBEKeySpec(passwordProvider.getPassword(), saltProvider.getSalt(), configuration.iterationCount(), configuration.keyLength());
            return factory.generateSecret(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
    }

}
