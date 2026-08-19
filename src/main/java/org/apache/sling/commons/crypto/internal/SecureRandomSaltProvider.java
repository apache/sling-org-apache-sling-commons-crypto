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
import java.security.SecureRandom;
import java.util.Objects;

import org.apache.sling.commons.crypto.SaltProvider;
import org.jetbrains.annotations.NotNull;
import org.osgi.framework.Constants;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.metatype.annotations.Designate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provider of salts created from <code>SecureRandom</code>.
 *
 * @see SecureRandom
 */
@Component(
    property = {
        Constants.SERVICE_DESCRIPTION + "=Apache Sling Commons Crypto – SecureRandom Salt Provider",
        Constants.SERVICE_VENDOR + "=The Apache Software Foundation"
    }
)
@Designate(
    ocd = SecureRandomSaltProviderConfiguration.class,
    factory = true
)
@SuppressWarnings({"java:S1117", "java:S6212"})
public final class SecureRandomSaltProvider implements SaltProvider {

    private final SecureRandom secureRandom;

    private final SecureRandomSaltProviderConfiguration configuration;

    private final Logger logger = LoggerFactory.getLogger(SecureRandomSaltProvider.class);

    @Activate
    public SecureRandomSaltProvider(final SecureRandomSaltProviderConfiguration configuration) throws NoSuchAlgorithmException { //
        logger.debug("activating");
        this.configuration = configuration;
        if (configuration.algorithm().isBlank()) {
            secureRandom = new SecureRandom();
        } else {
            secureRandom = SecureRandom.getInstance(configuration.algorithm());
        }
    }

    @Override
    public byte @NotNull [] getSalt() {
        final var configuration = this.configuration;
        Objects.requireNonNull(configuration, "Configuration must not be null");
        final byte[] bytes = new byte[configuration.keyLength()];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

}
