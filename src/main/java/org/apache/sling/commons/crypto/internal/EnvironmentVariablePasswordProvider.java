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

import java.util.Objects;

import org.apache.sling.commons.crypto.PasswordProvider;
import org.jetbrains.annotations.NotNull;
import org.osgi.framework.Constants;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.metatype.annotations.Designate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component(
    property = {
        Constants.SERVICE_DESCRIPTION + "=Apache Sling Commons Crypto – Environment Variable Password Provider",
        Constants.SERVICE_VENDOR + "=The Apache Software Foundation"
    }
)
@Designate(
    ocd = EnvironmentVariablePasswordProviderConfiguration.class,
    factory = true
)
@SuppressWarnings("java:S6212")
public class EnvironmentVariablePasswordProvider implements PasswordProvider {

    private EnvironmentVariablePasswordProviderConfiguration configuration;

    private final Logger logger = LoggerFactory.getLogger(EnvironmentVariablePasswordProvider.class);

    public EnvironmentVariablePasswordProvider() { //
    }

    @Activate
    protected void activate(final EnvironmentVariablePasswordProviderConfiguration configuration) {
        logger.debug("activating");
        this.configuration = configuration;
    }

    @Modified
    protected void modified(final EnvironmentVariablePasswordProviderConfiguration configuration) {
        logger.debug("modifying");
        this.configuration = configuration;
    }

    @Deactivate
    protected void deactivate() {
        logger.debug("deactivating");
    }

    @Override
    public char @NotNull [] getPassword() {
        Objects.requireNonNull(configuration, "Configuration must not be null");
        final String name = configuration.name();
        if (Objects.isNull(System.getenv(name))) {
            final String message = String.format("environment variable '%s' not set", name);
            throw new RuntimeException(message);
        } else {
            return System.getenv(name).toCharArray();
        }
    }

}
