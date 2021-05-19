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

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;

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
        Constants.SERVICE_DESCRIPTION + "=Apache Sling Commons Crypto – File Password Provider",
        Constants.SERVICE_VENDOR + "=The Apache Software Foundation"
    }
)
@Designate(
    ocd = FilePasswordProviderConfiguration.class,
    factory = true
)
public class FilePasswordProvider implements PasswordProvider {

    private FilePasswordProviderConfiguration configuration;

    private final Logger logger = LoggerFactory.getLogger(FilePasswordProvider.class);

    public FilePasswordProvider() {
    }

    @Activate
    private void activate(final FilePasswordProviderConfiguration configuration) throws IOException {
        logger.debug("activating");
        this.configuration = configuration;
        checkConfiguration();
    }

    @Modified
    private void modified(final FilePasswordProviderConfiguration configuration) throws IOException {
        logger.debug("modifying");
        this.configuration = configuration;
        checkConfiguration();
    }

    @Deactivate
    private void deactivate() {
        logger.debug("deactivating");
        this.configuration = null;
    }

    private char[] readPassword(final String path) throws IOException {
        final File file = new File(path);
        final char[] buffer = new char[(int) file.length()];
        try (final BufferedReader reader = Files.newBufferedReader(file.toPath(), StandardCharsets.UTF_8)) {
            final int size = reader.read(buffer);
            final char[] password = new char[size];
            System.arraycopy(buffer, 0, password, 0, size);
            Arrays.fill(buffer, '0');
            return password;
        }
    }

    private void checkConfiguration() throws IOException {
        final String path = configuration.path();
        final File file = new File(path);
        if (!file.canRead()) {
            final String message = String.format("Unable to read password file '%s'", path);
            throw new IOException(message);
        }
    }

    @Override
    public char @NotNull [] getPassword() {
        try {
            return readPassword(configuration.path());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
