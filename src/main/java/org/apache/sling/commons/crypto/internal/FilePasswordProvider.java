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

/**
 * Provider of passwords from files.
 *
 * @see File
 */
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
@SuppressWarnings({"java:S1117", "java:S6212"})
public final class FilePasswordProvider implements PasswordProvider {

    private static final char NEWLINE_CHARACTER = '\n';

    private FilePasswordProviderConfiguration configuration;

    private final Logger logger = LoggerFactory.getLogger(FilePasswordProvider.class);

    public FilePasswordProvider() { //
    }

    @Activate
    @SuppressWarnings("unused")
    private void activate(final FilePasswordProviderConfiguration configuration) throws IOException {
        logger.debug("activating");
        this.configuration = configuration;
        checkConfiguration(configuration);
    }

    @Modified
    @SuppressWarnings("unused")
    private void modified(final FilePasswordProviderConfiguration configuration) throws IOException {
        logger.debug("modifying");
        this.configuration = configuration;
        checkConfiguration(configuration);
    }

    @Deactivate
    @SuppressWarnings("unused")
    private void deactivate() {
        logger.debug("deactivating");
    }

    private char[] readPassword(final String path, final boolean fixPosixNewline) throws IOException {
        final File file = new File(path);
        checkPasswordFile(file);
        final char[] buffer = new char[(int) file.length()];
        try (BufferedReader reader = Files.newBufferedReader(file.toPath(), StandardCharsets.UTF_8)) {
            final int size = reader.read(buffer);
            final int length;
            if (fixPosixNewline && buffer[size - 1] == NEWLINE_CHARACTER) {
                length = size - 1;
            } else {
                length = size;
            }
            final char[] password = new char[length];
            System.arraycopy(buffer, 0, password, 0, length);
            Arrays.fill(buffer, '0');
            return password;
        }
    }

    private void checkConfiguration(final FilePasswordProviderConfiguration configuration) throws IOException {
        final File file = new File(configuration.path());
        checkPasswordFile(file);
    }

    private void checkPasswordFile(final File file) throws IOException {
        if (!file.canRead()) {
            final String message = String.format("Unable to read password file '%s'", file.getAbsolutePath());
            throw new IOException(message);
        }
    }

    @Override
    @SuppressWarnings("java:S112")
    public char @NotNull [] getPassword() {
        final var configuration = this.configuration;
        Objects.requireNonNull(configuration, "Configuration must not be null");
        try {
            return readPassword(configuration.path(), configuration.fix_posixNewline());
        } catch (IOException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

}
