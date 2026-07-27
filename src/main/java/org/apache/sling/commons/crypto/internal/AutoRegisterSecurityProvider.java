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

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Hashtable;

import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;
import org.osgi.framework.BundleEvent;
import org.osgi.framework.SynchronousBundleListener;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.propertytypes.ServiceDescription;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This DS component listens for bundle events and automatically registers or unregisters security providers
 * based on the presence of a service registration file {@value #SECURITY_PROVIDER_CONFIGURATION_FILE} in the bundle.
 */
@Component(immediate = true, service= {}, name = "org.apache.sling.commons.crypto.internal.AutoRegisterSecurityProvider")
@ServiceDescription("Apache Sling Commons Crypto – Auto Register Security Provider")
public class AutoRegisterSecurityProvider implements SynchronousBundleListener {
    private static final String SECURITY_PROVIDER_CONFIGURATION_FILE = "META-INF/services/java.security.Provider";
    private static final Logger LOGGER = LoggerFactory.getLogger(AutoRegisterSecurityProvider.class);

    @Activate
    public AutoRegisterSecurityProvider(BundleContext bundleContext) {
        bundleContext.addBundleListener(this);
        for (Bundle bundle : bundleContext.getBundles()) {
            if (bundle.getState() == Bundle.ACTIVE) {
                addOrRemoveProviderClass(true, bundle);
            }
        }
    }

    @Deactivate
    public void deactivate(BundleContext bundleContext) {
        bundleContext.removeBundleListener(this);
        for (Bundle bundle : bundleContext.getBundles()) {
            if (bundle.getState() == Bundle.ACTIVE) {
                addOrRemoveProviderClass(false, bundle);
            }
        }
    }

    @Override
    public void bundleChanged(BundleEvent event) {
        Bundle bundle = event.getBundle();
        final boolean isAdd;
        if (event.getType() == BundleEvent.STARTED) {
            isAdd = true;
        } else if (event.getType() == BundleEvent.STOPPING) {
            isAdd = false;
        } else {
            LOGGER.debug("Ignoring bundle event {} for bundle {}", event.getType(), bundle.getSymbolicName());
            return;
        }
        addOrRemoveProviderClass(isAdd, bundle);
    }

    protected void addOrRemoveProviderClass(boolean isAdd, Bundle bundle) {
        try {
            Collection<String> classNames = collectClassNamesFromProviderConfigurationFile(bundle);
            for (String className : classNames) {
                try {
                    addOrRemoveProviderClass(isAdd, bundle, className);
                } catch (ClassNotFoundException e) {
                    LOGGER.error("Class {} not found in bundle {}: {}", className, bundle.getSymbolicName(), e.getMessage(), e);
                } catch (Exception e) {
                    LOGGER.error("Error adding/removing security provider class {} from bundle {}: {}", className, bundle.getSymbolicName(), e.getMessage(), e);
                }
            }
        } catch (IOException e) {
            LOGGER.error("Error reading provider configuration file from bundle {}: {}", bundle.getSymbolicName(), e.getMessage(), e);
        }
    }

    protected Collection<String> collectClassNamesFromProviderConfigurationFile(Bundle bundle) throws IOException {
        var serviceRegistrationResource = bundle.getEntry(SECURITY_PROVIDER_CONFIGURATION_FILE);
        Collection<String> classNames = new ArrayList<>();
        if (serviceRegistrationResource != null) {
            try (var inputStream = serviceRegistrationResource.openStream()) {
                try (var reader = new java.io.BufferedReader(new java.io.InputStreamReader(inputStream))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        line = line.trim();
                        if (!line.isEmpty() && !line.startsWith("#")) {
                            classNames.add(line);
                        }
                    }
                }
            }
        } else {
            LOGGER.debug("No service registration file found in bundle {}", bundle);
        }
        return classNames;
    }

    protected void addOrRemoveProviderClass(boolean isAdd, Bundle bundle, String className)
            throws ClassNotFoundException, InstantiationException, IllegalAccessException, IllegalArgumentException,
            InvocationTargetException, NoSuchMethodException, SecurityException {
        Class<?> clazz = bundle.loadClass(className);
        if (!Provider.class.isAssignableFrom(clazz)) {
            // Handle the case where the class is not a Provider
            LOGGER.warn("Class {} in bundle {} is not a subclass of java.security.Provider", className, bundle);
        }
        Provider provider = (Provider) clazz.getDeclaredConstructor().newInstance();
        if (isAdd) {
            int position = Security.addProvider(provider);
            if (position == -1) {
                LOGGER.warn("Failed to add security provider {} (name {}) from bundle {} to the security providers list", className, provider.getName(), bundle);
            }
            // also add service registration for the provider so that other services can defer loading until the provider is available
            Hashtable<String, String> props = new Hashtable<>();
            props.put("provider.name", provider.getName());
            bundle.getBundleContext().registerService(Provider.class, provider, props);
            LOGGER.info("Added security provider {} (name {}) from bundle {} to last position {}", className, provider.getName(), bundle, position);
        } else {
            if (Security.getProvider(provider.getName()) != null) {
                Security.removeProvider(provider.getName());
                LOGGER.info("Removed security provider {} (name {}) from bundle {}", className, provider.getName(), bundle);
            } else {
                LOGGER.warn("Security provider {} (name {}) not found for removal", className, provider.getName());
            }
        }
    }
}
