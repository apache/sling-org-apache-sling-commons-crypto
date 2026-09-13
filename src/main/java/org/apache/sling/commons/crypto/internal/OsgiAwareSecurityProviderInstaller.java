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
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Hashtable;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;
import org.osgi.framework.BundleEvent;
import org.osgi.framework.ServiceRegistration;
import org.osgi.framework.SynchronousBundleListener;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.propertytypes.ServiceDescription;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This DS component listens for bundle events and automatically adds or removes security providers with the Java Security API
 * based on the presence of a service registration file {@value #SECURITY_PROVIDER_CONFIGURATION_FILE} in the 
 * started/stopping bundle via {@link Security#addProvider(Provider)} and {@link Security#removeProvider(String)}.
 * In addition it also registers each provider (even the ones shipping with the JVM) as an OSGi service so that other services can defer loading 
 * until a certain provider is available.
 * The OSGi service registration includes a property {@value #PROVIDER_NAME_PROPERTY} with the name of the provider.
 */
@Component(immediate = true, service= {}, name = "org.apache.sling.commons.crypto.internal.AutoRegisterSecurityProvider")
@ServiceDescription("Apache Sling Commons Crypto – Auto Register Security Provider")
public final class OsgiAwareSecurityProviderInstaller implements SynchronousBundleListener {
    private static final String SECURITY_PROVIDER_CONFIGURATION_FILE = "META-INF/services/java.security.Provider";
    private static final Logger LOGGER = LoggerFactory.getLogger(OsgiAwareSecurityProviderInstaller.class);
    private static final String PROVIDER_NAME_PROPERTY = "provider.name";
    private final Map<String, ServiceRegistration<Provider>> registeredProviders;
    private final BundleContext bundleContext;

    @Activate
    public OsgiAwareSecurityProviderInstaller(BundleContext bundleContext) {
        registeredProviders = new ConcurrentHashMap<>();
        this.bundleContext = bundleContext;
        bundleContext.addBundleListener(this);
        registerOrUnregisterDefaultProviders(true);
        for (Bundle bundle : bundleContext.getBundles()) {
            if (bundle.getState() == Bundle.ACTIVE) {
                addOrRemoveCustomProviders(true, bundle);
            }
        }
    }

    @Deactivate
    public void deactivate(BundleContext bundleContext) {
        bundleContext.removeBundleListener(this);
        for (Bundle bundle : bundleContext.getBundles()) {
            if (bundle.getState() == Bundle.ACTIVE) {
                addOrRemoveCustomProviders(false, bundle);
            }
        }
        registerOrUnregisterDefaultProviders(false);
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
        addOrRemoveCustomProviders(isAdd, bundle);
    }
    
    protected void registerOrUnregisterDefaultProviders(boolean isRegister) {
        for (Provider provider : Security.getProviders()) {
            if (isRegister) {
                registerProviderWithOsgi(this.bundleContext, provider);
            } else {
                unregisterProviderWithOsgi(provider.getName(), registeredProviders.remove(provider.getName()));
            }
        }
    }

    protected void addOrRemoveCustomProviders(boolean isAdd, Bundle bundle) {
        try {
            Collection<String> classNames = collectClassNamesFromProviderConfigurationFile(bundle);
            for (String className : classNames) {
                try {
                    addOrRemoveCustomProvider(isAdd, bundle, className);
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
            try (InputStream inputStream = serviceRegistrationResource.openStream();
                 BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (!line.isEmpty() && !line.startsWith("#")) {
                        classNames.add(line);
                    }
                }
            }
        } else {
            LOGGER.debug("No service registration file found in bundle {}", bundle);
        }
        return classNames;
    }

    protected void addOrRemoveCustomProvider(boolean isAdd, Bundle bundle, String providerClassName)
            throws ClassNotFoundException, InstantiationException, IllegalAccessException, IllegalArgumentException,
            InvocationTargetException, NoSuchMethodException, SecurityException {
        Class<?> clazz = bundle.loadClass(providerClassName);
        if (!Provider.class.isAssignableFrom(clazz)) {
            // Handle the case where the class is not a Provider
            LOGGER.warn("Class {} in bundle {} is not a subclass of java.security.Provider", providerClassName, bundle);
        }
        Provider provider = (Provider) clazz.getDeclaredConstructor().newInstance();
        if (isAdd) {
            int position = Security.addProvider(provider);
            if (position == -1) {
                LOGGER.warn("Failed to add security provider {} (name {}) from bundle {} to the security providers list. Provider with that name already registered.", providerClassName, provider.getName(), bundle);
            }
            LOGGER.info("Added security provider {} (name {}) from bundle {} to last position {}", providerClassName, provider.getName(), bundle, position);
            registerProviderWithOsgi(bundle.getBundleContext(), provider);
        } else {
            if (Security.getProvider(provider.getName()) != null) {
                Security.removeProvider(provider.getName());
                LOGGER.info("Removed security provider {} (name {}) from bundle {}", providerClassName, provider.getName(), bundle);
            } else {
                LOGGER.warn("Security provider {} (name {}) not found for removal", providerClassName, provider.getName());
            }
            unregisterProviderWithOsgi(provider.getName(), registeredProviders.remove(provider.getName()));
        }
    }

    private void registerProviderWithOsgi(BundleContext context, Provider provider) {
        // also add service registration for the provider so that other services can defer loading until the provider is available
        Hashtable<String, String> props = new Hashtable<>();
        props.put(PROVIDER_NAME_PROPERTY, provider.getName());
        ServiceRegistration<Provider> registration = context.registerService(Provider.class, provider, props);
        registeredProviders.put(provider.getName(), registration);
        LOGGER.info("Registered security provider with name {} as OSGi service", provider.getName());
    }

    private void unregisterProviderWithOsgi(String name, ServiceRegistration<Provider> registration) {
        if (registration == null) {
            LOGGER.warn("No service registration found for security provider with name '{}' to unregister", name);
            return;
        }
        try {
            registration.unregister();
            LOGGER.info("Unregistered security provider with name '{}' as OSGi service", name);
        } catch (IllegalStateException e) {
            LOGGER.warn("Service for provider with name {} is already unregistered: {}", name, e.getMessage(), e);
        }
    }
}
