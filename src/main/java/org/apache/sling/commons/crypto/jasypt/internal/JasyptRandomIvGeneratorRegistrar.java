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

import java.util.Dictionary;
import java.util.Hashtable;
import java.util.Objects;

import org.jasypt.iv.IvGenerator;
import org.jasypt.iv.RandomIvGenerator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Constants;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.metatype.annotations.Designate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component(
    property = {
        Constants.SERVICE_DESCRIPTION + "=Apache Sling Commons Crypto – Jasypt Random IV Generator Registrar",
        Constants.SERVICE_VENDOR + "=The Apache Software Foundation"
    }
)
@Designate(
    ocd = JasyptRandomIvGeneratorRegistrarConfiguration.class,
    factory = true
)
public class JasyptRandomIvGeneratorRegistrar {

    private ServiceRegistration<IvGenerator> serviceRegistration;

    private final Logger logger = LoggerFactory.getLogger(JasyptRandomIvGeneratorRegistrar.class);

    public JasyptRandomIvGeneratorRegistrar() {
    }

    @Activate
    private void activate(final JasyptRandomIvGeneratorRegistrarConfiguration configuration, final BundleContext bundleContext) {
        logger.debug("activating");
        final String algorithm = configuration.algorithm();
        final RandomIvGenerator ivGenerator = new RandomIvGenerator(algorithm);
        final Dictionary<String, String> properties = new Hashtable<>();
        properties.put("algorithm", algorithm);
        logger.debug("registering Random IV Generator with algorithm {}", algorithm);
        serviceRegistration = bundleContext.registerService(IvGenerator.class, ivGenerator, properties);
    }

    @Deactivate
    private void deactivate() {
        logger.debug("deactivating");
        if (Objects.nonNull(serviceRegistration)) {
            serviceRegistration.unregister();
        }
    }

}
