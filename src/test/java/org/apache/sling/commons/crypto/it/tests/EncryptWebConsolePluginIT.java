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
package org.apache.sling.commons.crypto.it.tests;

import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Dictionary;
import java.util.Hashtable;

import javax.inject.Inject;

import org.apache.sling.commons.crypto.CryptoService;
import org.apache.sling.testing.paxexam.SlingOptions;
import org.jsoup.Connection.Method;
import org.jsoup.Connection.Response;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ops4j.pax.exam.Configuration;
import org.ops4j.pax.exam.Option;
import org.ops4j.pax.exam.junit.PaxExam;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerMethod;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Constants;
import org.osgi.framework.ServiceReference;
import org.osgi.framework.ServiceRegistration;

import static org.apache.sling.testing.paxexam.SlingOptions.webconsole;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.is;
import static org.ops4j.pax.exam.CoreOptions.mavenBundle;
import static org.ops4j.pax.exam.CoreOptions.options;
import static org.ops4j.pax.exam.cm.ConfigurationAdminOptions.newConfiguration;

@RunWith(PaxExam.class)
@ExamReactorStrategy(PerMethod.class)
public class EncryptWebConsolePluginIT extends CryptoTestSupport {

    private String url;

    private final CryptoService cryptoService = new ReversingCryptoService();

    private ServiceRegistration<CryptoService> registration;

    @Inject
    private BundleContext bundleContext;

    private static final String CREDENTIALS = new String(Base64.getEncoder().encode("admin:admin".getBytes()));

    public EncryptWebConsolePluginIT() { //
    }

    private void registerCryptoService() {
        final Dictionary<String, Object> properties = new Hashtable<>();
        properties.put("names", new String[]{"reverse"});
        properties.put("algorithm", "reverse");
        registration = bundleContext.registerService(CryptoService.class, cryptoService, properties);
    }

    @Configuration
    public Option[] configuration() {
        final int httpPort = findFreePort();
        return options(
            baseConfiguration(),
            newConfiguration("org.apache.felix.http")
                .put("org.osgi.service.http.port", httpPort)
                .asOption(),
            webconsole(),
            mavenBundle().groupId("org.jsoup").artifactId("jsoup").versionAsInProject()
        );
    }

    @Configuration
    public Option[] configurationWithNewJettyAndWebconsole() {
        SlingOptions.versionResolver.setVersion("org.apache.felix", "org.apache.felix.http.jetty", "5.1.26");
        SlingOptions.versionResolver.setVersion("org.apache.felix", "org.apache.felix.http.servlet-api", "3.0.0");
        SlingOptions.versionResolver.setVersion("org.apache.felix", "org.apache.felix.webconsole", "5.0.8");
        final int httpPort = findFreePort();
        return options(
            baseConfiguration(),
            newConfiguration("org.apache.felix.http")
                .put("org.osgi.service.http.port", httpPort)
                .asOption(),
            webconsole(),
            mavenBundle().groupId("org.jsoup").artifactId("jsoup").versionAsInProject(),
            mavenBundle().groupId("org.owasp.encoder").artifactId("encoder").version("1.3.1")
        );
    }

    @Before
    public void setUp() throws Exception {
        url = String.format("http://localhost:%s/system/console/sling-commons-crypto-encrypt", httpPort());
        registerCryptoService();
    }

    @Test
    public void testGetFormNoCryptoServiceAvailable() throws IOException {
        registration.unregister();
        final Document document = Jsoup.connect(url)
            .header("Authorization", String.format("Basic %s", CREDENTIALS))
            .get();
        assertThat(document.title(), is("Apache Felix Web Console - Sling Commons Crypto Encrypt"));
        assertThat(document.getElementById("content").child(0).text(), is("No crypto service available"));
    }

    @Test
    public void testGetFormCryptoServiceAvailable() throws IOException {
        final ServiceReference<CryptoService> reference = registration.getReference();
        final String id = reference.getProperty(Constants.SERVICE_ID).toString();
        final String[] names = (String[]) reference.getProperty("names");
        final String algorithm = reference.getProperty("algorithm").toString();
        final String label = String.format("Service id %s, names: %s, algorithm: %s", id, Arrays.toString(names), algorithm);
        final Document document = Jsoup.connect(url)
            .header("Authorization", String.format("Basic %s", CREDENTIALS))
            .get();
        assertThat(document.title(), is("Apache Felix Web Console - Sling Commons Crypto Encrypt"));
        assertThat(document.getElementById("service-id").child(0).text(), is(label));
    }

    @Test
    public void testEncrypt() throws IOException {
        final ServiceReference<CryptoService> reference = registration.getReference();
        final String id = reference.getProperty(Constants.SERVICE_ID).toString();
        final String message = "Very secret message";
        final String text = String.format("Encrypted message: %s", cryptoService.encrypt(message));
        final Document document = Jsoup.connect(url)
            .header("Authorization", String.format("Basic %s", CREDENTIALS))
            .data("service-id", id)
            .data("message", message)
            .post();
        assertThat(document.title(), is("Apache Felix Web Console - Sling Commons Crypto Encrypt"));
        assertThat(document.getElementById("ciphertext").text(), is(text));
    }

    @Test
    public void testEncryptMissingMessage() throws IOException {
        final ServiceReference<CryptoService> reference = registration.getReference();
        final String id = reference.getProperty(Constants.SERVICE_ID).toString();
        final Response response = Jsoup.connect(url)
            .header("Authorization", String.format("Basic %s", CREDENTIALS))
            .data("service-id", id)
            .method(Method.POST)
            .ignoreHttpErrors(true)
            .execute();
        assertThat(response.statusCode(), is(400));

        final Document document = response.parse();
        assertThat(document.title(), endsWith("Parameter message is missing"));
    }

    @Test
    public void testEncryptMissingServiceId() throws IOException {
        final String message = "Very secret message";
        final Response response = Jsoup.connect(url)
            .header("Authorization", String.format("Basic %s", CREDENTIALS))
            .data("message", message)
            .method(Method.POST)
            .ignoreHttpErrors(true)
            .execute();
        assertThat(response.statusCode(), is(400));

        final Document document = response.parse();
        assertThat(document.title(), endsWith("Parameter service-id is missing"));
    }

    @Test
    public void testEncryptMissingInvalidServiceId() throws IOException {
        final String id = "invalid";
        final String message = "Very secret message";
        final Response response = Jsoup.connect(url)
            .header("Authorization", String.format("Basic %s", CREDENTIALS))
            .data("service-id", id)
            .data("message", message)
            .method(Method.POST)
            .ignoreHttpErrors(true)
            .execute();
        assertThat(response.statusCode(), is(404));

        final Document document = response.parse();
        assertThat(document.title(), endsWith("Crypto service with service id invalid not found"));
    }

}
