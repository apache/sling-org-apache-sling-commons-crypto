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
package org.apache.sling.commons.crypto.webconsole.internal;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.Objects;

import javax.servlet.RequestDispatcher;
import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.apache.sling.commons.crypto.CryptoService;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Constants;
import org.osgi.framework.ServiceReference;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.util.tracker.ServiceTracker;

@Component(
    service = Servlet.class,
    property = {
        "felix.webconsole.label=sling-commons-crypto-encrypt",
        "felix.webconsole.title=Sling Commons Crypto Encrypt",
        "felix.webconsole.category=Crypto"
    }
)
@SuppressWarnings({"java:S1989", "java:S2226", "java:S6212"})
public final class EncryptWebConsolePlugin extends HttpServlet {

    private static final String PARAMETER_SERVICE_ID = "service-id";

    private static final String PARAMETER_MESSAGE = "message";

    private static final String ATTRIBUTE_CIPHERTEXT = "org.apache.sling.commons.crypto.webconsole.internal.EncryptWebConsolePlugin.ciphertext";

    private BundleContext bundleContext;

    private ServiceTracker<CryptoService, CryptoService> tracker;

    public EncryptWebConsolePlugin() { //
    }

    @Activate
    @SuppressWarnings("unused")
    private void activate(final BundleContext bundleContext) {
        this.bundleContext = bundleContext;
        tracker = new ServiceTracker<>(bundleContext, CryptoService.class, null);
        tracker.open();
    }

    @Deactivate
    @SuppressWarnings("unused")
    private void deactivate() {
        this.bundleContext = null;
        if (Objects.nonNull(tracker)) {
            tracker.close();
            tracker = null;
        }
    }

    @Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response) throws ServletException, IOException {
        final ServiceReference<CryptoService>[] references = tracker.getServiceReferences();
        final PrintWriter writer = response.getWriter();
        if (Objects.nonNull(references) && references.length > 0) {
            final String form = buildForm(references);
            writer.println(form);
        } else {
            writer.println("<p>No crypto service available</p>");
        }

        final String forwardRequestUri = (String) request.getAttribute(RequestDispatcher.FORWARD_REQUEST_URI);
        if (Objects.nonNull(forwardRequestUri) && forwardRequestUri.equals(request.getRequestURI())) {
            final String ciphertext = (String) request.getAttribute(ATTRIBUTE_CIPHERTEXT);
            if (Objects.nonNull(ciphertext)) {
                final String html = String.format("<p id=\"ciphertext\">Encrypted message: %s</p>", ciphertext);
                writer.println(html);
            }
        }
    }

    @Override
    protected void doPost(final HttpServletRequest request, final HttpServletResponse response) throws ServletException, IOException {
        request.removeAttribute(ATTRIBUTE_CIPHERTEXT);
        final String serviceId = request.getParameter(PARAMETER_SERVICE_ID);
        final String message = request.getParameter(PARAMETER_MESSAGE); // do NOT log SECRET message
        if (Objects.isNull(serviceId)) {
            handleParameterMissing(response, PARAMETER_SERVICE_ID);
            return;
        }
        if (Objects.isNull(message)) {
            handleParameterMissing(response, PARAMETER_MESSAGE);
            return;
        }
        final CryptoService cryptoService = findCryptoService(serviceId);
        if (Objects.isNull(cryptoService)) {
            handleCryptoServiceNotFound(response, serviceId);
            return;
        }
        final String ciphertext = cryptoService.encrypt(message);
        request.setAttribute(ATTRIBUTE_CIPHERTEXT, ciphertext);
        final GetHttpServletRequestWrapper wrapper = new GetHttpServletRequestWrapper(request);
        request.getRequestDispatcher(request.getRequestURI()).forward(wrapper, response);
    }

    private void handleParameterMissing(final HttpServletResponse response, final String parameter) throws IOException {
        final String message = String.format("Parameter %s is missing", parameter);
        response.sendError(HttpServletResponse.SC_BAD_REQUEST, message);
    }

    private void handleCryptoServiceNotFound(final HttpServletResponse response, final String id) throws IOException {
        final String message = String.format("Crypto service with service id %s not found", id);
        response.sendError(HttpServletResponse.SC_NOT_FOUND, message);
    }

    private @NotNull String buildForm(final ServiceReference<CryptoService>[] references) {
        final StringBuilder builder = new StringBuilder();
        builder.append("<form method=\"POST\">");
        builder.append("<label for=\"message\">Message to encrypt</label>");
        builder.append("<br>");
        builder.append("<input type=\"text\" name=\"message\" id=\"message\">");
        builder.append("<br>");
        builder.append("<label>Available crypto services");
        builder.append("<br>");
        builder.append("<select id=\"service-id\" name=\"service-id\">");
        for (final ServiceReference<CryptoService> reference : references) {
            final String id = reference.getProperty(Constants.SERVICE_ID).toString();
            final String[] names = (String[]) reference.getProperty("names");
            final String algorithm = reference.getProperty("algorithm").toString();
            final String label = String.format("Service id %s, names: %s, algorithm: %s", id, Arrays.toString(names), algorithm);
            builder.append("<option value=\"").append(id).append("\">");
            builder.append(label);
            builder.append("</option>");
        }
        builder.append("</label>");
        builder.append("</select>");
        builder.append("<br>");
        builder.append("<button type=\"submit\">encrypt</button>");
        builder.append("</form>");
        return builder.toString();
    }

    private @Nullable CryptoService findCryptoService(@NotNull final String id) {
        final ServiceReference<CryptoService>[] references = tracker.getServiceReferences();
        if (Objects.isNull(references) || references.length == 0) {
            return null;
        }
        for (final ServiceReference<CryptoService> reference : references) {
            if (id.equals(reference.getProperty(Constants.SERVICE_ID).toString())) {
                return bundleContext.getService(reference);
            }
        }
        return null;
    }

    private static class GetHttpServletRequestWrapper extends HttpServletRequestWrapper {

        GetHttpServletRequestWrapper(final HttpServletRequest request) {
            super(request);
        }

        @Override
        public String getMethod() {
            return "GET";
        }

    }

}
