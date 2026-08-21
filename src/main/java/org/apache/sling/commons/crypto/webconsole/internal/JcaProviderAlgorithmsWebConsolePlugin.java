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
import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;
import java.util.Collection;
import java.util.LinkedList;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.stream.Stream;

import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.osgi.service.component.annotations.Component;

/**
 * Web Console plugin to list the algorithms for service types of JCA providers.
 */
@Component(
    service = Servlet.class,
    property = {
        "felix.webconsole.label=sling-commons-crypto-jca-provider-algorithms",
        "felix.webconsole.title=JCA Provider Algorithms",
        "felix.webconsole.category=Sling"
    }
)
@SuppressWarnings({"java:S1989", "java:S2226", "java:S6212"})
public final class JcaProviderAlgorithmsWebConsolePlugin extends HttpServlet {

    private static final String PARAMETER_PROVIDER_NAME = "provider";
    private static final String PARAMETER_SERVICE_TYPE = "servicetype";
    private static final String PARAMETER_VALUE_ALL = "all";


    public JcaProviderAlgorithmsWebConsolePlugin() { //
    }


    @Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response) throws ServletException, IOException {
        final Provider[] providers = Security.getProviders();
        final String providerName = Objects.toString(request.getParameter(PARAMETER_PROVIDER_NAME), PARAMETER_VALUE_ALL);
        final String serviceType = Objects.toString(request.getParameter(PARAMETER_SERVICE_TYPE), PARAMETER_VALUE_ALL);
        
        final PrintWriter writer = response.getWriter();
        Collection<Service> services = new LinkedList<>();
        Consumer<Service> serviceConsumer = services::add;
        writeForm(writer, serviceConsumer, providerName, serviceType, providers);
        
        writer.println("<table class='tablesorter nicetable'>");
        writer.println("<thead>");
        writer.println("<tr><th class='col-provider'>Provider</th><th class='col-typr'>Type</th><th class='col-algo'>Algorithm</th><th class='col-class'>Class Name</th></tr>");
        writer.println("</thead>");
        writer.println("<tbody>");
        for (Service service : services) {
            writer.println("<tr>");
            writeTableCell(writer, service.getProvider().getName());
            writeTableCell(writer, service.getType());
            writeTableCell(writer, service.getAlgorithm());
            writeTableCell(writer, service.getClassName());
            writer.println("</tr>");
        }
        writer.println("</tbody>");
        writer.println("</table>");
    }

    private void writeTableCell(final PrintWriter writer, String text) {
        writer.println("<td>" + escapeHtml(text) + "</td>");
    }

    private @NotNull void writeForm(@NotNull PrintWriter writer, @NotNull Consumer<Service> serviceConsumer, @NotNull String selectedProviderName, @NotNull String selectedServiceType, Provider...providers) {
        writer.append("<form method=\"GET\">");
        writer.append("<div class=\"ui-widget-header ui-corner-top buttonGroup\">");
        writer.append("<label for=\"").append(PARAMETER_PROVIDER_NAME).append("\">Provider</label>");
        writer.append("<select id=\"").append(PARAMETER_PROVIDER_NAME).append("\" name=\"").append(PARAMETER_PROVIDER_NAME).append("\">");
        // add an entry for all providers
        Provider selectedProvider = null;
        writeOption(writer, PARAMETER_VALUE_ALL, null, "All Providers", null);
        for (Provider provider : Security.getProviders()) {
            writeOption(writer, provider.getName(), selectedProviderName, provider.getName(), provider.getInfo());
            if (provider.getName().equals(selectedProviderName)) {
                selectedProvider = provider;
            }
        }
        writer.append("</select>");
        writer.append("<br>");
        writer.append("<label for=\"").append(PARAMETER_SERVICE_TYPE).append("\">Service Type</label>");
        writer.append("<select id=\"").append(PARAMETER_SERVICE_TYPE).append("\" name=\"").append(PARAMETER_SERVICE_TYPE).append("\">");
        writeOption(writer, PARAMETER_VALUE_ALL, null, "All Types", null);
        ServiceTypePredicate serviceTypePredicate = new ServiceTypePredicate(selectedServiceType);
        // entry for service types for that provider
        if (Objects.nonNull(selectedProvider)) {
            selectedProvider.getServices().stream()
                .filter(serviceTypePredicate)
                .forEach(serviceConsumer);
            selectedProvider.getServices().stream()
                .map(Provider.Service::getType)
                .distinct()
                .sorted()
                .forEach(serviceType -> 
                    writeOption(writer, serviceType, selectedServiceType, serviceType, null)
                );
        } else {
            Stream.of(providers).map(Provider::getServices).flatMap(Collection::stream).filter(serviceTypePredicate).forEach(serviceConsumer);
            Stream.of(providers).map(Provider::getServices).flatMap(Collection::stream)
                .map(Provider.Service::getType).distinct().sorted()
                    .forEach(serviceType -> 
                        writeOption(writer, serviceType, selectedServiceType, serviceType, null)
                    );
        }
        writer.append("</select>");
        writer.append("</div>");
        writer.append("</form>");
        
        writer.append("<script>")
               .append("(function(){")
               .append("var providerSelect=document.getElementById('").append(PARAMETER_PROVIDER_NAME).append("');")
               .append("var serviceTypeSelect=document.getElementById('").append(PARAMETER_SERVICE_TYPE).append("');")
               .append("if(!providerSelect){return;}")
               .append("function updateUrl(){")
               .append("var url=new URL(window.location.href);")
               .append("url.searchParams.set('").append(PARAMETER_PROVIDER_NAME).append("',providerSelect.value);")
               .append("if(serviceTypeSelect){")
               .append("var stValue=serviceTypeSelect.value;")
               .append("if(stValue==='").append(PARAMETER_VALUE_ALL).append("'){url.searchParams.delete('").append(PARAMETER_SERVICE_TYPE).append("');}else{url.searchParams.set('").append(PARAMETER_SERVICE_TYPE).append("',stValue);}}")
               .append("else{url.searchParams.delete('").append(PARAMETER_SERVICE_TYPE).append("');}")
               .append("window.location.href=url.toString();}")
               .append("providerSelect.addEventListener('change',function(){")
               .append("var url=new URL(window.location.href);")
               .append("url.searchParams.set('").append(PARAMETER_PROVIDER_NAME).append("',providerSelect.value);")
               .append("url.searchParams.delete('").append(PARAMETER_SERVICE_TYPE).append("');")
               .append("window.location.href=url.toString();")
               .append("});")
               .append("if(serviceTypeSelect){")
               .append("serviceTypeSelect.addEventListener('change',updateUrl);")
               .append("}")
               .append("})();")
               .append("</script>");
    }

    static class ServiceTypePredicate implements java.util.function.Predicate<Provider.Service> {
        private final String serviceType;

        public ServiceTypePredicate(String serviceType) {
            this.serviceType = serviceType;
        }

        @Override
        public boolean test(Provider.Service service) {
            return PARAMETER_VALUE_ALL.equals(serviceType) || service.getType().equals(serviceType);
        }
    }

    private void writeOption(@NotNull PrintWriter writer, @NotNull String value, @Nullable String selectedValue, @NotNull String label, @Nullable String title) {
        writer.append("<option value=\"").append(escapeHtml(value)).append("\"");
        if (value.equals(selectedValue)) {
            writer.append("selected");
        }
        if (title != null && !title.isEmpty()) {
            writer.append(" title=\"").append(escapeHtml(title)).append("\"");
        }
        writer.append(">");
        writer.append(escapeHtml(label));
        writer.append("</option>");
    }

    protected static String escapeHtml(@NotNull String input) {
        return input.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace("\"", "&quot;")
                    .replace("'", "&#x27;")
                    .replace("/", "&#x2F;");
    }
}