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

import java.io.PrintWriter;
import java.io.StringWriter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.reflect.MethodUtils;
import org.junit.Test;
import org.osgi.framework.BundleContext;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class EncryptWebConsolePluginTest {

    @Test
    public void testGetWithNoCryptoServicesAvailable() throws Exception {
        final BundleContext bundleContext = mock(BundleContext.class);
        final HttpServletRequest request = mock(HttpServletRequest.class);
        final StringWriter stringWriter = new StringWriter();
        final PrintWriter printWriter = new PrintWriter(stringWriter, true);
        final HttpServletResponse response = mock(HttpServletResponse.class);
        when(response.getWriter()).thenReturn(printWriter);
        final EncryptWebConsolePlugin plugin = new EncryptWebConsolePlugin();
        MethodUtils.invokeMethod(plugin, true, "activate", bundleContext);
        plugin.doGet(request, response);
        MethodUtils.invokeMethod(plugin, true, "deactivate");
        assertThat(stringWriter.toString(), containsString("<p>No crypto service available</p>"));
    }

    @Test
    public void testDeactivateWithNoServiceTracker() {
        final EncryptWebConsolePlugin plugin = new EncryptWebConsolePlugin();
        try {
            MethodUtils.invokeMethod(plugin, true, "deactivate");
        } catch (Exception e) {
            final String message = String.format("Deactivating component should not throw exception: %s", e.getMessage());
            fail(message);
        }
    }

    @Test
    public void testPostServiceIdParameterMissing() throws Exception {
        final BundleContext bundleContext = mock(BundleContext.class);
        final HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("service-id")).thenReturn(null);
        when(request.getParameter("message")).thenReturn("");
        final HttpServletResponse response = mock(HttpServletResponse.class);
        final EncryptWebConsolePlugin plugin = new EncryptWebConsolePlugin();
        MethodUtils.invokeMethod(plugin, true, "activate", bundleContext);
        plugin.doPost(request, response);
        verify(response).sendError(HttpServletResponse.SC_BAD_REQUEST, "Parameter service-id is missing");
    }

    @Test
    public void testPostMessageParameterMissing() throws Exception {
        final BundleContext bundleContext = mock(BundleContext.class);
        final HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("service-id")).thenReturn("");
        when(request.getParameter("message")).thenReturn(null);
        final HttpServletResponse response = mock(HttpServletResponse.class);
        final EncryptWebConsolePlugin plugin = new EncryptWebConsolePlugin();
        MethodUtils.invokeMethod(plugin, true, "activate", bundleContext);
        plugin.doPost(request, response);
        verify(response).sendError(HttpServletResponse.SC_BAD_REQUEST, "Parameter message is missing");
    }

    @Test
    public void testPostCryptoServiceNotAvailable() throws Exception {
        final BundleContext bundleContext = mock(BundleContext.class);
        final HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("service-id")).thenReturn("0");
        when(request.getParameter("message")).thenReturn("");
        final HttpServletResponse response = mock(HttpServletResponse.class);
        final EncryptWebConsolePlugin plugin = new EncryptWebConsolePlugin();
        MethodUtils.invokeMethod(plugin, true, "activate", bundleContext);
        plugin.doPost(request, response);
        verify(response).sendError(HttpServletResponse.SC_NOT_FOUND, "Crypto service with service id 0 not found");
    }

}
