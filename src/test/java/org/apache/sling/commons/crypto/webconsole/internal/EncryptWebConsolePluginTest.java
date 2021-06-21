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
import java.io.StringWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.osgi.framework.BundleContext;

import static com.google.common.truth.Truth.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class EncryptWebConsolePluginTest {

    @Test
    public void testGetWithNoCryptoServicesAvailable() throws ServletException, IOException {
        final BundleContext bundleContext = mock(BundleContext.class);
        final HttpServletRequest request = mock(HttpServletRequest.class);
        final StringWriter stringWriter = new StringWriter();
        final PrintWriter printWriter = new PrintWriter(stringWriter, true);
        final HttpServletResponse response = mock(HttpServletResponse.class);
        when(response.getWriter()).thenReturn(printWriter);
        final EncryptWebConsolePlugin plugin = new EncryptWebConsolePlugin();
        plugin.activate(bundleContext);
        plugin.doGet(request, response);
        plugin.deactivate();
        assertThat(stringWriter.toString()).contains("<p>No crypto service available</p>");
    }

    @Test
    public void testDeactivateWithNoServiceTracker() {
        final EncryptWebConsolePlugin plugin = new EncryptWebConsolePlugin();
        plugin.deactivate();
    }

}
