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

import org.apache.sling.testing.paxexam.SlingOptions;
import org.ops4j.pax.exam.Configuration;
import org.ops4j.pax.exam.Option;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerMethod;

import static org.ops4j.pax.exam.CoreOptions.mavenBundle;
import static org.ops4j.pax.exam.OptionUtils.combine;

@ExamReactorStrategy(PerMethod.class)
public class EncryptWebConsolePluginHttpWhiteboardIT extends EncryptWebConsolePluginIT {

    @Configuration
    public Option[] configuration() {
        SlingOptions.versionResolver.setVersion("org.apache.felix", "org.apache.felix.http.jetty", "5.1.26");
        SlingOptions.versionResolver.setVersion("org.apache.felix", "org.apache.felix.http.servlet-api", "3.0.0");
        SlingOptions.versionResolver.setVersion("org.apache.felix", "org.apache.felix.webconsole", "5.0.8");
        return combine(
            super.configuration(),
            mavenBundle().groupId("org.owasp.encoder").artifactId("encoder").version("1.3.1")
        );
    }

}
