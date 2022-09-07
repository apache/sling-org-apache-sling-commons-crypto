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
import org.apache.sling.testing.paxexam.TestSupport;
import org.ops4j.pax.exam.options.ModifiableCompositeOption;

import static org.apache.sling.testing.paxexam.SlingOptions.scr;
import static org.ops4j.pax.exam.CoreOptions.composite;

public abstract class CryptoTestSupport extends TestSupport {

    public ModifiableCompositeOption baseConfiguration() {
        SlingOptions.versionResolver.setVersion("org.apache.felix", "org.apache.felix.http.jetty", "4.0.14"); // 4.0.16 is incompatible due to change in Jetty 9.4.21
        return composite(
            super.baseConfiguration(),
            // Sling Commons Crypto
            testBundle("bundle.filename"),
            scr()
        );
    }

}
