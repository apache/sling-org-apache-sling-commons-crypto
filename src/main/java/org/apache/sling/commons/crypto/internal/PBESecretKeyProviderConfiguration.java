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

import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;

@ObjectClassDefinition(
    name = "Apache Sling Commons Crypto “PBE SecretKey Provider”",
    description = "Provides secret keys for password-based encryption (PBE)"
)
@interface PBESecretKeyProviderConfiguration {

    @AttributeDefinition(
        name = "Names",
        description = "names of this service",
        required = false
    )
    String[] names() default {};

    @AttributeDefinition(
        name = "Algorithm",
        description = "standard name of the requested secret-key algorithm"
    )
    String algorithm() default "PBKDF2WithHmacSHA1";

    @AttributeDefinition(
        name = "Iteration Count",
        description = "iteration count"
    )
    int iterationCount() default 1024;

    @AttributeDefinition(
        name = "Key Length",
        description = "to-be-derived key length"
    )
    int keyLength() default 256;

    @AttributeDefinition(
        name = "Password Provider Target",
        description = "filter expression to target a Password Provider",
        required = false
    )
    String passwordProvider_target();

    @AttributeDefinition(
        name = "Salt Provider Target",
        description = "filter expression to target a Salt Provider",
        required = false
    )
    String saltProvider_target();

    String webconsole_configurationFactory_nameHint() default "{names} {algorithm}";

}
