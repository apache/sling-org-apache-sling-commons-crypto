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

import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;
import org.osgi.service.metatype.annotations.Option;

import static org.jasypt.commons.CommonUtils.STRING_OUTPUT_TYPE_BASE64;
import static org.jasypt.commons.CommonUtils.STRING_OUTPUT_TYPE_HEXADECIMAL;
import static org.jasypt.encryption.pbe.StandardPBEByteEncryptor.DEFAULT_KEY_OBTENTION_ITERATIONS;

@ObjectClassDefinition(
    name = "Apache Sling Commons Crypto “Jasypt Standard PBE String Crypto Service”",
    description = "Crypto service which uses Jasypt StandardPBEStringEncryptor for encryption and decryption"
)
@SuppressWarnings("java:S100")
@interface JasyptStandardPbeStringCryptoServiceConfiguration {

    @AttributeDefinition(
        name = "Names",
        description = "names of this service",
        required = false
    )
    String[] names() default {};

    @AttributeDefinition(
        name = "Algorithm",
        description = "crypto algorithm"
    )
    String algorithm() default "PBEWITHHMACSHA512ANDAES_256";

    @AttributeDefinition(
        name = "Key Obtention Iterations",
        description = "number of hashing iterations applied for obtaining the encryption key from the specified password"
    )
    int keyObtentionIterations() default DEFAULT_KEY_OBTENTION_ITERATIONS;

    @AttributeDefinition(
        name = "Security Provider Name",
        description = "name of the Security Provider",
        required = false
    )
    String securityProviderName();

    @AttributeDefinition(
        name = "String Output Type",
        description = "encoding format of the encrypted string output",
        options = {
            @Option(label = "Base16 (hexadecimal)", value = STRING_OUTPUT_TYPE_HEXADECIMAL),
            @Option(label = "Base64", value = STRING_OUTPUT_TYPE_BASE64)
        }
    )
    String stringOutputType() default STRING_OUTPUT_TYPE_BASE64;

    @AttributeDefinition(
        name = "Password Provider Target",
        description = "filter expression to target a Password Provider",
        required = false
    )
    String passwordProvider_target();

    @AttributeDefinition(
        name = "Security Provider Target",
        description = "filter expression to target a Security Provider",
        required = false
    )
    String securityProvider_target();

    @AttributeDefinition(
        name = "IV Generator Target",
        description = "filter expression to target an IV Generator",
        required = false
    )
    String ivGenerator_target();

    @AttributeDefinition(
        name = "Salt Generator Target",
        description = "filter expression to target a Salt Generator",
        required = false
    )
    String saltGenerator_target();

    String webconsole_configurationFactory_nameHint() default "{names} {algorithm}";

}
