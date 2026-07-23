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
package org.apache.sling.commons.crypto.jca.internal;

import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;

@ObjectClassDefinition(
    name = "Apache Sling Commons Crypto JCA PBE Crypto Service",
    description = "Crypto service which uses Java Crypto Architecture (JCA) with a password based key derivation function (KDF) and a symmetric cipher for encryption and decryption"
)
@interface JcaPbeCryptoServiceConfiguration {

    @AttributeDefinition(
        name = "Names",
        description = "names of this service",
        required = false
    )
    String[] names() default {};

    @AttributeDefinition(
        name = "Secret Key Factory Algorithm",
        description = "Algorithm to use for generating the secret key from the password. Standard names outlined in https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#secretkeyfactory-algorithm-names"
    )
    String secretKeyFactory() default "PBKDF2WithHmacSHA512";

    @AttributeDefinition(
        name = "Cipher Algorithm",
        description = "Symmetric cypher algorithm to use for encryption and decryption in the form \"<algorithm>/<mode>/<padding>\". Standard names outlined in https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#cipher-algorithm-names. Include mode and padding specifiers as well (otherwise a non suitable default may be picked)."
    )
    String cipherAlgorithm() default "AES/GCM/NoPadding";

    @AttributeDefinition(
        name = "Secure Random Algorithm",
        description = "Algorithm to use for generating secure random numbers. Standard names outlined in https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#securerandom-number-generation-algorithms"
    )
    String secureRandomAlgorithm() default "NativePRNGBlocking";

    @AttributeDefinition(
        name = "PBE Key Iteration Count",
        description = "Number of iterations to derive a key from the password as defined in the PBE algorithm. The higher the number of iterations, the more secure the key derivation is,"
                + " but it also increases the time taken to derive the key."
    )
    int numKeyIterations() default 65536;

    @AttributeDefinition(
        name = "PBE Key Length (bits)",
        description = "Length of the key to be derived from the password as defined in the PBE algorithm. The key length should be appropriate for the chosen symmetric cipher algorithm."
    )
    int keyLengthBits() default 256;

    @AttributeDefinition(
        name = "Security Provider Name",
        description = "Name of the Security Provider, must either be one of the standard names outlined in https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#provider-names or a custom provider name registered with the JVM.",
        required = false
    )
    String securityProviderName() default "SunJCE";

    @AttributeDefinition(
        name = "Service Ranking",
        description = "OSGi service.ranking value used to prioritize this service when multiple implementations are available."
    )
    int service_ranking() default 0;

    String webconsole_configurationFactory_nameHint() default "{names} {secretKeyFactory} {cipherAlgorithm}";

}