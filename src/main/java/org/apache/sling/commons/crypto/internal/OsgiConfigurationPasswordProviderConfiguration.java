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
import org.osgi.service.metatype.annotations.AttributeType;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;

@ObjectClassDefinition(
    name = "Apache Sling Commons Crypto OSGi Configuration Password Provider",
    description = "Provides passwords from OSGi configurations."
)
@interface OsgiConfigurationPasswordProviderConfiguration {

    @AttributeDefinition(
        name = "Names",
        description = "Names of this service",
        required = false
    )
    String[] names() default {};

    @AttributeDefinition(
        type = AttributeType.PASSWORD,
        name = "Password",
        description = "The actual password. For security reasons only use with interpolation to reference external values via pattern \"$[secret:...]\" as outlined in https://github.com/apache/felix-dev/blob/master/configadmin-plugins/interpolation/README.md, e.g. \"$[secret:sling.crypto.password]\"."
    )
    String _password();

    String webconsole_configurationFactory_nameHint() default "{names}";

}
