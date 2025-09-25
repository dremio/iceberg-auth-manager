/*
 * Copyright (C) 2025 Dremio Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.dremio.iceberg.authmgr.oauth2.test.junit;

import com.dremio.iceberg.authmgr.oauth2.http.HttpClientType;
import com.dremio.iceberg.authmgr.oauth2.test.ImmutableTestEnvironment;
import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironment;
import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironmentExtension;
import com.dremio.iceberg.authmgr.oauth2.test.container.AutheliaContainer;
import com.nimbusds.oauth2.sdk.Scope;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

public class AutheliaExtension extends TestEnvironmentExtension
    implements BeforeAllCallback, AfterAllCallback {

  // Client1 is used for client_secret_basic authentication
  public static final String CLIENT_ID1 = "Client1";
  public static final String CLIENT_SECRET1 = "s3cr3t";

  // Client2 is used for client_secret_post authentication
  public static final String CLIENT_ID2 = "Client2";
  public static final String CLIENT_SECRET2 = "s3cr3t";

  // Authelia's private key and certificate
  // These are classpath resources in the testFixtures resources directory
  public static final String PRIVATE_KEY = "openssl/rsa_private_key_pkcs8.pem";
  public static final String CERTIFICATE = "openssl/rsa_certificate.pem";

  @Override
  public void beforeAll(ExtensionContext context) {
    AutheliaContainer authelia = new AutheliaContainer(PRIVATE_KEY, CERTIFICATE);
    authelia.start();
    context
        .getStore(ExtensionContext.Namespace.GLOBAL)
        .put(AutheliaContainer.class.getName(), authelia);
  }

  @Override
  public void afterAll(ExtensionContext context) {
    AutheliaContainer authelia =
        context
            .getStore(ExtensionContext.Namespace.GLOBAL)
            .remove(AutheliaContainer.class.getName(), AutheliaContainer.class);
    if (authelia != null) {
      authelia.close();
    }
  }

  @Override
  protected ImmutableTestEnvironment.Builder newTestEnvironmentBuilder(ExtensionContext context) {
    AutheliaContainer authelia =
        context
            .getStore(ExtensionContext.Namespace.GLOBAL)
            .get(AutheliaContainer.class.getName(), AutheliaContainer.class);
    return TestEnvironment.builder()
        .unitTest(false)
        .discoveryEnabled(true)
        .sslTrustAll(true)
        .sslHostnameVerificationEnabled(false)
        .httpClientType(HttpClientType.APACHE) // required for SSL
        .serverRootUrl(authelia.getAutheliaUrl())
        .authorizationServerUrl(authelia.getAutheliaUrl())
        .scope(Scope.parse("profile"));
  }
}
