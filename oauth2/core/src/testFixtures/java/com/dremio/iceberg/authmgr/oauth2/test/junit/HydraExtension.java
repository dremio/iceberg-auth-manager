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

import com.dremio.iceberg.authmgr.oauth2.test.ImmutableTestEnvironment;
import com.dremio.iceberg.authmgr.oauth2.test.TestConstants;
import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironment;
import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironmentExtension;
import com.dremio.iceberg.authmgr.oauth2.test.container.HydraContainer;
import com.nimbusds.oauth2.sdk.Scope;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

public class HydraExtension extends TestEnvironmentExtension
    implements BeforeAllCallback, AfterAllCallback {

  // Client1 is used for client_secret_basic authentication
  public static final String CLIENT_ID1 = TestConstants.CLIENT_ID1.getValue();
  public static final String CLIENT_SECRET1 = TestConstants.CLIENT_SECRET1.getValue();

  // Client2 is used for client_secret_post authentication
  public static final String CLIENT_ID2 = TestConstants.CLIENT_ID2.getValue();
  public static final String CLIENT_SECRET2 = TestConstants.CLIENT_SECRET2.getValue();

  // Client3 is used for public client (no authentication)
  public static final String CLIENT_ID3 = "Client3";

  public static final String SCOPE1 = TestConstants.SCOPE1.toString();

  @Override
  public void beforeAll(ExtensionContext context) {
    HydraContainer hydra =
        new HydraContainer()
            .withClient(CLIENT_ID1, CLIENT_SECRET1, "client_secret_basic")
            .withClient(CLIENT_ID2, CLIENT_SECRET2, "client_secret_post")
            .withClient(CLIENT_ID3, null, "none");
    hydra.start();
    context.getStore(ExtensionContext.Namespace.GLOBAL).put(HydraContainer.class.getName(), hydra);
  }

  @Override
  public void afterAll(ExtensionContext context) {
    HydraContainer hydra =
        context
            .getStore(ExtensionContext.Namespace.GLOBAL)
            .remove(HydraContainer.class.getName(), HydraContainer.class);
    if (hydra != null) {
      hydra.close();
    }
  }

  @Override
  protected ImmutableTestEnvironment.Builder newTestEnvironmentBuilder(ExtensionContext context) {
    HydraContainer hydra =
        context
            .getStore(ExtensionContext.Namespace.GLOBAL)
            .get(HydraContainer.class.getName(), HydraContainer.class);
    // Note: Hydra doesn't support device code flow nor token exchange
    // Note: cannot use metadata discovery, the URLs are internal to the container network
    return TestEnvironment.builder()
        .unitTest(false)
        .discoveryEnabled(false)
        .scope(new Scope(SCOPE1))
        .serverRootUrl(hydra.getPublicUrl())
        .tokenEndpoint(hydra.getTokenEndpoint())
        .authorizationEndpoint(hydra.getAuthEndpoint());
  }
}
