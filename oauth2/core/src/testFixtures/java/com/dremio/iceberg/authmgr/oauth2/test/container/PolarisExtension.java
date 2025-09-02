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
package com.dremio.iceberg.authmgr.oauth2.test.container;

import com.dremio.iceberg.authmgr.oauth2.test.ImmutableTestEnvironment;
import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironment;
import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironmentExtension;
import com.nimbusds.oauth2.sdk.Scope;
import java.time.Clock;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

public class PolarisExtension extends TestEnvironmentExtension
    implements BeforeAllCallback, AfterAllCallback {

  @Override
  public void beforeAll(ExtensionContext context) {
    PolarisContainer polaris = new PolarisContainer();
    polaris.start();
    context
        .getStore(ExtensionContext.Namespace.GLOBAL)
        .put(PolarisContainer.class.getName(), polaris);
  }

  @Override
  public void afterAll(ExtensionContext context) {
    PolarisContainer polaris =
        context
            .getStore(ExtensionContext.Namespace.GLOBAL)
            .remove(PolarisContainer.class.getName(), PolarisContainer.class);
    if (polaris != null) {
      polaris.close();
    }
  }

  @Override
  protected ImmutableTestEnvironment.Builder newTestEnvironmentBuilder(ExtensionContext context) {
    PolarisContainer polaris =
        context
            .getStore(ExtensionContext.Namespace.GLOBAL)
            .get(PolarisContainer.class.getName(), PolarisContainer.class);
    return TestEnvironment.builder()
        .unitTest(false)
        .discoveryEnabled(false)
        .serverRootUrl(polaris.baseUri())
        .tokenEndpoint(polaris.getTokenEndpoint())
        .catalogServerContextPath("/api/catalog/")
        .scope(new Scope("PRINCIPAL_ROLE:ALL"))
        .clock(Clock.systemUTC())
        .accessTokenLifespan(polaris.getAccessTokenLifespan());
  }
}
