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
package com.dremio.iceberg.authmgr.oauth2.test.expectation;

import static com.dremio.iceberg.authmgr.oauth2.test.expectation.ExpectationUtils.getJsonBody;

import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.google.common.collect.ImmutableMap;
import java.net.URI;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

@AuthManagerImmutable
public abstract class MetadataDiscoveryExpectation extends AbstractExpectation {

  @Override
  public void create() {
    if (getTestEnvironment().isDiscoveryEnabled()) {
      URI issuerUrl = getTestEnvironment().getAuthorizationServerUrl();
      URI discoveryEndpoint = getTestEnvironment().getDiscoveryEndpoint();
      ImmutableMap.Builder<String, Object> builder =
          ImmutableMap.<String, Object>builder()
              .put("issuer", issuerUrl.toString())
              .put(
                  "authorization_endpoint",
                  getTestEnvironment().getAuthorizationEndpoint().toString())
              .put("token_endpoint", getTestEnvironment().getTokenEndpoint().toString());
      if (getTestEnvironment().isIncludeDeviceAuthEndpointInDiscoveryMetadata()) {
        builder.put(
            "device_authorization_endpoint",
            getTestEnvironment().getDeviceAuthorizationEndpoint().toString());
      }
      getClientAndServer()
          .when(HttpRequest.request().withMethod("GET").withPath(discoveryEndpoint.getPath()))
          .respond(HttpResponse.response().withBody(getJsonBody(builder.build())));
    }
  }
}
