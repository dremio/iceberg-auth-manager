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

import com.dremio.iceberg.authmgr.oauth2.rest.ImmutableMetadataDiscoveryResponse;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
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
      ImmutableMetadataDiscoveryResponse.Builder builder =
          ImmutableMetadataDiscoveryResponse.builder()
              .issuerUrl(issuerUrl)
              .tokenEndpoint(getTestEnvironment().getTokenEndpoint())
              .authorizationEndpoint(getTestEnvironment().getAuthorizationEndpoint());
      if (getTestEnvironment().isIncludeDeviceAuthEndpointInDiscoveryMetadata()) {
        builder.deviceAuthorizationEndpoint(getTestEnvironment().getDeviceAuthorizationEndpoint());
      }
      getClientAndServer()
          .when(
              HttpRequest.request()
                  .withMethod("GET")
                  .withPath(discoveryEndpoint.getPath())
                  .withHeader("Accept", "application/json"))
          .respond(HttpResponse.response().withBody(getJsonBody(builder.build())));
    }
    if (getTestEnvironment().isImpersonationDiscoveryEnabled()) {
      URI issuerUrl = getTestEnvironment().getImpersonationServerUrl();
      URI discoveryEndpoint = getTestEnvironment().getImpersonationDiscoveryEndpoint();
      ImmutableMetadataDiscoveryResponse.Builder builder =
          ImmutableMetadataDiscoveryResponse.builder()
              .issuerUrl(issuerUrl)
              .tokenEndpoint(getTestEnvironment().getImpersonationTokenEndpoint())
              .authorizationEndpoint(getTestEnvironment().getAuthorizationEndpoint());
      getClientAndServer()
          .when(
              HttpRequest.request()
                  .withMethod("GET")
                  .withPath(discoveryEndpoint.getPath())
                  .withHeader("Accept", "application/json"))
          .respond(HttpResponse.response().withBody(getJsonBody(builder.build())));
    }
  }
}
