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
package com.dremio.iceberg.authmgr.oauth2.flow;

import com.dremio.iceberg.authmgr.oauth2.agent.OAuth2AgentSpec;
import com.dremio.iceberg.authmgr.oauth2.rest.MetadataDiscoveryResponse;
import com.dremio.iceberg.authmgr.oauth2.uri.UriBuilder;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.apache.iceberg.exceptions.RESTException;
import org.apache.iceberg.rest.RESTClient;
import org.immutables.value.Value;

@AuthManagerImmutable
public abstract class EndpointResolver {

  /**
   * Common locations for OpenID provider metadata.
   *
   * @see <a
   *     href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata">OpenID
   *     Connect Discovery 1.0</a>
   * @see <a href="https://tools.ietf.org/html/rfc8414#section-5">RFC 8414 Section 5</a>
   */
  public static final List<String> WELL_KNOWN_PATHS =
      List.of(".well-known/openid-configuration", ".well-known/oauth-authorization-server");

  public interface Builder {

    @CanIgnoreReturnValue
    Builder spec(OAuth2AgentSpec spec);

    @CanIgnoreReturnValue
    Builder restClient(RESTClient restClient);

    EndpointResolver build();
  }

  public static Builder builder() {
    return ImmutableEndpointResolver.builder();
  }

  protected abstract OAuth2AgentSpec getSpec();

  protected abstract RESTClient getRestClient();

  @Value.Lazy
  public URI getResolvedTokenEndpoint() {
    return getSpec()
        .getBasicConfig()
        .getTokenEndpoint()
        .orElseGet(() -> getOpenIdProviderMetadata().getTokenEndpoint());
  }

  @Value.Lazy
  public URI getResolvedAuthorizationEndpoint() {
    return getSpec()
        .getAuthorizationCodeConfig()
        .getAuthorizationEndpoint()
        .orElseGet(() -> getOpenIdProviderMetadata().getAuthorizationEndpoint());
  }

  @Value.Lazy
  public URI getResolvedDeviceAuthorizationEndpoint() {
    return getSpec()
        .getDeviceCodeConfig()
        .getDeviceAuthorizationEndpoint()
        .or(() -> Optional.ofNullable(getOpenIdProviderMetadata().getDeviceAuthorizationEndpoint()))
        .orElseThrow(
            () ->
                new IllegalStateException(
                    "OpenID provider metadata does not contain a device authorization endpoint"));
  }

  @Value.Lazy
  public URI getResolvedImpersonationTokenEndpoint() {
    return getSpec()
        .getImpersonationConfig()
        .getTokenEndpoint()
        .or(
            () ->
                getImpersonationOpenIdProviderMetadata()
                    .map(MetadataDiscoveryResponse::getTokenEndpoint))
        .orElseGet(this::getResolvedTokenEndpoint);
  }

  @Value.Lazy
  protected MetadataDiscoveryResponse getOpenIdProviderMetadata() {
    URI issuerUrl =
        getSpec()
            .getBasicConfig()
            .getIssuerUrl()
            .orElseThrow(() -> new IllegalStateException("No issuer URL configured"));
    return fetchOpenIdProviderMetadata(issuerUrl);
  }

  @Value.Lazy
  protected Optional<MetadataDiscoveryResponse> getImpersonationOpenIdProviderMetadata() {
    return getSpec().getImpersonationConfig().getIssuerUrl().map(this::fetchOpenIdProviderMetadata);
  }

  private MetadataDiscoveryResponse fetchOpenIdProviderMetadata(URI issuerUrl) {
    List<Exception> failures = null;
    for (String path : WELL_KNOWN_PATHS) {
      try {
        URI uri = new UriBuilder(issuerUrl).path(path).build();
        return getRestClient()
            .get(
                uri.toString(),
                MetadataDiscoveryResponse.class,
                Map.of("Accept", "application/json"),
                FlowErrorHandler.INSTANCE);
      } catch (Exception e) {
        if (failures == null) {
          failures = new ArrayList<>(WELL_KNOWN_PATHS.size());
        }
        failures.add(e);
      }
    }
    assert failures != null;
    RESTException e =
        new RESTException(failures.get(0), "Failed to fetch OpenID provider metadata");
    for (int i = 1; i < failures.size(); i++) {
      e.addSuppressed(failures.get(i));
    }
    throw e;
  }
}
