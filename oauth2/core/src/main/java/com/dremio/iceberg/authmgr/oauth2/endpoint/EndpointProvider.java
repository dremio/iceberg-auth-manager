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
package com.dremio.iceberg.authmgr.oauth2.endpoint;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Config;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.nimbusds.oauth2.sdk.AbstractConfigurationRequest;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerConfigurationRequest;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerEndpointMetadata;
import com.nimbusds.oauth2.sdk.as.ReadOnlyAuthorizationServerEndpointMetadata;
import com.nimbusds.oauth2.sdk.http.HTTPRequestSender;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderConfigurationRequest;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderEndpointMetadata;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.immutables.value.Value;

@AuthManagerImmutable
public abstract class EndpointProvider {

  public static EndpointProvider create(OAuth2Config spec, HTTPRequestSender httpClient) {
    Builder builder = builder().httpClient(httpClient);
    spec.getBasicConfig().getIssuerUrl().ifPresent(builder::issuerUrl);
    spec.getBasicConfig().getTokenEndpoint().ifPresent(builder::tokenEndpoint);
    spec.getAuthorizationCodeConfig()
        .getAuthorizationEndpoint()
        .ifPresent(builder::authorizationEndpoint);
    spec.getDeviceCodeConfig()
        .getDeviceAuthorizationEndpoint()
        .ifPresent(builder::deviceAuthorizationEndpoint);
    return builder.build();
  }

  public interface Builder {

    @CanIgnoreReturnValue
    Builder from(EndpointProvider endpointProvider);

    @CanIgnoreReturnValue
    Builder issuerUrl(URI issuerUrl);

    @CanIgnoreReturnValue
    Builder tokenEndpoint(URI tokenEndpoint);

    @CanIgnoreReturnValue
    Builder authorizationEndpoint(URI authorizationEndpoint);

    @CanIgnoreReturnValue
    Builder deviceAuthorizationEndpoint(URI deviceAuthorizationEndpoint);

    @CanIgnoreReturnValue
    Builder httpClient(HTTPRequestSender httpClient);

    EndpointProvider build();
  }

  public static Builder builder() {
    return ImmutableEndpointProvider.builder();
  }

  protected abstract Optional<URI> getIssuerUrl();

  protected abstract Optional<URI> getTokenEndpoint();

  protected abstract Optional<URI> getAuthorizationEndpoint();

  protected abstract Optional<URI> getDeviceAuthorizationEndpoint();

  protected abstract HTTPRequestSender getHttpClient();

  @Value.Lazy
  public URI getResolvedTokenEndpoint() {
    return getTokenEndpoint().orElseGet(() -> getOpenIdProviderMetadata().getTokenEndpointURI());
  }

  @Value.Lazy
  public URI getResolvedAuthorizationEndpoint() {
    return getAuthorizationEndpoint()
        .orElseGet(() -> getOpenIdProviderMetadata().getAuthorizationEndpointURI());
  }

  @Value.Lazy
  public URI getResolvedDeviceAuthorizationEndpoint() {
    return getDeviceAuthorizationEndpoint()
        .or(
            () ->
                Optional.ofNullable(
                    getOpenIdProviderMetadata().getDeviceAuthorizationEndpointURI()))
        .orElseThrow(
            () ->
                new IllegalStateException(
                    "OpenID provider metadata does not contain a device authorization endpoint"));
  }

  @Value.Lazy
  protected ReadOnlyAuthorizationServerEndpointMetadata getOpenIdProviderMetadata() {
    URI issuerUrl =
        getIssuerUrl().orElseThrow(() -> new IllegalStateException("No issuer URL configured"));
    return fetchOpenIdProviderMetadata(issuerUrl);
  }

  private ReadOnlyAuthorizationServerEndpointMetadata fetchOpenIdProviderMetadata(URI issuerUrl) {
    Issuer issuer = new Issuer(issuerUrl);
    List<Exception> failures = null;
    for (MetadataProvider provider :
        List.<MetadataProvider>of(this::oidcProvider, this::oauthProvider)) {
      try {
        return provider.fetchMetadata(issuer);
      } catch (Exception e) {
        if (failures == null) {
          failures = new ArrayList<>(2);
        }
        failures.add(e);
      }
    }
    RuntimeException e = new RuntimeException("Failed to fetch provider metadata", failures.get(0));
    for (int i = 1; i < failures.size(); i++) {
      e.addSuppressed(failures.get(i));
    }
    throw e;
  }

  private ReadOnlyAuthorizationServerEndpointMetadata oidcProvider(Issuer issuer)
      throws IOException, ParseException {
    AbstractConfigurationRequest request = new OIDCProviderConfigurationRequest(issuer);
    HTTPResponse httpResponse = request.toHTTPRequest().send(getHttpClient());
    if (httpResponse.indicatesSuccess()) {
      return OIDCProviderEndpointMetadata.parse(httpResponse.getBodyAsJSONObject());
    }
    throw providerFailure("OIDC", httpResponse);
  }

  private ReadOnlyAuthorizationServerEndpointMetadata oauthProvider(Issuer issuer)
      throws IOException, ParseException {
    AbstractConfigurationRequest request = new AuthorizationServerConfigurationRequest(issuer);
    HTTPResponse httpResponse = request.toHTTPRequest().send(getHttpClient());
    if (httpResponse.indicatesSuccess()) {
      return AuthorizationServerEndpointMetadata.parse(httpResponse.getBodyAsJSONObject());
    }
    throw providerFailure("OAuth", httpResponse);
  }

  private static RuntimeException providerFailure(String type, HTTPResponse httpResponse) {
    return new RuntimeException(
        String.format(
            "Failed to fetch %s provider metadata: server returned code %d with message: %s",
            type, httpResponse.getStatusCode(), httpResponse.getBody()));
  }

  @FunctionalInterface
  private interface MetadataProvider {
    ReadOnlyAuthorizationServerEndpointMetadata fetchMetadata(Issuer issuer)
        throws IOException, ParseException;
  }
}
