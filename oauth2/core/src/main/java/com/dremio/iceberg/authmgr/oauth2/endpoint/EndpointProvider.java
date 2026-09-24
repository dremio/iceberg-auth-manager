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
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.as.ReadOnlyAuthorizationServerEndpointMetadata;
import com.nimbusds.oauth2.sdk.as.ReadOnlyAuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.http.HTTPRequestSender;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderConfigurationRequest;
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

  /**
   * Returns the token endpoint URI to use for mTLS client authentication, preferring {@code
   * mtls_endpoint_aliases.token_endpoint} from server metadata per RFC 8705 §9.2, with fallback to
   * the plain {@code token_endpoint}. If the token endpoint was explicitly configured, it is
   * returned as-is (explicit configuration always takes priority over discovery).
   */
  @Value.Lazy
  public URI getResolvedMtlsTokenEndpoint() {
    if (getTokenEndpoint().isPresent()) {
      return getTokenEndpoint().get();
    }
    ReadOnlyAuthorizationServerMetadata metadata = getOpenIdProviderMetadata();
    ReadOnlyAuthorizationServerEndpointMetadata aliases = metadata.getReadOnlyMtlsEndpointAliases();
    if (aliases != null && aliases.getTokenEndpointURI() != null) {
      return aliases.getTokenEndpointURI();
    }
    return metadata.getTokenEndpointURI();
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
  protected ReadOnlyAuthorizationServerMetadata getOpenIdProviderMetadata() {
    URI issuerUrl =
        getIssuerUrl().orElseThrow(() -> new IllegalStateException("No issuer URL configured"));
    return fetchOpenIdProviderMetadata(issuerUrl);
  }

  private ReadOnlyAuthorizationServerMetadata fetchOpenIdProviderMetadata(URI issuerUrl) {
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

  private ReadOnlyAuthorizationServerMetadata oidcProvider(Issuer issuer)
      throws IOException, ParseException {
    AbstractConfigurationRequest request = new OIDCProviderConfigurationRequest(issuer);
    HTTPResponse httpResponse = request.toHTTPRequest().send(getHttpClient());
    if (httpResponse.indicatesSuccess()) {
      // Parse as AuthorizationServerMetadata rather than OIDCProviderMetadata: the AS variant is
      // more lenient (only requires "issuer") and covers all the fields we actually consume
      // (token_endpoint, authorization_endpoint, device_authorization_endpoint,
      // mtls_endpoint_aliases). OIDC-specific fields (jwks_uri, etc.) are unused here.
      return AuthorizationServerMetadata.parse(httpResponse.getBodyAsJSONObject());
    }
    throw providerFailure("OIDC", httpResponse);
  }

  private ReadOnlyAuthorizationServerMetadata oauthProvider(Issuer issuer)
      throws IOException, ParseException {
    AbstractConfigurationRequest request = new AuthorizationServerConfigurationRequest(issuer);
    HTTPResponse httpResponse = request.toHTTPRequest().send(getHttpClient());
    if (httpResponse.indicatesSuccess()) {
      return AuthorizationServerMetadata.parse(httpResponse.getBodyAsJSONObject());
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
    ReadOnlyAuthorizationServerMetadata fetchMetadata(Issuer issuer)
        throws IOException, ParseException;
  }
}
