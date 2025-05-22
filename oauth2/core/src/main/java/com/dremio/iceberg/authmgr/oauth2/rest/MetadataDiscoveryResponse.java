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
package com.dremio.iceberg.authmgr.oauth2.rest;

import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import jakarta.annotation.Nullable;
import java.net.URI;
import java.util.Map;
import org.apache.iceberg.rest.RESTResponse;

/**
 * The response from the OpenID Connect Discovery endpoint.
 *
 * @see <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata">OpenID
 *     Connect Discovery 1.0</a>
 * @see <a href="https://tools.ietf.org/html/rfc8414#section-5">RFC 8414 Section 5</a>
 */
@AuthManagerImmutable
@JsonSerialize(as = ImmutableMetadataDiscoveryResponse.class)
@JsonDeserialize(as = ImmutableMetadataDiscoveryResponse.class)
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public abstract class MetadataDiscoveryResponse implements RESTResponse {

  @Override
  public final void validate() {}

  /**
   * URL using the https scheme with no query or fragment components that the OP asserts as its
   * Issuer Identifier.
   */
  @JsonProperty("issuer")
  public abstract URI getIssuerUrl();

  /**
   * URL of the OP's OAuth 2.0 Authorization Endpoint. This URL MUST use the https scheme and MAY
   * contain port, path, and query parameter components.
   */
  public abstract URI getAuthorizationEndpoint();

  /**
   * URL of the OP's OAuth 2.0 Token Endpoint. This is REQUIRED unless only the Implicit Flow is
   * used. This URL MUST use the https scheme and MAY contain port, path, and query parameter
   * components.
   */
  public abstract URI getTokenEndpoint();

  /**
   * OPTIONAL. URL of the authorization server's device authorization endpoint.
   *
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc8628#section-4">RFC 8628 Section 4</a>
   */
  @Nullable
  public abstract URI getDeviceAuthorizationEndpoint();

  @JsonAnyGetter
  public abstract Map<String, Object> getExtraParameters();
}
