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
package com.dremio.iceberg.authmgr.oauth2.rest;

import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import jakarta.annotation.Nullable;
import java.net.URI;
import org.apache.iceberg.rest.RESTResponse;

/**
 * A device authorization response as defined in <a
 * href="https://tools.ietf.org/html/rfc8628#section-3.2">RFC 8628 Section 3.2</a>.
 *
 * <p>Example of response:
 *
 * <pre>{@code
 * HTTP/1.1 200 OK
 * Content-Type: application/json;charset=UTF-8
 * Cache-Control: no-store
 * Pragma: no-cache
 *
 * {
 * "device_code":"GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
 * "user_code":"WDJB-MJHT",
 * "verification_uri":"https://example.com/device",
 * "verification_uri_complete":"https://example.com/device?user_code=WDJB-MJHT",
 * "expires_in":1800,
 * "interval":5
 * }
 * }</pre>
 */
@AuthManagerImmutable
@JsonSerialize(as = ImmutableDeviceAuthorizationResponse.class)
@JsonDeserialize(as = ImmutableDeviceAuthorizationResponse.class)
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public abstract class DeviceAuthorizationResponse implements RESTResponse {

  @Override
  public final void validate() {}

  /** The device verification code. */
  public abstract String getDeviceCode();

  /** The end-user verification code. */
  public abstract String getUserCode();

  /**
   * The end-user verification URI on the authorization server. The URI should be short and easy to
   * remember as end users will be asked to manually type it into their user agent.
   */
  public abstract URI getVerificationUri();

  /**
   * OPTIONAL. A verification URI that includes the "user_code" (or other information with the same
   * function as the "user_code"), which is designed for non-textual transmission.
   */
  @Nullable
  public abstract URI getVerificationUriComplete();

  /** The lifetime in seconds of the "device_code" and "user_code". */
  @JsonProperty("expires_in")
  public abstract int getExpiresInSeconds();

  /**
   * OPTIONAL. The minimum amount of time in seconds that the client SHOULD wait between polling
   * requests to the token endpoint. If no value is provided, clients MUST use 5 as the default.
   */
  @Nullable
  @JsonProperty("interval")
  public abstract Integer getIntervalSeconds();
}
