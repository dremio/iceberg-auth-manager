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

import com.dremio.iceberg.authmgr.oauth2.grant.GrantType;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.util.HashMap;
import java.util.Map;

/**
 * A device access token request as defined in <a
 * href="https://tools.ietf.org/html/rfc8628#section-3.4">RFC 8628 Section 3.4</a>.
 *
 * <p>Example of request:
 *
 * <pre>{@code
 * POST /token HTTP/1.1
 * Host: server.example.com
 * Content-Type: application/x-www-form-urlencoded
 *
 * grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code
 *     &device_code=GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS
 *     &client_id=1406020730
 * }</pre>
 */
@AuthManagerImmutable
public abstract class DeviceAccessTokenRequest implements TokenRequest {

  @Override
  public final GrantType getGrantType() {
    return GrantType.DEVICE_CODE;
  }

  /** The device verification code. */
  public abstract String getDeviceCode();

  @Override
  public final Map<String, String> asFormParameters() {
    Map<String, String> data = new HashMap<>(TokenRequest.super.asFormParameters());
    data.put("device_code", getDeviceCode());
    return Map.copyOf(data);
  }

  public static Builder builder() {
    return ImmutableDeviceAccessTokenRequest.builder();
  }

  public interface Builder extends TokenRequest.Builder<DeviceAccessTokenRequest, Builder> {

    @CanIgnoreReturnValue
    Builder deviceCode(String deviceCode);
  }
}
