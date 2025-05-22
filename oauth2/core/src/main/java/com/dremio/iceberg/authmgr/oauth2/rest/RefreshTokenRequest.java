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

import com.dremio.iceberg.authmgr.oauth2.grant.GrantType;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.util.HashMap;
import java.util.Map;

/**
 * A <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-6">Token Request</a> that uses
 * the "refresh_tokens" grant type to refresh an existing access token.
 *
 * <p>Example:
 *
 * <pre>{@code
 * POST /token HTTP/1.1
 * Host: server.example.com
 * Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
 * Content-Type: application/x-www-form-urlencoded
 *
 * grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA
 * }</pre>
 */
@AuthManagerImmutable
public abstract class RefreshTokenRequest implements TokenRequest {

  @Override
  public final GrantType getGrantType() {
    return GrantType.REFRESH_TOKEN;
  }

  /** The refresh token issued to the client. */
  public abstract String getRefreshToken();

  @Override
  public final Map<String, String> asFormParameters() {
    Map<String, String> data = new HashMap<>(TokenRequest.super.asFormParameters());
    data.put("refresh_token", getRefreshToken());
    return Map.copyOf(data);
  }

  public static Builder builder() {
    return ImmutableRefreshTokenRequest.builder();
  }

  public interface Builder extends TokenRequest.Builder<RefreshTokenRequest, Builder> {

    @CanIgnoreReturnValue
    Builder refreshToken(String refreshToken);
  }
}
