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
package com.dremio.iceberg.authmgr.oauth2.auth;

import com.dremio.iceberg.authmgr.oauth2.config.Secret;
import com.dremio.iceberg.authmgr.oauth2.rest.ClientCredentialsTokenRequest;
import com.dremio.iceberg.authmgr.oauth2.rest.ClientRequest;
import com.dremio.iceberg.authmgr.oauth2.rest.ClientRequest.Builder;
import com.dremio.iceberg.authmgr.oauth2.rest.TokenExchangeRequest;
import com.dremio.iceberg.authmgr.oauth2.token.Tokens;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import jakarta.annotation.Nullable;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/** A non-standard client authenticator targeting the Iceberg REST dialect. */
@AuthManagerImmutable
public abstract class IcebergClientAuthenticator implements ClientAuthenticator {

  abstract Optional<String> getClientId();

  abstract Optional<Secret> getClientSecret();

  @Override
  public final <R extends ClientRequest, B extends Builder<R, B>> void authenticate(
      ClientRequest.Builder<R, B> request,
      Map<String, String> headers,
      @Nullable Tokens currentTokens) {
    if (request instanceof ClientCredentialsTokenRequest.Builder) {
      // initial token fetches: use client_secret_post style, except that
      // both client id and client secret could be absent
      getClientId().ifPresent(request::clientId);
      getClientSecret().map(Secret::getSecret).ifPresent(request::clientSecret);
    } else if (request instanceof TokenExchangeRequest.Builder) {
      // token refreshes: use client_secret_basic style if possible,
      // otherwise bearer token (non-standard)
      if (getClientId().isPresent() && getClientSecret().isPresent()) {
        String auth =
            Base64.getEncoder()
                .encodeToString(
                    (getClientId().get() + ":" + getClientSecret().get().getSecret())
                        .getBytes(StandardCharsets.UTF_8));
        headers.put("Authorization", "Basic " + auth);
      } else {
        headers.put(
            "Authorization",
            "Bearer " + Objects.requireNonNull(currentTokens).getAccessToken().getPayload());
      }
    } else {
      throw new IllegalArgumentException(
          "Unsupported request builder type for Iceberg REST dialect: "
              + request.getClass().getName());
    }
  }
}
