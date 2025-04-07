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

import com.dremio.iceberg.authmgr.oauth2.rest.ClientRequest;
import com.dremio.iceberg.authmgr.oauth2.rest.ClientRequest.Builder;
import com.dremio.iceberg.authmgr.oauth2.token.Tokens;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import jakarta.annotation.Nullable;
import java.util.Map;

/**
 * A Client authentication method for clients in possession of a client password, using request body
 * parameters.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1">OAuth 2.0
 *     specification, Section 2.3.1</a>.
 */
@AuthManagerImmutable
abstract class ClientSecretPostClientAuthenticator implements ClientSecretAuthenticator {

  @Override
  public final <R extends ClientRequest, B extends Builder<R, B>> void authenticate(
      Builder<R, B> request, Map<String, String> headers, @Nullable Tokens currentTokens) {
    request.clientId(getClientId());
    request.clientSecret(getClientSecret().getSecret());
  }
}
