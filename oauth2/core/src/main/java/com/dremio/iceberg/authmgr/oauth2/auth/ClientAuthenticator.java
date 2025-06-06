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
import jakarta.annotation.Nullable;
import java.util.Map;

/**
 * A client authenticator. This interface is used to authenticate a client by adding the necessary
 * authentication information to the request.
 */
public interface ClientAuthenticator {

  /**
   * Authenticates a client by adding the necessary authentication information to the request.
   *
   * @param request the {@link ClientRequest.Builder request} to authenticate
   * @param headers the current request headers; the map is mutable and can be modified
   * @param currentTokens the current tokens; may be null if no tokens are available (this parameter
   *     is only useful for Iceberg REST dialect authentication)
   * @param <R> the type of the request
   * @param <B> the type of the request builder
   */
  <R extends ClientRequest, B extends Builder<R, B>> void authenticate(
      Builder<R, B> request, Map<String, String> headers, @Nullable Tokens currentTokens);
}
