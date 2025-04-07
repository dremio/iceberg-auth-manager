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
package com.dremio.iceberg.authmgr.oauth2.token.provider;

import com.dremio.iceberg.authmgr.oauth2.token.AccessToken;
import com.dremio.iceberg.authmgr.oauth2.token.TypedToken;
import jakarta.annotation.Nullable;

/**
 * A {@link TokenProvider} is a functional interface that provides a method to obtain a {@link
 * TypedToken}, given the current {@link AccessToken}. It is used to implement different token
 * exchange strategies.
 */
@FunctionalInterface
public interface TokenProvider {

  /**
   * Provides a {@link TypedToken} that will serve as either the subject or actor token in the token
   * exchange request.
   *
   * <p>The current access token will be null if the token exchange is happening as an initial token
   * fetch. If the token exchange is happening as an impersonation flow, the current access token
   * will be the original token that was fetched initially.
   *
   * @return a {@link TypedToken} to use for the token exchange, or null if no token should be used.
   *     Note that returning null is incorrect for a subject token provider.
   */
  @Nullable
  TypedToken provideToken(@Nullable AccessToken currentAccessToken);
}
