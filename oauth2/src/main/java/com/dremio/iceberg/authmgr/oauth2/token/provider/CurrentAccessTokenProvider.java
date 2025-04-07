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
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import java.net.URI;
import java.util.Objects;
import org.immutables.value.Value;

@AuthManagerImmutable
abstract class CurrentAccessTokenProvider implements TokenProvider {

  @Value.Parameter(order = 1)
  @Value.Default
  protected URI getTokenType() {
    return TypedToken.URN_ACCESS_TOKEN;
  }

  @Nonnull
  @Override
  public final TypedToken provideToken(@Nullable AccessToken accessToken) {
    Objects.requireNonNull(accessToken);
    return TypedToken.of(accessToken, getTokenType());
  }
}
