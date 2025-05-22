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
package com.dremio.iceberg.authmgr.oauth2.token;

import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import jakarta.annotation.Nullable;
import java.time.Instant;

@AuthManagerImmutable
public interface RefreshToken extends Token {

  @Override
  RefreshToken withExpirationTime(@Nullable Instant expirationTime);

  static RefreshToken of(String payload, @Nullable Instant expirationTime) {
    return ImmutableRefreshToken.builder().payload(payload).expirationTime(expirationTime).build();
  }
}
