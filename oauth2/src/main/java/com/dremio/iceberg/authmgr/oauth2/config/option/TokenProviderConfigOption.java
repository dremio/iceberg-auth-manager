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
package com.dremio.iceberg.authmgr.oauth2.config.option;

import static com.dremio.iceberg.authmgr.oauth2.OAuth2Properties.TokenExchange.CURRENT_ACCESS_TOKEN;
import static com.dremio.iceberg.authmgr.oauth2.token.TypedToken.URN_ACCESS_TOKEN;

import com.dremio.iceberg.authmgr.oauth2.token.TypedToken;
import com.dremio.iceberg.authmgr.oauth2.token.provider.TokenProvider;
import com.dremio.iceberg.authmgr.oauth2.token.provider.TokenProviders;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import java.net.URI;
import java.util.Map;
import java.util.Optional;

@AuthManagerImmutable
abstract class TokenProviderConfigOption extends ConfigOption<TokenProvider> {

  protected abstract String tokenOption();

  protected abstract String tokenTypeOption();

  @Override
  public void apply(Map<String, String> properties) {
    if (properties.containsKey(tokenOption())) {
      String token = properties.get(tokenOption());
      if (shouldSetOption(token)) {
        URI tokenType =
            Optional.ofNullable(properties.get(tokenTypeOption()))
                .map(URI::create)
                .orElse(URN_ACCESS_TOKEN);
        TokenProvider tokenProvider =
            token.equalsIgnoreCase(CURRENT_ACCESS_TOKEN)
                ? TokenProviders.currentAccessToken(tokenType)
                : TokenProviders.staticToken(TypedToken.of(token, tokenType));
        setter().accept(tokenProvider);
      }
    } else {
      fallback().ifPresent(setter());
    }
  }
}
