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
package com.dremio.iceberg.authmgr.oauth2.tokenexchange;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Config;
import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties;
import com.dremio.iceberg.authmgr.oauth2.config.BasicConfig;
import com.dremio.iceberg.authmgr.oauth2.config.TokenExchangeConfig;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.TokenTypeURI;
import com.nimbusds.oauth2.sdk.token.TypelessAccessToken;
import java.net.URI;
import java.util.Map;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ScheduledExecutorService;
import org.assertj.core.api.junit.jupiter.SoftAssertionsExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(SoftAssertionsExtension.class)
class ActorTokenSupplierTest {

  private static final Map<String, String> CONFIG =
      Map.of(OAuth2Properties.Basic.GRANT_TYPE, GrantType.CLIENT_CREDENTIALS.getValue());

  @Test
  void testSupplyActorTokenAsyncStatic() {
    OAuth2Config spec = createSpec("actor-token", TokenTypeURI.ID_TOKEN, Map.of());
    try (ActorTokenSupplier supplier = createSupplier(spec)) {
      CompletionStage<AccessToken> stage = supplier.supplyTokenAsync();
      assertThat(stage)
          .isCompletedWithValue(
              new BearerAccessToken("actor-token", 0, null, TokenTypeURI.ID_TOKEN));
    }
  }

  @Test
  void testSupplyActorTokenAsyncDynamic() {
    OAuth2Config spec = createSpec(null, TokenTypeURI.ACCESS_TOKEN, CONFIG);
    try (ActorTokenSupplier supplier = createSupplier(spec)) {
      CompletionStage<AccessToken> stage = supplier.supplyTokenAsync();
      assertThat(stage).isNotCompleted();
    }
  }

  @Test
  void testSupplyActorTokenAsyncNull() {
    OAuth2Config spec = createSpec(null, TokenTypeURI.ACCESS_TOKEN, Map.of());
    try (ActorTokenSupplier supplier = createSupplier(spec)) {
      CompletionStage<AccessToken> stage = supplier.supplyTokenAsync();
      assertThat(stage).isCompletedWithValue(null);
    }
  }

  private OAuth2Config createSpec(
      String actorToken, TokenTypeURI actorTokenType, Map<String, String> actorTokenConfig) {
    TokenExchangeConfig.Builder tokenExchangeBuilder =
        TokenExchangeConfig.builder()
            .subjectToken(new TypelessAccessToken("subject-token"))
            .actorTokenConfig(actorTokenConfig)
            .actorTokenType(actorTokenType);
    if (actorToken != null) {
      tokenExchangeBuilder.actorToken(new TypelessAccessToken(actorToken));
    }
    return OAuth2Config.builder()
        .basicConfig(
            BasicConfig.builder()
                .grantType(GrantType.TOKEN_EXCHANGE)
                .tokenEndpoint(URI.create("https://example.com/token"))
                .clientId(new ClientID("test-client"))
                .clientSecret(new Secret("test-secret"))
                .build())
        .tokenExchangeConfig(tokenExchangeBuilder.build())
        .build();
  }

  private static ActorTokenSupplier createSupplier(OAuth2Config spec) {
    ScheduledExecutorService executor = mock(ScheduledExecutorService.class);
    return ActorTokenSupplier.create(spec, executor);
  }
}
