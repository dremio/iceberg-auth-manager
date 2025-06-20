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
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.Mockito.mock;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties;
import com.dremio.iceberg.authmgr.oauth2.agent.OAuth2AgentSpec;
import com.dremio.iceberg.authmgr.oauth2.config.BasicConfig;
import com.dremio.iceberg.authmgr.oauth2.config.TokenExchangeConfig;
import com.dremio.iceberg.authmgr.oauth2.grant.GrantType;
import com.dremio.iceberg.authmgr.oauth2.token.TypedToken;
import java.net.URI;
import java.util.Map;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ScheduledExecutorService;
import java.util.function.Supplier;
import org.apache.iceberg.rest.RESTClient;
import org.assertj.core.api.junit.jupiter.SoftAssertionsExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(SoftAssertionsExtension.class)
class SubjectTokenSupplierTest {

  private static final Map<String, String> CONFIG =
      Map.of(OAuth2Properties.Basic.GRANT_TYPE, GrantType.CLIENT_CREDENTIALS.name());

  @Test
  void testSupplyTokenAsyncStatic() {
    OAuth2AgentSpec spec = createSpec("subject-token", TypedToken.URN_ID_TOKEN, Map.of());
    try (SubjectTokenSupplier supplier = createSupplier(spec)) {
      CompletionStage<TypedToken> stage = supplier.supplyTokenAsync();
      assertThat(stage)
          .isCompletedWithValue(TypedToken.of("subject-token", TypedToken.URN_ID_TOKEN));
    }
  }

  @Test
  void testSupplyTokenAsyncDynamic() {
    OAuth2AgentSpec spec = createSpec(null, TypedToken.URN_ACCESS_TOKEN, CONFIG);
    try (SubjectTokenSupplier supplier = createSupplier(spec)) {
      CompletionStage<TypedToken> stage = supplier.supplyTokenAsync();
      assertThat(stage).isNotCompleted();
    }
  }

  @Test
  @SuppressWarnings("resource")
  void testValidate() {
    OAuth2AgentSpec spec = createSpec(null, TypedToken.URN_ACCESS_TOKEN, Map.of());
    assertThatIllegalArgumentException()
        .isThrownBy(() -> createSupplier(spec))
        .withMessage("Subject token is dynamic but no configuration is provided");
  }

  private OAuth2AgentSpec createSpec(
      String subjectToken, URI subjectTokenType, Map<String, String> subjectTokenConfig) {
    TokenExchangeConfig.Builder tokenExchangeBuilder =
        TokenExchangeConfig.builder()
            .subjectTokenConfig(subjectTokenConfig)
            .subjectTokenType(subjectTokenType);
    if (subjectToken != null) {
      tokenExchangeBuilder.subjectToken(subjectToken);
    }
    return OAuth2AgentSpec.builder()
        .basicConfig(
            BasicConfig.builder()
                .grantType(GrantType.TOKEN_EXCHANGE)
                .tokenEndpoint(URI.create("https://example.com/token"))
                .clientId("test-client")
                .clientSecret("test-secret")
                .build())
        .tokenExchangeConfig(tokenExchangeBuilder.build())
        .build();
  }

  private static SubjectTokenSupplier createSupplier(OAuth2AgentSpec spec) {
    ScheduledExecutorService executor = mock(ScheduledExecutorService.class);
    Supplier<RESTClient> restClientSupplier = () -> mock(RESTClient.class);
    return SubjectTokenSupplier.of(spec, executor, restClientSupplier);
  }
}
