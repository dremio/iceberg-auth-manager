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

import static org.assertj.core.api.Assertions.assertThat;

import com.dremio.iceberg.authmgr.oauth2.config.Secret;
import com.dremio.iceberg.authmgr.oauth2.rest.ClientCredentialsTokenRequest;
import com.dremio.iceberg.authmgr.oauth2.rest.TokenExchangeRequest;
import com.dremio.iceberg.authmgr.oauth2.test.TestConstants;
import com.dremio.iceberg.authmgr.oauth2.token.AccessToken;
import com.dremio.iceberg.authmgr.oauth2.token.Tokens;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class IcebergClientAuthenticatorTest {

  @Test
  void authenticateClientSecretPost() {
    IcebergClientAuthenticator authenticator =
        ImmutableIcebergClientAuthenticator.builder()
            .clientId(TestConstants.CLIENT_ID1)
            .clientSecret(Secret.of(TestConstants.CLIENT_SECRET1))
            .build();
    assertThat(authenticator.getClientId()).contains(TestConstants.CLIENT_ID1);
    assertThat(authenticator.getClientSecret()).contains(Secret.of(TestConstants.CLIENT_SECRET1));
    ClientCredentialsTokenRequest.Builder builder = ClientCredentialsTokenRequest.builder();
    authenticator.authenticate(builder, new HashMap<>(), null);
    assertThat(builder.build())
        .extracting(
            ClientCredentialsTokenRequest::getClientId,
            ClientCredentialsTokenRequest::getClientSecret)
        .containsExactly(TestConstants.CLIENT_ID1, TestConstants.CLIENT_SECRET1);
  }

  @Test
  void authenticateClientSecretBasic() {
    IcebergClientAuthenticator authenticator =
        ImmutableIcebergClientAuthenticator.builder()
            .clientId(TestConstants.CLIENT_ID1)
            .clientSecret(Secret.of(TestConstants.CLIENT_SECRET1))
            .build();
    assertThat(authenticator.getClientId()).contains(TestConstants.CLIENT_ID1);
    assertThat(authenticator.getClientSecret()).contains(Secret.of(TestConstants.CLIENT_SECRET1));
    TokenExchangeRequest.Builder builder = TokenExchangeRequest.builder();
    Map<String, String> headers = new HashMap<>();
    authenticator.authenticate(builder, headers, null);
    assertThat(headers)
        .containsEntry("Authorization", "Basic " + TestConstants.CLIENT_CREDENTIALS1_BASE_64);
  }

  @Test
  void authenticateBearerToken() {
    IcebergClientAuthenticator authenticator =
        ImmutableIcebergClientAuthenticator.builder().build();
    assertThat(authenticator.getClientId()).isEmpty();
    assertThat(authenticator.getClientSecret()).isEmpty();
    TokenExchangeRequest.Builder builder = TokenExchangeRequest.builder();
    Tokens tokens = Tokens.of(AccessToken.of("token"), null);
    Map<String, String> headers = new HashMap<>();
    authenticator.authenticate(builder, headers, tokens);
    assertThat(headers).containsEntry("Authorization", "Bearer token");
  }
}
