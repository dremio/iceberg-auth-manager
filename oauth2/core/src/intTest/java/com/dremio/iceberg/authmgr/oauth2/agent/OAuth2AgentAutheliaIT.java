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
package com.dremio.iceberg.authmgr.oauth2.agent;

import static com.dremio.iceberg.authmgr.oauth2.test.junit.AutheliaExtension.CLIENT_ID1;
import static com.dremio.iceberg.authmgr.oauth2.test.junit.AutheliaExtension.CLIENT_ID2;
import static com.dremio.iceberg.authmgr.oauth2.test.junit.AutheliaExtension.CLIENT_SECRET1;
import static com.dremio.iceberg.authmgr.oauth2.test.junit.AutheliaExtension.CLIENT_SECRET2;
import static com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
import static com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.CLIENT_SECRET_POST;
import static org.assertj.core.api.InstanceOfAssertFactories.type;

import com.dremio.iceberg.authmgr.oauth2.flow.OAuth2Exception;
import com.dremio.iceberg.authmgr.oauth2.flow.TokensResult;
import com.dremio.iceberg.authmgr.oauth2.test.ImmutableTestEnvironment.Builder;
import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironment;
import com.dremio.iceberg.authmgr.oauth2.test.junit.AutheliaExtension;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.ParseException;
import java.util.Objects;
import org.assertj.core.api.SoftAssertions;
import org.assertj.core.api.junit.jupiter.InjectSoftAssertions;
import org.assertj.core.api.junit.jupiter.SoftAssertionsExtension;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;

@ExtendWith(AutheliaExtension.class)
@ExtendWith(SoftAssertionsExtension.class)
public class OAuth2AgentAutheliaIT {

  @InjectSoftAssertions private SoftAssertions soft;

  private static Path keyStorePath;

  @BeforeAll
  static void beforeAll(@TempDir Path tempDir) throws Exception {
    keyStorePath = tempDir.resolve("keystore.p12");
    try (InputStream is =
        OAuth2AgentAutheliaIT.class.getResourceAsStream("/openssl/keystore.p12")) {
      Files.copy(Objects.requireNonNull(is), keyStorePath);
    }
  }

  @Test
  void clientSecretBasic(Builder envBuilder) throws Exception {
    try (TestEnvironment env =
            envBuilder
                .grantType(GrantType.CLIENT_CREDENTIALS)
                .clientAuthenticationMethod(CLIENT_SECRET_BASIC)
                .clientId(new ClientID(CLIENT_ID1))
                .clientSecret(new Secret(CLIENT_SECRET1))
                .sslTrustAll(false)
                .sslTrustStorePath(keyStorePath)
                .sslTrustStorePassword("s3cr3t")
                .build();
        OAuth2Agent agent = env.newAgent()) {
      assertAgent(agent, CLIENT_ID1, env.getAuthorizationServerUrl());
    }
  }

  @Test
  void clientSecretPost(Builder envBuilder) throws Exception {
    try (TestEnvironment env =
            envBuilder
                .grantType(GrantType.CLIENT_CREDENTIALS)
                .clientAuthenticationMethod(CLIENT_SECRET_POST)
                .clientId(new ClientID(CLIENT_ID2))
                .clientSecret(new Secret(CLIENT_SECRET2))
                .sslTrustAll(false)
                .sslTrustStorePath(keyStorePath)
                .sslTrustStorePassword("s3cr3t")
                .build();
        OAuth2Agent agent = env.newAgent()) {
      assertAgent(agent, CLIENT_ID2, env.getAuthorizationServerUrl());
    }
  }

  @Test
  void unauthorizedBadClientSecret(Builder envBuilder) {
    try (TestEnvironment env =
            envBuilder
                .clientSecret(new Secret("BAD SECRET"))
                .sslTrustAll(false)
                .sslTrustStorePath(keyStorePath)
                .sslTrustStorePassword("s3cr3t")
                .build();
        OAuth2Agent agent = env.newAgent()) {
      soft.assertThatThrownBy(agent::authenticate)
          .asInstanceOf(type(OAuth2Exception.class))
          .extracting(OAuth2Exception::getErrorObject)
          .extracting(ErrorObject::getHTTPStatusCode, ErrorObject::getCode)
          .containsExactly(401, "invalid_client");
    }
  }

  private void assertAgent(OAuth2Agent agent, String clientId, URI issuer) throws Exception {
    // initial grant
    TokensResult initial = agent.authenticateInternal();
    introspectToken(initial.getTokens().getAccessToken(), clientId, issuer);
    soft.assertThat(initial.getTokens().getRefreshToken()).isNull();
    // fetch new tokens
    TokensResult renewed = agent.fetchNewTokens().toCompletableFuture().get();
    introspectToken(renewed.getTokens().getAccessToken(), clientId, issuer);
    soft.assertThat(renewed.getTokens().getRefreshToken()).isNull();
  }

  private void introspectToken(AccessToken accessToken, String clientId, URI issuer)
      throws ParseException {
    soft.assertThat(accessToken).isNotNull();
    JWT jwt = JWTParser.parse(accessToken.getValue());
    soft.assertThat(jwt).isNotNull();
    String actualIssuer = jwt.getJWTClaimsSet().getIssuer();
    String actualClientId = jwt.getJWTClaimsSet().getStringClaim("client_id");
    soft.assertThat(actualIssuer).isEqualTo(issuer.toString());
    soft.assertThat(actualClientId).isEqualTo(clientId);
  }
}
