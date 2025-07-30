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

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.dremio.iceberg.authmgr.oauth2.config.ClientAssertionConfig;
import com.dremio.iceberg.authmgr.oauth2.config.Secret;
import com.dremio.iceberg.authmgr.oauth2.rest.ClientCredentialsTokenRequest;
import com.dremio.iceberg.authmgr.oauth2.test.TestConstants;
import com.dremio.iceberg.authmgr.oauth2.token.TypedToken;
import java.net.URI;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class TestClientSecretJwtAuthenticator {

  @ParameterizedTest
  @MethodSource
  void authenticate(
      ClientAssertionConfig clientAssertionConfig, Consumer<TypedToken> requirements) {
    ClientSecretJwtAuthenticator authenticator =
        ImmutableClientSecretJwtAuthenticator.builder()
            .clientId(TestConstants.CLIENT_ID1)
            .clientSecret(Secret.of(TestConstants.CLIENT_SECRET1))
            .clientAssertionConfig(clientAssertionConfig)
            .tokenEndpoint(URI.create("https://example.com/token"))
            .clock(TestConstants.CLOCK)
            .build();
    assertThat(authenticator.getClientId()).isEqualTo(TestConstants.CLIENT_ID1);
    assertThat(authenticator.getClientSecret()).isEqualTo(Secret.of(TestConstants.CLIENT_SECRET1));
    assertThat(authenticator.getTokenEndpoint()).isEqualTo(URI.create("https://example.com/token"));
    assertThat(authenticator.getClientAssertionConfig()).isEqualTo(clientAssertionConfig);
    ClientCredentialsTokenRequest.Builder builder = ClientCredentialsTokenRequest.builder();
    authenticator.authenticate(builder, new HashMap<>(), null);
    ClientCredentialsTokenRequest request = builder.build();
    assertThat(request.getClientId()).isNull();
    assertThat(request.getClientSecret()).isNull();
    assertThat(request.getClientAssertion()).satisfies(requirements);
  }

  static Stream<Arguments> authenticate() {
    return Stream.of(
        Arguments.of(
            ClientAssertionConfig.builder().algorithm(JwtSigningAlgorithm.HMAC_SHA256).build(),
            (Consumer<TypedToken>)
                assertion -> {
                  assertThat(assertion).isNotNull();
                  assertThat(assertion.getTokenType()).isEqualTo(TypedToken.URN_JWT_BEARER);
                  DecodedJWT jwt = JWT.decode(assertion.getPayload());
                  assertThat(jwt.getIssuer()).isEqualTo(TestConstants.CLIENT_ID1);
                  assertThat(jwt.getSubject()).isEqualTo(TestConstants.CLIENT_ID1);
                  assertThat(jwt.getAudience()).containsOnly("https://example.com/token");
                  assertThat(jwt.getClaim("iat").asLong())
                      .isEqualTo(TestConstants.CLOCK.instant().getEpochSecond());
                  assertThat(jwt.getClaim("exp").asLong())
                      .isEqualTo(
                          TestConstants.CLOCK
                              .instant()
                              .plusSeconds(
                                  ClientAssertionConfig.DEFAULT_TOKEN_LIFESPAN.getSeconds())
                              .getEpochSecond());
                }),
        Arguments.of(
            ClientAssertionConfig.builder()
                .issuer(TestConstants.CLIENT_ID2)
                .subject(TestConstants.CLIENT_ID2)
                .audience("https://example.com/token2")
                .tokenLifespan(Duration.ofHours(1))
                .extraClaims(Map.of("claim1", "value1", "claim2", "value2"))
                .algorithm(JwtSigningAlgorithm.HMAC_SHA512)
                .build(),
            (Consumer<TypedToken>)
                assertion -> {
                  assertThat(assertion).isNotNull();
                  assertThat(assertion.getTokenType()).isEqualTo(TypedToken.URN_JWT_BEARER);
                  DecodedJWT jwt = JWT.decode(assertion.getPayload());
                  assertThat(jwt.getIssuer()).isEqualTo(TestConstants.CLIENT_ID2);
                  assertThat(jwt.getSubject()).isEqualTo(TestConstants.CLIENT_ID2);
                  assertThat(jwt.getAudience()).containsOnly("https://example.com/token2");
                  assertThat(jwt.getClaim("iat").asLong())
                      .isEqualTo(TestConstants.CLOCK.instant().getEpochSecond());
                  assertThat(jwt.getClaim("exp").asLong())
                      .isEqualTo(
                          TestConstants.CLOCK.instant().plus(Duration.ofHours(1)).getEpochSecond());
                  assertThat(jwt.getClaim("claim1").asString()).isEqualTo("value1");
                  assertThat(jwt.getClaim("claim2").asString()).isEqualTo("value2");
                }));
  }
}
