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
package com.dremio.iceberg.authmgr.oauth2.flow;

import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.ACCESS_TOKEN_EXPIRATION_TIME;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.ACCESS_TOKEN_LIFESPAN;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.NOW;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.REFRESH_TOKEN_EXPIRATION_TIME;
import static com.dremio.iceberg.authmgr.oauth2.test.TokenAssertions.assertTokens;
import static org.assertj.core.api.Assertions.assertThat;

import com.dremio.iceberg.authmgr.oauth2.grant.GrantType;
import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironment;
import com.dremio.iceberg.authmgr.oauth2.token.AccessToken;
import com.dremio.iceberg.authmgr.oauth2.token.RefreshToken;
import com.dremio.iceberg.authmgr.oauth2.token.Tokens;
import java.time.Duration;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

class ImpersonatingTokenExchangeFlowTest {

  private final Tokens currentTokens =
      Tokens.of(
          AccessToken.of("access_initial", "Bearer", ACCESS_TOKEN_EXPIRATION_TIME),
          RefreshToken.of("refresh_initial", REFRESH_TOKEN_EXPIRATION_TIME));

  @ParameterizedTest
  @CsvSource({"true, true", "true, false", "false, true", "false, false"})
  void fetchNewTokens(boolean privateClient, boolean returnRefreshTokens) {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.AUTHORIZATION_CODE)
                .impersonationEnabled(true)
                .privateClient(privateClient)
                .returnRefreshTokens(returnRefreshTokens)
                .build();
        Flow flow = env.newImpersonationFlow()) {
      Tokens tokens = flow.fetchNewTokens(currentTokens);
      assertTokens(tokens, "access_impersonated", "refresh_initial");
    }
  }

  @ParameterizedTest
  @MethodSource
  void expirationTimes(Duration primaryLifespan, Duration secondaryLifespan, Duration expected) {
    try (TestEnvironment env =
            TestEnvironment.builder()
                .grantType(GrantType.AUTHORIZATION_CODE)
                .impersonationEnabled(true)
                .accessTokenLifespan(primaryLifespan)
                .impersonationAccessTokenLifespan(secondaryLifespan)
                .build();
        Flow flow = env.newImpersonationFlow()) {
      Tokens currentTokens =
          Tokens.of(
              AccessToken.of("access_initial", "Bearer", NOW.plus(primaryLifespan)),
              RefreshToken.of("refresh_initial", REFRESH_TOKEN_EXPIRATION_TIME));
      Tokens tokens = flow.fetchNewTokens(currentTokens);
      assertThat(tokens.getAccessToken().getExpirationTime()).isEqualTo(NOW.plus(expected));
    }
  }

  static Stream<Arguments> expirationTimes() {
    return Stream.of(
        Arguments.of(ACCESS_TOKEN_LIFESPAN, ACCESS_TOKEN_LIFESPAN, ACCESS_TOKEN_LIFESPAN),
        Arguments.of(
            ACCESS_TOKEN_LIFESPAN.minusSeconds(1),
            ACCESS_TOKEN_LIFESPAN,
            ACCESS_TOKEN_LIFESPAN.minusSeconds(1)),
        Arguments.of(
            ACCESS_TOKEN_LIFESPAN,
            ACCESS_TOKEN_LIFESPAN.minusSeconds(1),
            ACCESS_TOKEN_LIFESPAN.minusSeconds(1)));
  }
}
