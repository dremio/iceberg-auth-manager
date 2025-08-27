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
package com.dremio.iceberg.authmgr.oauth2.test;

import static org.assertj.core.api.Assertions.assertThat;

import com.dremio.iceberg.authmgr.oauth2.flow.TokensResult;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;

public class TokenAssertions {

  public static void assertTokensResult(
      TokensResult result, String accessToken, String refreshToken) {
    assertTokens(result.getTokens(), accessToken, refreshToken);
    assertThat(result.getExpirationTime()).isEqualTo(TestConstants.ACCESS_TOKEN_EXPIRATION_TIME);
  }

  public static void assertTokens(Tokens result, String accessToken, String refreshToken) {
    assertAccessToken(
        result.getAccessToken(), accessToken, TestConstants.ACCESS_TOKEN_EXPIRES_IN_SECONDS);
    assertRefreshToken(result.getRefreshToken(), refreshToken);
  }

  public static void assertAccessToken(AccessToken actual, String expected, int expiresInSeconds) {
    assertThat(actual.getValue()).isEqualTo(expected);
    assertThat(actual.getType()).isEqualTo(AccessTokenType.BEARER);
    assertThat(actual.getLifetime()).isEqualTo(expiresInSeconds);
  }

  public static void assertRefreshToken(RefreshToken actual, String expected) {
    if (expected == null) {
      assertThat(actual).isNull();
    } else {
      assertThat(actual).isNotNull();
      assertThat(actual.getValue()).isEqualTo(expected);
    }
  }
}
