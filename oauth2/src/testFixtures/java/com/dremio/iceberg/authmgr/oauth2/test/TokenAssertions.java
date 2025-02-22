/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.dremio.iceberg.authmgr.oauth2.test;

import static org.assertj.core.api.Assertions.assertThat;

import com.dremio.iceberg.authmgr.oauth2.token.AccessToken;
import com.dremio.iceberg.authmgr.oauth2.token.RefreshToken;
import com.dremio.iceberg.authmgr.oauth2.token.Tokens;
import java.time.Instant;

public class TokenAssertions {

  public static void assertTokens(Tokens tokens, String accessToken, String refreshToken) {
    assertAccessToken(
        tokens.getAccessToken(), accessToken, TestConstants.ACCESS_TOKEN_EXPIRATION_TIME);
    assertRefreshToken(tokens.getRefreshToken(), refreshToken);
  }

  public static void assertAccessToken(
      AccessToken actual, String expected, Instant expirationTime) {
    assertThat(actual.getPayload()).isEqualTo(expected);
    assertThat(actual.getExpirationTime()).isEqualTo(expirationTime);
    assertThat(actual.getTokenType()).isEqualToIgnoringCase("bearer");
  }

  public static void assertRefreshToken(RefreshToken actual, String expected) {
    if (expected == null) {
      assertThat(actual).isNull();
    } else {
      assertThat(actual.getPayload()).isEqualTo(expected);
      assertThat(actual.getExpirationTime()).isEqualTo(TestConstants.REFRESH_TOKEN_EXPIRATION_TIME);
    }
  }
}
