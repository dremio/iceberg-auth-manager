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

import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.NOW;
import static org.assertj.core.api.Assertions.assertThat;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import java.time.Instant;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class TokenTest {

  /** Valid empty JWT token. */
  static final String JWT_WITHOUT_EXP_CLAIM =
      JWT.create().withSubject("Alice").sign(Algorithm.HMAC256("s3cr3t"));

  static final String JWT_WITH_EXP_CLAIM =
      JWT.create().withSubject("Alice").withExpiresAt(NOW).sign(Algorithm.HMAC256("s3cr3t"));

  @ParameterizedTest
  @MethodSource
  void testIsExpired(Token token, Instant now, boolean expected) {
    assertThat(token.isExpired(now)).isEqualTo(expected);
  }

  static Stream<Arguments> testIsExpired() {
    return Stream.of(
        // expiration time from the token response
        Arguments.of(RefreshToken.of("payload", NOW), NOW, true),
        Arguments.of(RefreshToken.of("payload", NOW.minusSeconds(1)), NOW, true),
        Arguments.of(RefreshToken.of("payload", NOW.plusSeconds(1)), NOW, false),
        // no expiration time in the response
        Arguments.of(RefreshToken.of("payload", null), NOW, false),
        // no expiration time in the response, token is a JWT, exp claim present
        Arguments.of(RefreshToken.of(JWT_WITH_EXP_CLAIM, null), NOW, true),
        Arguments.of(RefreshToken.of(JWT_WITH_EXP_CLAIM, null), NOW.minusSeconds(1), false),
        Arguments.of(RefreshToken.of(JWT_WITH_EXP_CLAIM, null), NOW.plusSeconds(1), true),
        // no expiration time in the response, token is a JWT, but no exp claim
        Arguments.of(RefreshToken.of(JWT_WITHOUT_EXP_CLAIM, null), NOW, false));
  }
}
