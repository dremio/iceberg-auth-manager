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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import java.time.Instant;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class JwtTokenTest {

  private static final Instant JWT_EXP_CLAIM = Instant.ofEpochSecond(123456);
  private static final Instant JWT_NBF_CLAIM = Instant.ofEpochSecond(234567);
  private static final Instant JWT_IAT_CLAIM = Instant.ofEpochSecond(345678);

  private static final String JWT_EMPTY = JWT.create().sign(Algorithm.HMAC256("s3cr3t"));

  private static final String JWT_NON_EMPTY =
      JWT.create()
          .withIssuer("Alice")
          .withSubject("Bob")
          .withAudience("Charlie", "Delta")
          .withJWTId("id1")
          .withExpiresAt(JWT_EXP_CLAIM)
          .withNotBefore(JWT_NBF_CLAIM)
          .withIssuedAt(JWT_IAT_CLAIM)
          .sign(Algorithm.HMAC256("s3cr3t"));

  @ParameterizedTest
  @MethodSource
  void testJwtIssuer(String token, boolean valid, String expected) {
    if (valid) {
      JwtToken jwtToken = JwtToken.parse(token);
      assertThat(jwtToken).isNotNull();
      assertThat(jwtToken.getIssuer()).isEqualTo(JWT.decode(token).getIssuer()).isEqualTo(expected);
    } else {
      assertThatThrownBy(() -> JwtToken.parse(token))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessage("Invalid JWT token: " + token);
    }
  }

  static Stream<Arguments> testJwtIssuer() {
    return Stream.concat(commonCases(), Stream.of(Arguments.of(JWT_NON_EMPTY, true, "Alice")));
  }

  @ParameterizedTest
  @MethodSource
  void testJwtSubject(String token, boolean valid, String expected) {
    if (valid) {
      JwtToken jwtToken = JwtToken.parse(token);
      assertThat(jwtToken).isNotNull();
      assertThat(jwtToken.getSubject())
          .isEqualTo(JWT.decode(token).getSubject())
          .isEqualTo(expected);
    } else {
      assertThatThrownBy(() -> JwtToken.parse(token))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessage("Invalid JWT token: " + token);
    }
  }

  static Stream<Arguments> testJwtSubject() {
    return Stream.concat(commonCases(), Stream.of(Arguments.of(JWT_NON_EMPTY, true, "Bob")));
  }

  @ParameterizedTest
  @MethodSource
  void testJwtAudience(String token, boolean valid, List<String> expected) {
    if (valid) {
      JwtToken jwtToken = JwtToken.parse(token);
      assertThat(jwtToken).isNotNull();
      assertThat(jwtToken.getAudience())
          .isEqualTo(JWT.decode(token).getAudience())
          .isEqualTo(expected);
    } else {
      assertThatThrownBy(() -> JwtToken.parse(token))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessage("Invalid JWT token: " + token);
    }
  }

  static Stream<Arguments> testJwtAudience() {
    return Stream.concat(
        commonCases(), Stream.of(Arguments.of(JWT_NON_EMPTY, true, List.of("Charlie", "Delta"))));
  }

  @ParameterizedTest
  @MethodSource
  void testJwtExpirationTime(String token, boolean valid, Instant expected) {
    if (valid) {
      JwtToken jwtToken = JwtToken.parse(token);
      assertThat(jwtToken).isNotNull();
      assertThat(jwtToken.getExpirationTime())
          .isEqualTo(JWT.decode(token).getExpiresAtAsInstant())
          .isEqualTo(expected);
    } else {
      assertThatThrownBy(() -> JwtToken.parse(token))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessage("Invalid JWT token: " + token);
    }
  }

  static Stream<Arguments> testJwtExpirationTime() {
    return Stream.concat(
        commonCases(), Stream.of(Arguments.of(JWT_NON_EMPTY, true, JWT_EXP_CLAIM)));
  }

  @ParameterizedTest
  @MethodSource
  void testJwtNotBefore(String token, boolean valid, Instant expected) {
    if (valid) {
      JwtToken jwtToken = JwtToken.parse(token);
      assertThat(jwtToken).isNotNull();
      assertThat(jwtToken.getNotBefore())
          .isEqualTo(JWT.decode(token).getNotBeforeAsInstant())
          .isEqualTo(expected);
    } else {
      assertThatThrownBy(() -> JwtToken.parse(token))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessage("Invalid JWT token: " + token);
    }
  }

  static Stream<Arguments> testJwtNotBefore() {
    return Stream.concat(
        commonCases(), Stream.of(Arguments.of(JWT_NON_EMPTY, true, JWT_NBF_CLAIM)));
  }

  @ParameterizedTest
  @MethodSource
  void testJwtIssuedAt(String token, boolean valid, Instant expected) {
    if (valid) {
      JwtToken jwtToken = JwtToken.parse(token);
      assertThat(jwtToken).isNotNull();
      assertThat(jwtToken.getIssuedAt())
          .isEqualTo(JWT.decode(token).getIssuedAtAsInstant())
          .isEqualTo(expected);
    } else {
      assertThatThrownBy(() -> JwtToken.parse(token))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessage("Invalid JWT token: " + token);
    }
  }

  static Stream<Arguments> testJwtIssuedAt() {
    return Stream.concat(
        commonCases(), Stream.of(Arguments.of(JWT_NON_EMPTY, true, JWT_IAT_CLAIM)));
  }

  @ParameterizedTest
  @MethodSource
  void testJwtId(String token, boolean valid, String expected) {
    if (valid) {
      JwtToken jwtToken = JwtToken.parse(token);
      assertThat(jwtToken).isNotNull();
      assertThat(jwtToken.getId()).isEqualTo(JWT.decode(token).getId()).isEqualTo(expected);
    } else {
      assertThatThrownBy(() -> JwtToken.parse(token))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessage("Invalid JWT token: " + token);
    }
  }

  static Stream<Arguments> testJwtId() {
    return Stream.concat(commonCases(), Stream.of(Arguments.of(JWT_NON_EMPTY, true, "id1")));
  }

  private static Stream<Arguments> commonCases() {
    return Stream.of(
        Arguments.of(null, false, null),
        Arguments.of("", false, null),
        Arguments.of("invalidtoken", false, null),
        Arguments.of("invalid.token", false, null),
        Arguments.of("invalid.to.ken", false, null),
        Arguments.of("invalid..token", false, null),
        Arguments.of("in.valid.to.ken", false, null),
        Arguments.of(JWT_EMPTY, true, null));
  }
}
