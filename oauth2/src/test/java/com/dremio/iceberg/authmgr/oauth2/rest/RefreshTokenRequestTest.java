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
package com.dremio.iceberg.authmgr.oauth2.rest;

import static org.assertj.core.api.Assertions.assertThat;

import com.dremio.iceberg.authmgr.oauth2.grant.GrantType;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class RefreshTokenRequestTest {

  @ParameterizedTest
  @MethodSource
  void asFormParameters(RefreshTokenRequest input, Map<String, String> expected) {
    assertThat(input.asFormParameters()).containsExactlyEntriesOf(expected);
  }

  public static Stream<Arguments> asFormParameters() {
    return Stream.of(
        Arguments.of(
            RefreshTokenRequest.builder().refreshToken("refreshToken1").build(),
            Map.of(
                "grant_type",
                GrantType.REFRESH_TOKEN.getCanonicalName(),
                "refresh_token",
                "refreshToken1")),
        Arguments.of(
            RefreshTokenRequest.builder()
                .clientId("client1")
                .scope("scope1 scope2")
                .extraParameters(Map.of("extra1", "value1", "extra2", "value2"))
                .refreshToken("refreshToken1")
                .build(),
            Map.of(
                "grant_type", GrantType.REFRESH_TOKEN.getCanonicalName(),
                "client_id", "client1",
                "scope", "scope1 scope2",
                "extra1", "value1",
                "extra2", "value2",
                "refresh_token", "refreshToken1")));
  }
}
