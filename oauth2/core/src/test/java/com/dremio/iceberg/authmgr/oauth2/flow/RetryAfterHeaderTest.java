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

import static org.assertj.core.api.Assertions.assertThat;

import com.dremio.iceberg.authmgr.oauth2.test.TestConstants;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import java.time.Duration;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class RetryAfterHeaderTest {

  @ParameterizedTest
  @MethodSource
  void testParse(String headerValue, Duration expected) {
    HTTPResponse response = new HTTPResponse(429);
    if (headerValue != null) {
      response.setHeader(RetryAfterHeader.NAME, headerValue);
    }
    assertThat(RetryAfterHeader.parse(response, TestConstants.NOW)).isEqualTo(expected);
  }

  static Stream<Arguments> testParse() {
    // TestConstants.NOW is 2025-01-01T00:00:00Z, a Wednesday
    return Stream.of(
        Arguments.of(null, null),
        Arguments.of("", null),
        Arguments.of("   ", null),
        Arguments.of("0", Duration.ZERO),
        Arguments.of("120", Duration.ofSeconds(120)),
        Arguments.of(" 120 ", Duration.ofSeconds(120)),
        Arguments.of("-1", null),
        Arguments.of("1.5", null),
        Arguments.of("99999999999999999999", null),
        Arguments.of("soon", null),
        Arguments.of("Wed, 01 Jan 2025 00:02:00 GMT", Duration.ofMinutes(2)),
        Arguments.of("Wed, 01 Jan 2025 00:00:00 GMT", Duration.ZERO),
        // date in the past
        Arguments.of("Tue, 31 Dec 2024 23:59:00 GMT", null),
        // malformed date
        Arguments.of("2025-01-01T00:02:00Z", null));
  }
}
