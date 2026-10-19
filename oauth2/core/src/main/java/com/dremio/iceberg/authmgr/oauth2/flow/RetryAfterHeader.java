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

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import jakarta.annotation.Nullable;
import java.time.Duration;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;

/**
 * Parser for the {@code Retry-After} response header (RFC 9110 §10.2.3), which servers send along
 * with 429 and 503 responses to tell the client how long to wait before trying again.
 */
final class RetryAfterHeader {

  static final String NAME = "Retry-After";

  private RetryAfterHeader() {}

  /**
   * Returns the delay requested by the {@code Retry-After} header of the given response, or null if
   * the header is absent, malformed, or already in the past. Both forms are supported: a
   * non-negative number of seconds, and an HTTP-date (RFC 1123), which is resolved against {@code
   * now}.
   */
  @Nullable
  static Duration parse(HTTPResponse response, Instant now) {
    String value = response.getHeaderValue(NAME);
    if (value == null) {
      return null;
    }
    Duration delay = parse(value.trim(), now);
    return delay != null && !delay.isNegative() ? delay : null;
  }

  @Nullable
  private static Duration parse(String value, Instant now) {
    if (value.isEmpty()) {
      return null;
    }
    if (Character.isDigit(value.charAt(0))) {
      try {
        return Duration.ofSeconds(Long.parseLong(value));
      } catch (NumberFormatException e) {
        return null;
      }
    }
    try {
      ZonedDateTime date = ZonedDateTime.parse(value, DateTimeFormatter.RFC_1123_DATE_TIME);
      return Duration.between(now, date.toInstant());
    } catch (DateTimeParseException e) {
      return null;
    }
  }
}
