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

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ErrorResponse;
import jakarta.annotation.Nullable;
import java.time.Duration;
import java.util.Optional;
import java.util.stream.Collectors;
import net.minidev.json.JSONObject;

/** An exception thrown when the server replies with an OAuth2 error. */
public final class OAuth2Exception extends RuntimeException {

  /** HTTP 429 Too Many Requests (RFC 6585 §4), which Nimbus has no constant for. */
  private static final int SC_TOO_MANY_REQUESTS = 429;

  private final ErrorObject errorObject;
  @Nullable private final Duration retryAfter;

  OAuth2Exception(ErrorResponse errorResponse) {
    this(errorResponse, null);
  }

  OAuth2Exception(ErrorResponse errorResponse, @Nullable Duration retryAfter) {
    this(errorResponse.getErrorObject(), retryAfter);
  }

  OAuth2Exception(ErrorObject errorObject) {
    this(errorObject, null);
  }

  OAuth2Exception(ErrorObject errorObject, @Nullable Duration retryAfter) {
    this(
        "OAuth2 request failed: " + formatErrorObject(errorObject.toJSONObject()),
        errorObject,
        retryAfter);
  }

  OAuth2Exception(String message, ErrorObject errorObject) {
    this(message, errorObject, null);
  }

  OAuth2Exception(String message, ErrorObject errorObject, @Nullable Duration retryAfter) {
    super(message);
    this.errorObject = errorObject;
    this.retryAfter = retryAfter;
  }

  public ErrorObject getErrorObject() {
    return errorObject;
  }

  /**
   * The HTTP status code of the error response, or 0 if unknown.
   *
   * @see ErrorObject#getHTTPStatusCode()
   */
  public int getHttpStatusCode() {
    return errorObject.getHTTPStatusCode();
  }

  /** Whether the server rejected the request because the client is being rate-limited (429). */
  public boolean isRateLimited() {
    return getHttpStatusCode() == SC_TOO_MANY_REQUESTS;
  }

  /**
   * The delay the server asked the client to wait before trying again, as conveyed by the {@code
   * Retry-After} header of the error response, if present and well-formed. Typically sent along
   * with 429 and 503 responses.
   */
  public Optional<Duration> getRetryAfter() {
    return Optional.ofNullable(retryAfter);
  }

  private static String formatErrorObject(JSONObject jsonObject) {
    return jsonObject.entrySet().stream()
        .filter(entry -> entry.getValue() != null)
        .map(entry -> entry.getKey() + ": " + entry.getValue())
        .collect(Collectors.joining(", "));
  }
}
