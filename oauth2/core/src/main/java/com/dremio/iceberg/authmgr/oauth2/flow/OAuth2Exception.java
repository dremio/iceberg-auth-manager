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

/** An exception thrown when the server replies with an OAuth2 error. */
public final class OAuth2Exception extends RuntimeException {

  private final ErrorObject errorObject;

  OAuth2Exception(ErrorResponse errorResponse) {
    this(errorResponse.getErrorObject());
  }

  OAuth2Exception(ErrorObject errorObject) {
    this("OAuth2 request failed: " + errorObject.getDescription(), errorObject);
  }

  OAuth2Exception(String message, ErrorObject errorObject) {
    super(message);
    this.errorObject = errorObject;
  }

  public ErrorObject getErrorObject() {
    return errorObject;
  }
}
