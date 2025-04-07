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

import org.apache.iceberg.rest.ErrorHandler;
import org.apache.iceberg.rest.responses.ErrorResponse;
import org.apache.iceberg.rest.responses.OAuthErrorResponseParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

final class FlowErrorHandler extends ErrorHandler {

  static final ErrorHandler INSTANCE = new FlowErrorHandler();

  private static final Logger LOGGER = LoggerFactory.getLogger(FlowErrorHandler.class);

  private FlowErrorHandler() {}

  @Override
  public ErrorResponse parseResponse(int code, String json) {
    try {
      return OAuthErrorResponseParser.fromJson(code, json);
    } catch (Exception e) {
      LOGGER.warn("Unable to parse error response", e);
    }
    return ErrorResponse.builder().responseCode(code).withMessage(json).build();
  }

  @Override
  public void accept(ErrorResponse errorResponse) {
    throw new OAuth2Exception(errorResponse);
  }
}
