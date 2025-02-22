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
package com.dremio.iceberg.authmgr.oauth2.test.expectation;

import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;
import org.mockserver.model.JsonBody;
import org.mockserver.model.MediaType;

@AuthManagerImmutable
public abstract class ErrorExpectation extends AbstractExpectation {

  public static final HttpResponse AUTHORIZATION_SERVER_ERROR_RESPONSE =
      HttpResponse.response()
          .withStatusCode(401)
          .withContentType(MediaType.APPLICATION_JSON)
          .withBody(
              JsonBody.json(
                  "{\"error\":\"invalid_request\",\"error_description\":\"Invalid request\"}"));

  public static final HttpResponse CATALLG_SERVER_ERROR_RESPONSE =
      HttpResponse.response()
          .withStatusCode(401)
          .withContentType(MediaType.APPLICATION_JSON)
          .withBody(
              JsonBody.json(
                  "{\"error\":{\"code\":401,\"type\":\"invalid_request\",\"message\":\"Invalid request\"}}"));

  @Override
  public void create() {
    getClientAndServer()
        .when(
            HttpRequest.request()
                .withPath(getTestEnvironment().getAuthorizationServerContextPath() + ".*"))
        .respond(AUTHORIZATION_SERVER_ERROR_RESPONSE);
    getClientAndServer()
        .when(
            HttpRequest.request()
                .withPath(getTestEnvironment().getImpersonationServerContextPath() + ".*"))
        .respond(AUTHORIZATION_SERVER_ERROR_RESPONSE);
    getClientAndServer()
        .when(
            HttpRequest.request()
                .withPath(getTestEnvironment().getCatalogServerContextPath() + ".*"))
        .respond(CATALLG_SERVER_ERROR_RESPONSE);
  }
}
