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
package com.dremio.iceberg.authmgr.oauth2.test.expectation;

import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.SCOPE1;

import com.dremio.iceberg.authmgr.oauth2.rest.ImmutableTokenExchangeRequest;
import com.dremio.iceberg.authmgr.oauth2.rest.PostFormRequest;
import com.dremio.iceberg.authmgr.oauth2.token.TypedToken;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import org.mockserver.model.HttpRequest;

@AuthManagerImmutable
public abstract class IcebergRefreshTokenExpectation extends AbstractTokenEndpointExpectation {

  @Override
  public void create() {
    getClientAndServer()
        .when(tokenRequest())
        .respond(httpRequest -> tokenResponse(httpRequest, "access_refreshed", null));
  }

  @Override
  protected void addRequestHeaders(HttpRequest request) {
    // accept both Basic and Bearer
    request.withHeader("Authorization", "(Basic|Bearer) .*");
  }

  @Override
  protected PostFormRequest tokenRequestBody() {
    return ImmutableTokenExchangeRequest.builder()
        .subjectToken("access_.*")
        .subjectTokenType(TypedToken.URN_ACCESS_TOKEN)
        .scope(SCOPE1)
        .putExtraParameter("extra1", "value1")
        .build();
  }
}
