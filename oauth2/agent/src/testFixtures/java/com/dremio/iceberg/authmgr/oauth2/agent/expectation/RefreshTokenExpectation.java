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
package com.dremio.iceberg.authmgr.oauth2.agent.expectation;

import static com.dremio.iceberg.authmgr.oauth2.agent.TestConstants.ACCESS_TOKEN_REFRESHED;
import static com.dremio.iceberg.authmgr.oauth2.agent.TestConstants.REFRESH_TOKEN_REFRESHED;
import static com.dremio.iceberg.authmgr.oauth2.agent.TestConstants.SCOPE1;
import static com.dremio.iceberg.authmgr.oauth2.agent.TestConstants.SCOPE2;

import com.dremio.iceberg.authmgr.oauth2.agent.TestConstants;
import com.dremio.iceberg.authmgr.oauth2.agent.TestServer;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.google.common.collect.ImmutableMap;
import com.nimbusds.oauth2.sdk.GrantType;
import java.util.regex.Pattern;

@AuthManagerImmutable
public abstract class RefreshTokenExpectation extends AbstractTokenEndpointExpectation {

  @Override
  public void create() {
    TestServer.getInstance()
        .when(request())
        .respond(
            httpRequest -> response(httpRequest, ACCESS_TOKEN_REFRESHED, REFRESH_TOKEN_REFRESHED));
  }

  @Override
  protected ImmutableMap.Builder<String, String> requestBody() {
    return super.requestBody()
        .put("grant_type", GrantType.REFRESH_TOKEN.toString())
        .put(
            "refresh_token",
            String.format(
                "(%s|%s)",
                Pattern.quote(TestConstants.REFRESH_TOKEN_INITIAL),
                Pattern.quote(TestConstants.REFRESH_TOKEN_REFRESHED)))
        .put("scope", String.format("(%s|%s)", SCOPE1, SCOPE2));
  }
}
