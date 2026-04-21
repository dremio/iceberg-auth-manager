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

import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.AUDIENCE;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.RESOURCE;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.SCOPE1;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.SCOPE2;

import com.dremio.iceberg.authmgr.oauth2.test.TestConstants;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.google.common.collect.ImmutableMap;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.token.TokenTypeURI;
import java.util.regex.Pattern;

@AuthManagerImmutable
public abstract class TokenExchangeExpectation extends InitialTokenFetchExpectation {

  @Override
  protected ImmutableMap.Builder<String, String> requestBody() {
    return super.requestBody()
        .put("grant_type", GrantType.TOKEN_EXCHANGE.toString())
        .put(
            "subject_token",
            String.format(
                "(%s|%s)",
                Pattern.quote(TestConstants.SUBJECT_TOKEN),
                Pattern.quote(TestConstants.ACCESS_TOKEN_INITIAL)))
        .put(
            "actor_token",
            String.format(
                "(%s|%s)",
                Pattern.quote(TestConstants.ACTOR_TOKEN),
                Pattern.quote(TestConstants.ACCESS_TOKEN_INITIAL)))
        .put("subject_token_type", "urn:ietf:params:oauth:token-type:.*")
        .put("actor_token_type", "urn:ietf:params:oauth:token-type:.*")
        .put("requested_token_type", TokenTypeURI.ACCESS_TOKEN.toString())
        .put("audience", AUDIENCE.toString())
        .put("resource", RESOURCE.toString())
        .put("scope", String.format("(%s|%s)", SCOPE1, SCOPE2));
  }
}
