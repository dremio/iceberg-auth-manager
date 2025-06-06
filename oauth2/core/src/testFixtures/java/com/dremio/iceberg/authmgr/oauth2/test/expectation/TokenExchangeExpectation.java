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

import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.ACTOR_TOKEN;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.ACTOR_TOKEN_TYPE;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.AUDIENCE;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.CLIENT_ID1;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.REQUESTED_TOKEN_TYPE;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.RESOURCE;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.SUBJECT_TOKEN;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.SUBJECT_TOKEN_TYPE;

import com.dremio.iceberg.authmgr.oauth2.rest.ImmutableTokenExchangeRequest;
import com.dremio.iceberg.authmgr.oauth2.rest.PostFormRequest;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;

@AuthManagerImmutable
public abstract class TokenExchangeExpectation extends InitialTokenFetchExpectation {

  @Override
  protected PostFormRequest tokenRequestBody() {
    return ImmutableTokenExchangeRequest.builder()
        .clientId(getTestEnvironment().isPrivateClient() ? null : CLIENT_ID1)
        .subjectToken(SUBJECT_TOKEN)
        .subjectTokenType(SUBJECT_TOKEN_TYPE)
        .actorToken(ACTOR_TOKEN)
        .actorTokenType(ACTOR_TOKEN_TYPE)
        .requestedTokenType(REQUESTED_TOKEN_TYPE)
        .audience(AUDIENCE)
        .resource(RESOURCE)
        .putExtraParameter("extra1", "value1")
        .build();
  }
}
