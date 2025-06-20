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
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.SCOPE2;

import com.dremio.iceberg.authmgr.oauth2.rest.ImmutableClientCredentialsTokenRequest;
import com.dremio.iceberg.authmgr.oauth2.rest.PostFormRequest;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;

@AuthManagerImmutable
public abstract class ClientCredentialsExpectation extends InitialTokenFetchExpectation {

  @Override
  protected PostFormRequest tokenRequestBody() {
    return ImmutableClientCredentialsTokenRequest.builder()
        .scope(String.format("(%s|%s)", SCOPE1, SCOPE2))
        .putExtraParameter("(extra1|extra2)", "(value1|value2)")
        .build();
  }
}
