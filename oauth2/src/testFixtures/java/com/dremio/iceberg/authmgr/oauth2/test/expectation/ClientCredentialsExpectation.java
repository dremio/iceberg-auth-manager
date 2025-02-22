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

import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.SCOPE1;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.SCOPE2;
import static com.dremio.iceberg.authmgr.oauth2.test.expectation.ExpectationUtils.getParameterBody;

import com.dremio.iceberg.authmgr.oauth2.rest.ImmutableClientCredentialsTokenRequest;
import com.dremio.iceberg.authmgr.oauth2.rest.PostFormRequest;
import com.dremio.iceberg.authmgr.oauth2.test.TestConstants;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import org.mockserver.model.HttpRequest;

@AuthManagerImmutable
public abstract class ClientCredentialsExpectation extends InitialTokenFetchExpectation {

  @Override
  public void create() {
    super.create();
    // Some tests also require a second expectation for CLIENT_ID2 + SCOPE2, returning
    // access_initial2 + refresh_initial2
    HttpRequest request =
        tokenRequestTemplate()
            .withHeader("Authorization", "Basic " + TestConstants.CLIENT_CREDENTIALS2_BASE_64)
            .withBody(
                getParameterBody(
                    ImmutableClientCredentialsTokenRequest.builder().scope(SCOPE2).build()));
    getClientAndServer()
        .when(request)
        .respond(httpRequest -> tokenResponse(httpRequest, "access_initial2", "refresh_initial2"));
  }

  @Override
  protected PostFormRequest tokenRequestBody() {
    return ImmutableClientCredentialsTokenRequest.builder().scope(SCOPE1).build();
  }
}
