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
package com.dremio.iceberg.authmgr.oauth2;

import com.dremio.iceberg.authmgr.oauth2.agent.OAuth2Agent;
import com.dremio.iceberg.authmgr.oauth2.agent.OAuth2AgentSpec;
import com.dremio.iceberg.authmgr.oauth2.token.AccessToken;
import java.util.concurrent.ScheduledExecutorService;
import java.util.function.Supplier;
import org.apache.iceberg.rest.HTTPHeaders;
import org.apache.iceberg.rest.HTTPHeaders.HTTPHeader;
import org.apache.iceberg.rest.HTTPRequest;
import org.apache.iceberg.rest.ImmutableHTTPRequest;
import org.apache.iceberg.rest.RESTClient;
import org.apache.iceberg.rest.auth.AuthSession;

public class OAuth2Session implements AuthSession {

  private final OAuth2Agent agent;

  public OAuth2Session(
      OAuth2AgentSpec spec,
      ScheduledExecutorService executor,
      Supplier<RESTClient> restClientSupplier) {
    this.agent = new OAuth2Agent(spec, executor, restClientSupplier);
  }

  private OAuth2Session(OAuth2Session toCopy) {
    this.agent = toCopy.agent.copy();
  }

  public OAuth2AgentSpec getSpec() {
    return agent.getSpec();
  }

  /**
   * Copies this session and the underlying agent. This is only needed when reusing an init session
   * as a catalog session.
   */
  public OAuth2Session copy() {
    return new OAuth2Session(this);
  }

  @Override
  public HTTPRequest authenticate(HTTPRequest request) {
    AccessToken accessToken = agent.authenticate();
    HTTPHeader authorization = HTTPHeader.of("Authorization", "Bearer " + accessToken.getPayload());
    HTTPHeaders newHeaders = request.headers().putIfAbsent(HTTPHeaders.of(authorization));
    return newHeaders.equals(request.headers())
        ? request
        : ImmutableHTTPRequest.builder().from(request).headers(newHeaders).build();
  }

  @Override
  public void close() {
    agent.close();
  }
}
