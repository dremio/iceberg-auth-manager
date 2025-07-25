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

import com.dremio.iceberg.authmgr.oauth2.config.Secret;
import com.dremio.iceberg.authmgr.oauth2.rest.PasswordTokenRequest;
import com.dremio.iceberg.authmgr.oauth2.token.Tokens;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import java.util.concurrent.CompletionStage;

/**
 * An implementation of the <a
 * href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.3">Resource Owner Password
 * Credentials Grant</a> flow.
 */
@AuthManagerImmutable
abstract class PasswordFlow extends AbstractFlow implements InitialFlow {

  interface Builder extends AbstractFlow.Builder<PasswordFlow, Builder> {}

  @Override
  public CompletionStage<Tokens> fetchNewTokens() {
    String username =
        getSpec()
            .getResourceOwnerConfig()
            .getUsername()
            .orElseThrow(() -> new IllegalStateException("Username is required"));
    String password =
        getSpec()
            .getResourceOwnerConfig()
            .getPassword()
            .map(Secret::getSecret)
            .orElseThrow(() -> new IllegalStateException("Password is required"));
    PasswordTokenRequest.Builder request =
        PasswordTokenRequest.builder().username(username).password(password);
    return invokeTokenEndpoint(null, request);
  }
}
