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

import com.dremio.iceberg.authmgr.oauth2.token.Tokens;
import jakarta.annotation.Nullable;
import java.util.concurrent.CompletionStage;

/**
 * An interface representing an OAuth2 flow. A flow is used to fetch new tokens from the OAuth2
 * provider.
 *
 * <p>A flow is a short-lived component that represents a set of interactions (generally one, but
 * sometimes more) between the agent and the server, in order to obtain access tokens.
 *
 * <p>A flow may be stateful or stateless. Stateful flows should clean up internal resources when
 * the returned {@link CompletionStage} completes.
 */
public interface Flow {

  /**
   * Fetches new tokens from the OAuth2 provider. This method is called when the current tokens are
   * expired or about to expire, and new tokens are needed.
   *
   * @param currentTokens The current tokens. This can be null if no tokens are available.
   * @return The new tokens fetched from the OAuth2 provider.
   */
  CompletionStage<Tokens> fetchNewTokens(@Nullable Tokens currentTokens);
}
