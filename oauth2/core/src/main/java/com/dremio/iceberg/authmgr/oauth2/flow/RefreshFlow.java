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
import java.util.concurrent.CompletionStage;

/** An interface representing an OAuth2 flow that can be used to refresh existing tokens. */
public interface RefreshFlow extends Flow {

  /**
   * Refreshes the current tokens.
   *
   * <p>A flow may be stateful or stateless. Stateful flows should clean up internal resources when
   * the returned {@link CompletionStage} completes.
   *
   * @param currentTokens The current tokens. Cannot be null.
   * @return A future that completes when the tokens are refreshed.
   */
  CompletionStage<Tokens> refreshTokens(Tokens currentTokens);
}
