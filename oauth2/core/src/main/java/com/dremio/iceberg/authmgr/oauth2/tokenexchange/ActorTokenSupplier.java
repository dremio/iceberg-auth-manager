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
package com.dremio.iceberg.authmgr.oauth2.tokenexchange;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Config;
import com.dremio.iceberg.authmgr.oauth2.agent.OAuth2AgentRuntime;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.nimbusds.oauth2.sdk.token.TokenTypeURI;
import com.nimbusds.oauth2.sdk.token.TypelessAccessToken;
import java.util.Map;
import java.util.Optional;

/** A component that centralizes the logic for supplying the actor token for token exchanges. */
@AuthManagerImmutable
public abstract class ActorTokenSupplier extends AbstractTokenSupplier {

  public static ActorTokenSupplier create(OAuth2Config config, OAuth2AgentRuntime runtime) {
    return ImmutableActorTokenSupplier.builder().mainConfig(config).runtime(runtime).build();
  }

  @Override
  public ActorTokenSupplier copy() {
    return ImmutableActorTokenSupplier.builder()
        .from(this)
        .tokenAgent(getTokenAgent() == null ? null : getTokenAgent().copy())
        .build();
  }

  @Override
  protected Optional<TypelessAccessToken> getStaticToken() {
    return getMainConfig().getTokenExchangeConfig().getActorToken();
  }

  @Override
  protected TokenTypeURI getStaticTokenType() {
    return getMainConfig().getTokenExchangeConfig().getActorTokenType();
  }

  @Override
  protected Map<String, String> getDynamicTokenConfig() {
    return getMainConfig().getTokenExchangeConfig().getActorTokenConfig();
  }

  @Override
  protected String getDefaultAgentName() {
    return getMainConfig().getSystemConfig().getAgentName() + "-actor";
  }
}
