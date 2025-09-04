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

import static com.dremio.iceberg.authmgr.oauth2.config.ConfigUtils.prefixedMap;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Config;
import com.dremio.iceberg.authmgr.oauth2.agent.OAuth2Agent;
import com.dremio.iceberg.authmgr.oauth2.agent.OAuth2AgentRuntime;
import com.dremio.iceberg.authmgr.oauth2.config.SystemConfig;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.TokenTypeURI;
import com.nimbusds.oauth2.sdk.token.TypelessAccessToken;
import jakarta.annotation.Nullable;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import org.immutables.value.Value;

public abstract class AbstractTokenSupplier implements AutoCloseable {

  /**
   * Returns a stage that will supply the requested token when completed.
   *
   * <p>If the token is static, the returned stage will be already completed with the token to use.
   * Otherwise, the stage will complete when the underlying agent has completed its authentication.
   *
   * <p>If no token is configured, the returned stage will be already completed, with a null value.
   */
  public CompletionStage<AccessToken> supplyTokenAsync() {
    if (getTokenAgent() != null) {
      return getTokenAgent().authenticateAsync();
    }
    if (getStaticToken().isPresent()) {
      TypelessAccessToken token = getStaticToken().get();
      BearerAccessToken accessToken =
          new BearerAccessToken(token.getValue(), 0, null, getStaticTokenType());
      return CompletableFuture.completedFuture(accessToken);
    } else {
      return CompletableFuture.completedFuture(null);
    }
  }

  /**
   * Returns a copy of this token supplier. The copy will share the same spec, executor and REST
   * client supplier as the original supplier, as well as its static token, if any. If the token is
   * dynamic, the original agent will be copied.
   */
  public abstract AbstractTokenSupplier copy();

  /**
   * Returns the agent to use for fetching the token. Returns null if the token is static or not
   * configured.
   */
  @Value.Default
  @Nullable
  protected OAuth2Agent getTokenAgent() {
    if (!getMainConfig().getBasicConfig().getGrantType().equals(GrantType.TOKEN_EXCHANGE)
        || getStaticToken().isPresent()
        || getTokenAgentConfig().isEmpty()) {
      return null;
    }
    Map<String, String> tokenAgentProperties = getTokenAgentConfig();
    if (!tokenAgentProperties.containsKey(SystemConfig.PREFIX + '.' + SystemConfig.AGENT_NAME)) {
      tokenAgentProperties = new HashMap<>(tokenAgentProperties);
      tokenAgentProperties.put(
          SystemConfig.PREFIX + '.' + SystemConfig.AGENT_NAME, getDefaultAgentName());
    }
    OAuth2Config tokenAgentConfig = getMainConfig().merge(tokenAgentProperties);
    return new OAuth2Agent(tokenAgentConfig, getRuntime());
  }

  @Override
  public void close() {
    if (getTokenAgent() != null) {
      getTokenAgent().close();
    }
  }

  @Value.Derived
  protected Map<String, String> getTokenAgentConfig() {
    return prefixedMap(getDynamicTokenConfig(), OAuth2Config.PREFIX);
  }

  protected abstract OAuth2Config getMainConfig();

  protected abstract OAuth2AgentRuntime getRuntime();

  @Value.Derived
  protected abstract Optional<TypelessAccessToken> getStaticToken();

  @Value.Derived
  protected abstract TokenTypeURI getStaticTokenType();

  @Value.Derived
  protected abstract Map<String, String> getDynamicTokenConfig();

  @Value.Derived
  protected abstract String getDefaultAgentName();
}
