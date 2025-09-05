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
import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties;
import com.dremio.iceberg.authmgr.oauth2.agent.OAuth2Agent;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Token;
import com.nimbusds.oauth2.sdk.token.TokenTypeURI;
import jakarta.annotation.Nullable;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ScheduledExecutorService;
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
    if (getToken().isPresent()) {
      Token token = getToken().get();
      BearerAccessToken accessToken =
          token instanceof BearerAccessToken
              ? (BearerAccessToken) token
              : new BearerAccessToken(token.getValue(), 0, null, getTokenType());
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
        || getToken().isPresent()
        || getTokenAgentProperties().isEmpty()) {
      return null;
    }
    Map<String, String> tokenAgentProperties = getTokenAgentProperties();
    if (!tokenAgentProperties.containsKey(OAuth2Properties.System.AGENT_NAME)) {
      tokenAgentProperties = new HashMap<>(tokenAgentProperties);
      tokenAgentProperties.put(OAuth2Properties.System.AGENT_NAME, getDefaultAgentName());
    }
    OAuth2Config tokenAgentConfig = getMainConfig().merge(tokenAgentProperties);
    return new OAuth2Agent(tokenAgentConfig, getExecutor());
  }

  @Override
  public void close() {
    if (getTokenAgent() != null) {
      getTokenAgent().close();
    }
  }

  protected abstract OAuth2Config getMainConfig();

  protected abstract ScheduledExecutorService getExecutor();

  protected abstract Optional<Token> getToken();

  protected abstract TokenTypeURI getTokenType();

  @Value.Derived
  protected abstract Map<String, String> getTokenAgentProperties();

  protected abstract String getDefaultAgentName();
}
