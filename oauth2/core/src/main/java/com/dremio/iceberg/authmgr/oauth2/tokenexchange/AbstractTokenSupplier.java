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

import com.dremio.iceberg.authmgr.oauth2.OAuth2Properties;
import com.dremio.iceberg.authmgr.oauth2.agent.OAuth2Agent;
import com.dremio.iceberg.authmgr.oauth2.agent.OAuth2AgentSpec;
import com.dremio.iceberg.authmgr.oauth2.grant.GrantType;
import com.dremio.iceberg.authmgr.oauth2.token.TypedToken;
import jakarta.annotation.Nullable;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ScheduledExecutorService;
import java.util.function.Supplier;
import org.apache.iceberg.rest.RESTClient;
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
  public CompletionStage<TypedToken> supplyTokenAsync() {
    if (getTokenAgent() != null) {
      return getTokenAgent().authenticateAsync().thenApply(TypedToken::of);
    }
    return getToken().isPresent()
        ? CompletableFuture.completedFuture(TypedToken.of(getToken().get(), getTokenType()))
        : CompletableFuture.completedFuture(null);
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
    if (getMainSpec().getBasicConfig().getGrantType() != GrantType.TOKEN_EXCHANGE
        || getToken().isPresent()
        || getTokenConfig().isEmpty()) {
      return null;
    }
    Map<String, String> config = getTokenConfig();
    if (!config.containsKey(OAuth2Properties.Runtime.AGENT_NAME)) {
      config = new HashMap<>(config);
      config.put(OAuth2Properties.Runtime.AGENT_NAME, getDefaultAgentName());
    }
    OAuth2AgentSpec tokenSpec = getMainSpec().merge(config);
    return new OAuth2Agent(tokenSpec, getExecutor(), getRestClientSupplier());
  }

  @Override
  public void close() {
    if (getTokenAgent() != null) {
      getTokenAgent().close();
    }
  }

  protected abstract OAuth2AgentSpec getMainSpec();

  protected abstract ScheduledExecutorService getExecutor();

  protected abstract Supplier<RESTClient> getRestClientSupplier();

  protected abstract Optional<String> getToken();

  protected abstract URI getTokenType();

  @Value.Derived
  protected abstract Map<String, String> getTokenConfig();

  protected abstract String getDefaultAgentName();
}
