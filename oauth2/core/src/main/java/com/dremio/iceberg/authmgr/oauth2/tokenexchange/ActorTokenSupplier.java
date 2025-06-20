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

import com.dremio.iceberg.authmgr.oauth2.agent.OAuth2AgentSpec;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import java.net.URI;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ScheduledExecutorService;
import java.util.function.Supplier;
import org.apache.iceberg.rest.RESTClient;

/** A component that centralizes the logic for supplying the actor token for token exchanges. */
@AuthManagerImmutable
public abstract class ActorTokenSupplier extends AbstractTokenSupplier {

  public static ActorTokenSupplier of(
      OAuth2AgentSpec spec,
      ScheduledExecutorService executor,
      Supplier<RESTClient> restClientSupplier) {
    return ImmutableActorTokenSupplier.builder()
        .mainSpec(spec)
        .executor(executor)
        .restClientSupplier(restClientSupplier)
        .build();
  }

  @Override
  protected Optional<String> getToken() {
    return getMainSpec().getTokenExchangeConfig().getActorToken();
  }

  @Override
  protected URI getTokenType() {
    return getMainSpec().getTokenExchangeConfig().getActorTokenType();
  }

  @Override
  protected Map<String, String> getTokenConfig() {
    return getMainSpec().getTokenExchangeConfig().getActorTokenConfig();
  }

  @Override
  protected String getDefaultAgentName() {
    return getMainSpec().getRuntimeConfig().getAgentName() + "-actor";
  }
}
