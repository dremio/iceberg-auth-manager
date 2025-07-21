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

import com.dremio.iceberg.authmgr.oauth2.agent.OAuth2AgentSpec;
import com.dremio.iceberg.authmgr.oauth2.auth.ClientAuthenticator;
import com.dremio.iceberg.authmgr.oauth2.auth.ClientAuthenticatorFactory;
import com.dremio.iceberg.authmgr.oauth2.endpoint.EndpointProvider;
import com.dremio.iceberg.authmgr.oauth2.endpoint.EndpointProviderFactory;
import com.dremio.iceberg.authmgr.oauth2.grant.GrantType;
import com.dremio.iceberg.authmgr.oauth2.tokenexchange.ActorTokenSupplier;
import com.dremio.iceberg.authmgr.oauth2.tokenexchange.SubjectTokenSupplier;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import jakarta.annotation.Nullable;
import java.util.Objects;
import java.util.concurrent.ScheduledExecutorService;
import java.util.function.Supplier;
import org.apache.iceberg.rest.RESTClient;
import org.immutables.value.Value;

@AuthManagerImmutable
public abstract class FlowFactory implements AutoCloseable {

  public static FlowFactory of(
      OAuth2AgentSpec spec,
      ScheduledExecutorService executor,
      Supplier<RESTClient> restClientSupplier) {
    return ImmutableFlowFactory.builder()
        .spec(spec)
        .executor(executor)
        .restClientSupplier(restClientSupplier)
        .build();
  }

  /** Creates a flow for fetching new tokens. This is used for the initial token fetch. */
  public InitialFlow createInitialFlow() {
    return newInitialFlowBuilder()
        .spec(getSpec())
        .executor(getExecutor())
        .restClient(getRestClientSupplier().get())
        .endpointProvider(getEndpointProvider())
        .clientAuthenticator(getClientAuthenticator())
        .build();
  }

  /**
   * Creates a flow for refreshing tokens. This is used for refreshing tokens when the access token
   * expires.
   */
  public RefreshFlow createTokenRefreshFlow() {
    return newTokenRefreshFlowBuilder()
        .spec(getSpec())
        .executor(getExecutor())
        .restClient(getRestClientSupplier().get())
        .endpointProvider(getEndpointProvider())
        .clientAuthenticator(getClientAuthenticator())
        .build();
  }

  @Override
  @SuppressWarnings("EmptyTryBlock")
  public void close() {
    if (getSpec().getBasicConfig().getGrantType() == GrantType.TOKEN_EXCHANGE) {
      SubjectTokenSupplier subjectTokenSupplier = getSubjectTokenSupplier();
      ActorTokenSupplier actorTokenSupplier = getActorTokenSupplier();
      try (subjectTokenSupplier;
          actorTokenSupplier) {}
    }
  }

  public FlowFactory copy() {
    SubjectTokenSupplier subjectTokenSupplier = getSubjectTokenSupplier();
    ActorTokenSupplier actorTokenSupplier = getActorTokenSupplier();
    return ImmutableFlowFactory.builder()
        .from(this)
        // Copy the token suppliers to also create copies of their internal agents.
        .subjectTokenSupplier(subjectTokenSupplier == null ? null : subjectTokenSupplier.copy())
        .actorTokenSupplier(actorTokenSupplier == null ? null : actorTokenSupplier.copy())
        .build();
  }

  protected abstract OAuth2AgentSpec getSpec();

  protected abstract ScheduledExecutorService getExecutor();

  protected abstract Supplier<RESTClient> getRestClientSupplier();

  @Value.Default
  protected EndpointProvider getEndpointProvider() {
    return EndpointProviderFactory.createEndpointProvider(getSpec(), getRestClientSupplier());
  }

  @Value.Default
  protected ClientAuthenticator getClientAuthenticator() {
    return ClientAuthenticatorFactory.createAuthenticator(
        getSpec(), getEndpointProvider().getResolvedTokenEndpoint());
  }

  @Value.Default
  @Nullable
  protected SubjectTokenSupplier getSubjectTokenSupplier() {
    return getSpec().getBasicConfig().getGrantType() != GrantType.TOKEN_EXCHANGE
        ? null
        : SubjectTokenSupplier.of(getSpec(), getExecutor(), getRestClientSupplier());
  }

  @Value.Default
  @Nullable
  protected ActorTokenSupplier getActorTokenSupplier() {
    return getSpec().getBasicConfig().getGrantType() != GrantType.TOKEN_EXCHANGE
        ? null
        : ActorTokenSupplier.of(getSpec(), getExecutor(), getRestClientSupplier());
  }

  private AbstractFlow.Builder<? extends InitialFlow, ?> newInitialFlowBuilder() {
    switch (getSpec().getBasicConfig().getGrantType()) {
      case CLIENT_CREDENTIALS:
        return ImmutableClientCredentialsFlow.builder();
      case PASSWORD:
        return ImmutablePasswordFlow.builder();
      case AUTHORIZATION_CODE:
        return ImmutableAuthorizationCodeFlow.builder();
      case DEVICE_CODE:
        return ImmutableDeviceCodeFlow.builder();
      case TOKEN_EXCHANGE:
        return ImmutableTokenExchangeFlow.builder()
            .subjectTokenStage(Objects.requireNonNull(getSubjectTokenSupplier()).supplyTokenAsync())
            .actorTokenStage(Objects.requireNonNull(getActorTokenSupplier()).supplyTokenAsync());
      default:
        throw new IllegalArgumentException(
            "Unknown or invalid grant type for initial token fetch: "
                + getSpec().getBasicConfig().getGrantType());
    }
  }

  private AbstractFlow.Builder<? extends RefreshFlow, ?> newTokenRefreshFlowBuilder() {
    switch (getSpec().getBasicConfig().getDialect()) {
      case STANDARD:
        return ImmutableRefreshTokenFlow.builder();
      case ICEBERG_REST:
        return ImmutableIcebergRefreshTokenFlow.builder();
      default:
        throw new IllegalArgumentException(
            "Unknown or invalid dialect: " + getSpec().getBasicConfig().getDialect());
    }
  }
}
