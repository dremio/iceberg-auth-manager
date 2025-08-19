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

import com.dremio.iceberg.authmgr.oauth2.OAuth2Config;
import com.dremio.iceberg.authmgr.oauth2.endpoint.EndpointProvider;
import com.dremio.iceberg.authmgr.oauth2.http.HttpClient;
import com.dremio.iceberg.authmgr.oauth2.tokenexchange.ActorTokenSupplier;
import com.dremio.iceberg.authmgr.oauth2.tokenexchange.SubjectTokenSupplier;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import jakarta.annotation.Nullable;
import java.util.Objects;
import java.util.concurrent.ScheduledExecutorService;
import org.immutables.value.Value;

@AuthManagerImmutable
public abstract class FlowFactory implements AutoCloseable {

  public static FlowFactory create(OAuth2Config config, ScheduledExecutorService executor) {
    return ImmutableFlowFactory.builder().config(config).executor(executor).build();
  }

  /** Creates a flow for fetching new tokens. This is used for the initial token fetch. */
  public Flow createInitialFlow() {
    return newInitialFlowBuilder()
        .config(getConfig())
        .executor(getExecutor())
        .endpointProvider(getEndpointProvider())
        .requestSender(getHttpClient())
        .build();
  }

  /**
   * Creates a flow for refreshing tokens. This is used for refreshing tokens when the access token
   * expires.
   */
  public Flow createTokenRefreshFlow(RefreshToken currentRefreshToken) {
    return ImmutableRefreshTokenFlow.builder()
        .config(getConfig())
        .executor(getExecutor())
        .endpointProvider(getEndpointProvider())
        .requestSender(getHttpClient())
        .refreshToken(currentRefreshToken)
        .build();
  }

  @Override
  @SuppressWarnings("EmptyTryBlock")
  public void close() {
    SubjectTokenSupplier subjectTokenSupplier = getSubjectTokenSupplier();
    ActorTokenSupplier actorTokenSupplier = getActorTokenSupplier();
    HttpClient httpClient = getHttpClient();
    try (httpClient;
        subjectTokenSupplier;
        actorTokenSupplier) {}
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

  protected abstract OAuth2Config getConfig();

  protected abstract ScheduledExecutorService getExecutor();

  @Value.Lazy
  @SuppressWarnings("MustBeClosedChecker")
  protected HttpClient getHttpClient() {
    return HttpClient.create(getConfig());
  }

  @Value.Default
  protected EndpointProvider getEndpointProvider() {
    return EndpointProvider.create(getConfig(), getHttpClient());
  }

  @Value.Default
  @Nullable
  protected SubjectTokenSupplier getSubjectTokenSupplier() {
    return getConfig().getBasicConfig().getGrantType() != GrantType.TOKEN_EXCHANGE
        ? null
        : SubjectTokenSupplier.create(getConfig(), getExecutor());
  }

  @Value.Default
  @Nullable
  protected ActorTokenSupplier getActorTokenSupplier() {
    return getConfig().getBasicConfig().getGrantType() != GrantType.TOKEN_EXCHANGE
        ? null
        : ActorTokenSupplier.create(getConfig(), getExecutor());
  }

  private AbstractFlow.Builder<? extends Flow, ?> newInitialFlowBuilder() {

    GrantType grantType = getConfig().getBasicConfig().getGrantType();

    if (grantType.equals(GrantType.CLIENT_CREDENTIALS)) {
      return ImmutableClientCredentialsFlow.builder();

    } else if (grantType.equals(GrantType.PASSWORD)) {
      return ImmutablePasswordFlow.builder();

    } else if (grantType.equals(GrantType.AUTHORIZATION_CODE)) {
      return ImmutableAuthorizationCodeFlow.builder();

    } else if (grantType.equals(GrantType.DEVICE_CODE)) {
      return ImmutableDeviceCodeFlow.builder();

    } else if (grantType.equals(GrantType.TOKEN_EXCHANGE)) {
      return ImmutableTokenExchangeFlow.builder()
          .subjectTokenStage(Objects.requireNonNull(getSubjectTokenSupplier()).supplyTokenAsync())
          .actorTokenStage(Objects.requireNonNull(getActorTokenSupplier()).supplyTokenAsync());
    }

    throw new IllegalArgumentException(
        "Unknown or invalid grant type for initial token fetch: "
            + getConfig().getBasicConfig().getGrantType());
  }
}
