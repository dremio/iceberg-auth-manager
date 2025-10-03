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
package com.dremio.iceberg.authmgr.oauth2.test.container;

import com.google.errorprone.annotations.CanIgnoreReturnValue;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;

public class HydraContainer extends GenericContainer<HydraContainer> {

  private static final Logger LOGGER = LoggerFactory.getLogger(HydraContainer.class);

  private static final int PUBLIC_PORT = 4444;
  private static final int ADMIN_PORT = 4445;

  public static final String ISSUER_URL = "http://localhost:" + PUBLIC_PORT + "/";

  private final List<HydraClient> clients = new ArrayList<>();

  private URI publicUrl;
  private URI adminUrl;
  private URI tokenEndpoint;
  private URI authEndpoint;

  @SuppressWarnings("resource")
  public HydraContainer() {
    super("oryd/hydra:v2.3.0");

    withNetworkAliases("hydra");
    withLogConsumer(new Slf4jLogConsumer(LOGGER));
    withExposedPorts(PUBLIC_PORT, ADMIN_PORT);
    waitingFor(Wait.forHttp("/health/ready").forPort(PUBLIC_PORT));

    withEnv("DSN", "memory"); // Use in-memory database
    withEnv("URLS_SELF_ISSUER", ISSUER_URL);
    withEnv("SECRETS_SYSTEM", "this-is-a-test-secret-only-for-testing");
    withEnv("OIDC_SUBJECT_IDENTIFIERS_SUPPORTED_TYPES", "public");
    withEnv("OIDC_SUBJECT_IDENTIFIERS_PAIRWISE_SALT", "test-salt");
    withEnv("STRATEGIES_ACCESS_TOKEN", "jwt");

    withEnv("LOG_LEVEL", getLogLevel());
    withEnv("LOG_FORMAT", "text");
    withEnv("LOG_LEAK_SENSITIVE_VALUES", "true"); // Enable sensitive value logging for debugging

    withCommand("serve", "all", "--dev");
  }

  @CanIgnoreReturnValue
  public HydraContainer withClient(String clientId, String clientSecret, String authMethod) {
    clients.add(new HydraClient(clientId, clientSecret, authMethod));
    return this;
  }

  @Override
  public void start() {
    if (getContainerId() != null) {
      return;
    }
    super.start();
    publicUrl = URI.create("http://localhost:" + getMappedPort(PUBLIC_PORT));
    adminUrl = URI.create("http://localhost:" + getMappedPort(ADMIN_PORT));
    tokenEndpoint = publicUrl.resolve("/oauth2/token");
    authEndpoint = publicUrl.resolve("/oauth2/auth");
    LOGGER.info("Hydra URLs configured: public={}, admin={}", publicUrl, adminUrl);
    try (Client httpClient = ClientBuilder.newBuilder().build()) {
      for (HydraClient client : clients) {
        createClient(client, httpClient);
      }
    }
  }

  public URI getPublicUrl() {
    return publicUrl;
  }

  public URI getAdminUrl() {
    return adminUrl;
  }

  public URI getTokenEndpoint() {
    return tokenEndpoint;
  }

  public URI getAuthEndpoint() {
    return authEndpoint;
  }

  private void createClient(HydraClient hydraClient, Client httpClient) {
    StringBuilder builder = new StringBuilder();
    builder.append("{");
    builder.append("\"client_id\":\"").append(hydraClient.clientId).append("\",");
    builder.append("\"client_name\":\"").append(hydraClient.clientId).append("\",");
    if (hydraClient.clientSecret != null) {
      builder.append("\"client_secret\":\"").append(hydraClient.clientSecret).append("\",");
    }
    builder.append("\"grant_types\":[");
    if (hydraClient.authMethod.equals("none")) {
      builder.append("\"client_credentials\"");
    } else {
      builder.append(
          "\"client_credentials\", \"password\", \"authorization_code\", \"refresh_token\"");
    }
    builder.append("],");
    builder.append("\"response_types\":[\"code\",\"token\",\"id_token\"],");
    builder.append("\"scope\":\"catalog openid offline\",");
    builder.append("\"redirect_uris\":[");
    builder.append("\"http://localhost:63000").append("/*\"");
    builder.append("],");
    builder.append("\"token_endpoint_auth_method\":\"").append(hydraClient.authMethod).append("\"");
    builder.append("}");

    String json = builder.toString();

    try (Response response =
        httpClient.target(getAdminUrl()).path("/admin/clients").request().post(Entity.json(json))) {
      if (response.getStatus() != Response.Status.CREATED.getStatusCode()) {
        throw new RuntimeException("Failed to create client: " + response.readEntity(String.class));
      }
    }
  }

  private record HydraClient(String clientId, String clientSecret, String authMethod) {}

  private static String getLogLevel() {
    return LOGGER.isDebugEnabled()
        ? "debug"
        : LOGGER.isInfoEnabled() ? "info" : LOGGER.isWarnEnabled() ? "warn" : "error";
  }
}
