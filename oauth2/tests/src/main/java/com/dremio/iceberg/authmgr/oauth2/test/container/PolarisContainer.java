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
import jakarta.ws.rs.core.GenericType;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.HttpWaitStrategy;

public class PolarisContainer extends GenericContainer<PolarisContainer> {

  private static final Logger LOGGER = LoggerFactory.getLogger(PolarisContainer.class);

  public static final String CLIENT_ID = "Client1";
  public static final String CLIENT_SECRET = "s3cr3t";

  private String clientId = CLIENT_ID;
  private String clientSecret = CLIENT_SECRET;
  private Duration accessTokenLifespan = Duration.ofMinutes(10);

  private URI baseUri;

  @SuppressWarnings("resource")
  public PolarisContainer() {
    super("apache/polaris:1.0.1-incubating");
    withNetworkAliases("polaris");
    withLogConsumer(new Slf4jLogConsumer(LOGGER));
    withExposedPorts(8181, 8182);
    waitingFor(
        new HttpWaitStrategy()
            .forPath("/q/health")
            .forPort(8182)
            .forResponsePredicate(body -> body.contains("\"status\": \"UP\"")));
    withEnv("quarkus.log.level", getRootLoggerLevel());
    withEnv("quarkus.log.category.\"io.quarkus.oidc\".level", getPolarisLoggerLevel());
    withEnv("quarkus.log.category.\"org.apache.polaris\".level", getPolarisLoggerLevel());
  }

  @Override
  @SuppressWarnings("resource")
  public void start() {
    if (getContainerId() != null) {
      return;
    }
    withEnv("POLARIS_BOOTSTRAP_CREDENTIALS", "POLARIS," + clientId + "," + clientSecret);
    withEnv(
        "polaris-authentication.token-broker.max-token-generation", accessTokenLifespan.toString());
    super.start();
    baseUri = URI.create("http://localhost:" + getMappedPort(8181));
  }

  @CanIgnoreReturnValue
  public PolarisContainer withClient(String clientId, String clientSecret) {
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    return this;
  }

  @CanIgnoreReturnValue
  public PolarisContainer withAccessTokenLifespan(Duration accessTokenLifespan) {
    this.accessTokenLifespan = accessTokenLifespan;
    return this;
  }

  public URI baseUri() {
    return baseUri;
  }

  public URI getCatalogApiEndpoint() {
    return baseUri.resolve("/api/catalog/");
  }

  public URI getTokenEndpoint() {
    return getCatalogApiEndpoint().resolve("v1/oauth/tokens");
  }

  public Duration getAccessTokenLifespan() {
    return accessTokenLifespan;
  }

  private static String getRootLoggerLevel() {
    return LOGGER.isInfoEnabled() ? "INFO" : LOGGER.isWarnEnabled() ? "WARN" : "ERROR";
  }

  private static String getPolarisLoggerLevel() {
    return LOGGER.isDebugEnabled() ? "DEBUG" : getRootLoggerLevel();
  }

  public String fetchNewToken() {
    try (Client client = ClientBuilder.newBuilder().build();
        Response response =
            client
                .target(getCatalogApiEndpoint())
                .path("v1/oauth/tokens")
                .request()
                .post(
                    Entity.form(
                        new MultivaluedHashMap<>(
                            Map.of(
                                "grant_type",
                                "client_credentials",
                                "scope",
                                "PRINCIPAL_ROLE:ALL",
                                "client_id",
                                clientId,
                                "client_secret",
                                clientSecret))))) {
      if (response.getStatus() != 200) {
        throw new RuntimeException("Failed to get token: " + response.readEntity(String.class));
      }
      return response.readEntity(new GenericType<Map<String, String>>() {}).get("access_token");
    }
  }

  public void createCatalog(String token, String name, String location, String endpoint) {
    createCatalog(
        token,
        name,
        Map.of(
            "default-base-location",
            location,
            "table-default.s3.endpoint",
            endpoint,
            "table-default.s3.path-style-access",
            "true",
            "table-default.s3.access-key-id",
            "fake",
            "table-default.s3.secret-access-key",
            "fake"),
        Map.of(
            "storageType",
            "S3",
            "roleArn",
            "arn:aws:iam::123456789012:role/my-role",
            "externalId",
            "my-external-id",
            "userArn",
            "arn:aws:iam::123456789012:user/my-user",
            "allowedLocations",
            List.of(location)));
  }

  public void createCatalog(
      String token, String name, Map<String, String> properties, Map<String, Object> storageInfo) {
    var body =
        Entity.json(
            Map.of(
                "catalog",
                Map.of(
                    "name",
                    name,
                    "type",
                    "INTERNAL",
                    "readOnly",
                    false,
                    "properties",
                    properties,
                    "storageConfigInfo",
                    storageInfo)));
    try (Client client = ClientBuilder.newBuilder().build();
        Response response =
            client
                .target(baseUri)
                .path("/api/management/v1/catalogs")
                .request()
                .header("Authorization", "Bearer " + token)
                .post(body)) {
      if (response.getStatus() != 201) {
        throw new RuntimeException(
            "Failed to create test catalog: " + response.readEntity(String.class));
      }
    }
  }
}
