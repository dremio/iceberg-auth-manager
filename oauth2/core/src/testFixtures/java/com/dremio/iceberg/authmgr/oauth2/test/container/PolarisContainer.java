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

import com.dremio.iceberg.authmgr.oauth2.test.TestConstants;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.GenericType;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.util.Map;
import org.apache.iceberg.rest.ResourcePaths;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.HttpWaitStrategy;

public class PolarisContainer extends GenericContainer<PolarisContainer> {

  private static final Logger LOGGER = LoggerFactory.getLogger(PolarisContainer.class);

  private final String clientId;
  private final String clientSecret;

  private URI baseUri;

  public PolarisContainer() {
    this(TestConstants.CLIENT_ID1.getValue(), TestConstants.CLIENT_SECRET1.getValue());
  }

  @SuppressWarnings("resource")
  public PolarisContainer(String clientId, String clientSecret) {
    super("apache/polaris:1.0.1-incubating");
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    withLogConsumer(new Slf4jLogConsumer(LOGGER));
    withExposedPorts(8181, 8182);
    waitingFor(
        new HttpWaitStrategy()
            .forPath("/q/health")
            .forPort(8182)
            .forResponsePredicate(body -> body.contains("\"status\": \"UP\"")));
    withEnv("POLARIS_BOOTSTRAP_CREDENTIALS", "POLARIS," + clientId + "," + clientSecret);
    withEnv("quarkus.log.level", getRootLoggerLevel());
    withEnv("quarkus.log.category.\"io.quarkus.oidc\".level", getPolarisLoggerLevel());
    withEnv("quarkus.log.category.\"org.apache.polaris\".level", getPolarisLoggerLevel());
  }

  @Override
  public void start() {
    super.start();
    baseUri = URI.create("http://localhost:" + getMappedPort(8181));
  }

  public URI getCatalogApiEndpoint() {
    return baseUri.resolve("/api/catalog/");
  }

  public URI getTokenEndpoint() {
    return getCatalogApiEndpoint().resolve(ResourcePaths.tokens());
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
                .path(ResourcePaths.tokens())
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

  public void createCatalog(
      String token, Map<String, String> properties, Map<String, Object> storageInfo) {
    var body =
        Entity.json(
            Map.of(
                "catalog",
                Map.of(
                    "name",
                    TestConstants.WAREHOUSE,
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
