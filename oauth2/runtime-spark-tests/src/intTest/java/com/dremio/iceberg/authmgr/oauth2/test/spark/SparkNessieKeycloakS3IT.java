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
package com.dremio.iceberg.authmgr.oauth2.test.spark;

import com.dremio.iceberg.authmgr.oauth2.test.TestConstants;
import com.dremio.iceberg.authmgr.oauth2.test.container.KeycloakContainer;
import com.dremio.iceberg.authmgr.oauth2.test.container.NessieContainer;
import com.google.common.collect.ImmutableMap;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.AfterAll;
import org.testcontainers.containers.Network;

/**
 * A test that exercises Spark with Nessie configured with an external authentication provider
 * (Keycloak) and request signing enabled.
 */
public class SparkNessieKeycloakS3IT extends SparkNessieS3ITBase {

  private KeycloakContainer keycloak;
  private CompletableFuture<Void> keycloakStart;

  @Override
  public CompletableFuture<Void> startAllContainers(Network network) {
    keycloak = new KeycloakContainer().withNetwork(network).withNetworkAliases("keycloak");
    keycloakStart = CompletableFuture.runAsync(keycloak::start);
    return CompletableFuture.allOf(super.startAllContainers(network), keycloakStart);
  }

  @SuppressWarnings("resource")
  @Override
  protected CompletableFuture<NessieContainer> createNessieContainer(Network network) {
    return keycloakStart.thenApply(
        v ->
            new NessieContainer()
                .withEnv("AWS_REGION", "us-west-2")
                .withEnv("nessie.catalog.default-warehouse", TestConstants.WAREHOUSE)
                .withEnv(
                    "nessie.catalog.warehouses." + TestConstants.WAREHOUSE + ".location",
                    "s3://test-bucket/path/to/data")
                .withEnv("nessie.catalog.service.s3.default-options.region", "us-west-2")
                .withEnv("nessie.catalog.service.s3.default-options.endpoint", "http://s3:9090")
                .withEnv(
                    "nessie.catalog.service.s3.default-options.external-endpoint",
                    s3.getHttpEndpoint())
                .withEnv(
                    "nessie.catalog.service.s3.default-options.request-signing-enabled", "true")
                .withEnv("nessie.catalog.service.s3.default-options.path-style-access", "true")
                .withEnv(
                    "nessie.catalog.service.s3.default-options.access-key",
                    "urn:nessie-secret:quarkus:nessie-catalog-secrets.s3-access-key")
                .withEnv("nessie-catalog-secrets.s3-access-key.name", "fake")
                .withEnv("nessie-catalog-secrets.s3-access-key.secret", "fake")
                .withEnv("nessie.server.authentication.enabled", "true")
                .withEnv("quarkus.oidc.auth-server-url", "http://keycloak:8080/realms/master")
                .withEnv("quarkus.oidc.token.issuer", keycloak.getIssuerClaim())
                .withEnv("quarkus.oidc.client-id", TestConstants.CLIENT_ID1.getValue())
                .withNetwork(network));
  }

  @Override
  protected Map<String, Object> sparkConfig(Path tempDir) {
    return ImmutableMap.<String, Object>builder()
        .putAll(super.sparkConfig(tempDir))
        .put(
            "spark.sql.catalog.test.rest.auth.oauth2.issuer-url",
            keycloak.getIssuerUrl().toString())
        .put("spark.sql.catalog.test.rest.auth.oauth2.scope", TestConstants.SCOPE1.toString())
        .build();
  }

  @AfterAll
  @Override
  public void stopAllContainers() throws Exception {
    var keycloak = this.keycloak;
    try (keycloak) {
      super.stopAllContainers();
    }
  }
}
