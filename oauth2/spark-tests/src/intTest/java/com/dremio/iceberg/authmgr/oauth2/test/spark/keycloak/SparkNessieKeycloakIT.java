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
package com.dremio.iceberg.authmgr.oauth2.test.spark.keycloak;

import com.dremio.iceberg.authmgr.oauth2.test.spark.SparkITBase;
import com.google.common.collect.ImmutableMap;
import java.net.URI;
import java.nio.file.Path;
import java.util.Map;
import org.testcontainers.containers.Network;
import org.testcontainers.lifecycle.Startables;

/**
 * A test that exercises Spark with Nessie as the catalog server and Keycloak as the identity
 * provider. Request signing is enabled.
 */
public class SparkNessieKeycloakIT extends SparkITBase {

  @Override
  public void startContainers(Network network) {
    keycloak = createKeycloakContainer(network);
    Startables.deepStart(s3, keycloak).join();
    nessie =
        createNessieContainer(network)
            .withEnv("quarkus.oidc.auth-server-url", "http://keycloak:8080/realms/master")
            .withEnv("quarkus.oidc.token.issuer", keycloak.getIssuerClaim())
            .withEnv("quarkus.oidc.client-id", CLIENT_ID);
    nessie.start();
  }

  @Override
  protected URI catalogApiEndpoint() {
    return nessie.getIcebergRestApiEndpoint();
  }

  @Override
  protected Map<String, Object> sparkConfig(Path tempDir) {
    return ImmutableMap.<String, Object>builder()
        .putAll(super.sparkConfig(tempDir))
        .put(
            "spark.sql.catalog.test.rest.auth.oauth2.issuer-url",
            keycloak.getIssuerUrl().toString())
        .put("spark.sql.catalog.test.rest.auth.oauth2.scope", SCOPE)
        .build();
  }
}
