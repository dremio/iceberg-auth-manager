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
package com.dremio.iceberg.authmgr.oauth2.test.flink;

import com.google.common.collect.ImmutableMap;
import java.util.Map;
import org.testcontainers.containers.Network;
import org.testcontainers.lifecycle.Startables;

/**
 * A test that exercises Flink with Polaris as the catalog server and Keycloak as the identity
 * provider.
 */
public class FlinkPolarisKeycloakIT extends FlinkITBase {

  @Override
  public void startContainers(Network network) {
    keycloak = createKeycloakContainer(network);
    Startables.deepStart(s3, keycloak).join();
    polaris =
        createPolarisContainer(network)
            .withEnv("quarkus.oidc.tenant-enabled", "true")
            .withEnv("quarkus.oidc.auth-server-url", "http://keycloak:8080/realms/master")
            .withEnv("quarkus.oidc.token.issuer", keycloak.getIssuerClaim())
            .withEnv("quarkus.oidc.client-id", CLIENT_ID)
            .withEnv("polaris.authentication.type", "external")
            .withEnv("polaris.oidc.principal-mapper.id-claim-path", "principal_id");
    polaris.start();
    String token = keycloak.fetchNewToken(CLIENT_ID, CLIENT_SECRET, SCOPE);
    polaris.createCatalog(token, WAREHOUSE, "s3://test-bucket/path/to/data", "http://s3:9090");
  }

  @Override
  protected Map<String, String> flinkCatalogOptions() {
    return ImmutableMap.<String, String>builder()
        .putAll(super.flinkCatalogOptions())
        .put("rest.auth.oauth2.issuer-url", keycloak.getIssuerUrl().toString())
        .put("rest.auth.oauth2.scope", SCOPE)
        .build();
  }
}
