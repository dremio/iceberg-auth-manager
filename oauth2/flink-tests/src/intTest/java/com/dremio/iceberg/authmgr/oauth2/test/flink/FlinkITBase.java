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

import static org.assertj.core.api.Assertions.assertThat;

import com.adobe.testing.s3mock.testcontainers.S3MockContainer;
import com.dremio.iceberg.authmgr.oauth2.OAuth2Manager;
import com.dremio.iceberg.authmgr.oauth2.test.container.KeycloakContainer;
import com.dremio.iceberg.authmgr.oauth2.test.container.PolarisContainer;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Iterators;
import java.util.Map;
import org.apache.flink.table.api.EnvironmentSettings;
import org.apache.flink.table.api.TableEnvironment;
import org.apache.iceberg.IcebergBuild;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.testcontainers.containers.Network;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public abstract class FlinkITBase {

  public static final String WAREHOUSE = "warehouse1";
  public static final String SCOPE = "catalog";
  public static final String CLIENT_ID = "Client1";
  public static final String CLIENT_SECRET = "s3cr3t";

  protected S3MockContainer s3;
  protected KeycloakContainer keycloak;
  protected PolarisContainer polaris;

  protected TableEnvironment flink;

  @BeforeAll
  void recordExpectedVersions() {
    var expectedIcebergVersion = System.getProperty("authmgr.test.iceberg.version");
    var actualIcebergVersion = IcebergBuild.version();
    assertThat(actualIcebergVersion).startsWith(expectedIcebergVersion);
    // TODO how to check Flink version? GlobalConfiguration.loadConfiguration() doesn't work
  }

  @BeforeAll
  void setup() {
    var network = Network.newNetwork();
    s3 = createS3Container(network);
    startContainers(network);
    EnvironmentSettings settings = EnvironmentSettings.newInstance().inBatchMode().build();
    flink = TableEnvironment.create(settings);
    createFlinkCatalog(flinkCatalogOptions());
  }

  protected abstract void startContainers(Network network);

  @SuppressWarnings("resource")
  protected S3MockContainer createS3Container(Network network) {
    return new S3MockContainer("4.8.0")
        .withNetwork(network)
        .withNetworkAliases("s3")
        .withInitialBuckets("test-bucket");
  }

  @SuppressWarnings("resource")
  protected KeycloakContainer createKeycloakContainer(Network network) {
    return new KeycloakContainer()
        .withNetwork(network)
        .withScope(SCOPE)
        .withClient(CLIENT_ID, CLIENT_SECRET, "client_secret_basic");
  }

  @SuppressWarnings("resource")
  protected PolarisContainer createPolarisContainer(Network network) {
    return new PolarisContainer()
        .withNetwork(network)
        .withClient(CLIENT_ID, CLIENT_SECRET)
        .withEnv("AWS_REGION", "us-west-2")
        .withEnv("polaris.features.\"SKIP_CREDENTIAL_SUBSCOPING_INDIRECTION\"", "true");
  }

  protected Map<String, String> flinkCatalogOptions() {
    return ImmutableMap.<String, String>builder()
        .put("type", "iceberg")
        .put("catalog-type", "rest")
        .put("uri", polaris.getCatalogApiEndpoint().toString())
        .put("warehouse", WAREHOUSE)
        .put("header.Polaris-Realm", "POLARIS")
        .put("header.Accept-Encoding", "none") // for debugging
        .put("s3.path-style-access", "true")
        .put("s3.endpoint", s3.getHttpEndpoint())
        .put("rest.auth.type", OAuth2Manager.class.getName())
        .put("rest.auth.oauth2.client-id", CLIENT_ID)
        .put("rest.auth.oauth2.client-secret", CLIENT_SECRET)
        .put("rest.auth.oauth2.http.client-type", "apache")
        .build();
  }

  protected void createFlinkCatalog(Map<String, String> options) {
    String sql =
        "CREATE CATALOG polaris WITH ("
            + options.entrySet().stream()
                .map(e -> "'" + e.getKey() + "' = '" + e.getValue() + "'")
                .reduce((a, b) -> a + ", " + b)
                .orElseThrow()
            + ")";
    flink.executeSql(sql);
  }

  @Test
  public void smokeTest() throws Exception {
    flink.executeSql("USE CATALOG polaris");
    try (var iterator = flink.executeSql("SHOW DATABASES").collect()) {
      assertThat(Iterators.size(iterator)).isEqualTo(0L);
    }
    flink.executeSql("CREATE DATABASE ns1");
    flink.executeSql("USE ns1");
    flink.executeSql("CREATE TABLE tb1 (col1 INT, col2 STRING)");
    flink.executeSql("INSERT INTO tb1 VALUES (1, 'a'), (2, 'b'), (3, 'c')").await();
    try (var iterator = flink.executeSql("SELECT * FROM tb1").collect()) {
      assertThat(Iterators.size(iterator)).isEqualTo(3L);
    }
  }

  @AfterAll
  @SuppressWarnings("EmptyTryBlock")
  void stopContainers() {
    var s3 = this.s3;
    var keycloak = this.keycloak;
    var polaris = this.polaris;
    try (s3;
        keycloak;
        polaris) {}
  }
}
