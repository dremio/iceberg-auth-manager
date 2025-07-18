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

import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.CLIENT_ID1;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.CLIENT_SECRET1;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.WAREHOUSE;
import static org.assertj.core.api.Assertions.assertThat;

import com.adobe.testing.s3mock.testcontainers.S3MockContainer;
import com.dremio.iceberg.authmgr.oauth2.OAuth2Manager;
import com.dremio.iceberg.authmgr.oauth2.test.container.PolarisContainer;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Iterators;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import org.apache.flink.table.api.EnvironmentSettings;
import org.apache.flink.table.api.TableEnvironment;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.testcontainers.containers.Network;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@SuppressWarnings("resource")
public abstract class FlinkPolarisS3ITBase {

  protected S3MockContainer s3;
  protected volatile PolarisContainer polaris;
  protected TableEnvironment flink;

  @BeforeAll
  public void setup() throws ExecutionException, InterruptedException {
    var network = Network.newNetwork();
    startAllContainers(network).get();
    EnvironmentSettings settings = EnvironmentSettings.newInstance().inBatchMode().build();
    flink = TableEnvironment.create(settings);
    createFlinkCatalog(flinkCatalogOptions());
  }

  protected CompletableFuture<Void> startAllContainers(Network network) {
    s3 = createS3Container(network);
    return CompletableFuture.allOf(
        CompletableFuture.runAsync(this.s3::start),
        createPolarisContainer(network)
            .thenCompose(
                container -> {
                  polaris = container;
                  return CompletableFuture.runAsync(container::start);
                })
            .thenCompose(v -> fetchNewToken())
            .thenAccept(this::createPolarisCatalog));
  }

  @SuppressWarnings("resource")
  protected S3MockContainer createS3Container(Network network) {
    return new S3MockContainer("3.11.0")
        .withInitialBuckets("test-bucket")
        .withNetwork(network)
        .withNetworkAliases("s3");
  }

  protected abstract CompletableFuture<PolarisContainer> createPolarisContainer(Network network);

  protected abstract CompletableFuture<String> fetchNewToken();

  protected void createPolarisCatalog(String token) {
    polaris.createCatalog(
        token,
        Map.of(
            "default-base-location",
            "s3://test-bucket/path/to/data",
            "table-default.s3.endpoint",
            "http://s3:9090",
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
            List.of("s3://test-bucket/path/to/data")));
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
        .put("rest.auth.oauth2.client-id", CLIENT_ID1)
        .put("rest.auth.oauth2.client-secret", CLIENT_SECRET1)
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

  @SuppressWarnings("EmptyTryBlock")
  @AfterAll
  public void stopAllContainers() {
    var polaris = this.polaris;
    var s3 = this.s3;
    try (polaris;
        s3) {}
  }
}
