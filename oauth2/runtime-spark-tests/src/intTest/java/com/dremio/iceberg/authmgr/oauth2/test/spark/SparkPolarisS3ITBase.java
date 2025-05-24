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

import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.CLIENT_ID1;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.CLIENT_SECRET1;
import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.WAREHOUSE;
import static org.assertj.core.api.Assertions.assertThat;

import com.adobe.testing.s3mock.testcontainers.S3MockContainer;
import com.dremio.iceberg.authmgr.oauth2.OAuth2Manager;
import com.dremio.iceberg.authmgr.oauth2.test.container.PolarisContainer;
import com.google.common.collect.ImmutableMap;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import org.apache.spark.sql.SparkSession;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.io.TempDir;
import org.testcontainers.containers.Network;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public abstract class SparkPolarisS3ITBase {

  protected S3MockContainer s3;
  protected volatile PolarisContainer polaris;
  protected SparkSession spark;

  @BeforeAll
  public void setup(@TempDir Path tempDir) {
    var network = Network.newNetwork();
    startAllContainers(network).join();
    Map<String, Object> sparkConfig = sparkConfig(tempDir);
    spark = SparkSession.builder().master("local[1]").config(sparkConfig).getOrCreate();
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

  protected Map<String, Object> sparkConfig(Path tempDir) {
    return ImmutableMap.<String, Object>builder()
        .put(
            "spark.sql.extensions",
            "org.apache.iceberg.spark.extensions.IcebergSparkSessionExtensions")
        .put("spark.ui.showConsoleProgress", "false")
        .put("spark.ui.enabled", "false")
        .put("spark.sql.warehouse.dir", tempDir.toString())
        .put("spark.sql.catalog.polaris", "org.apache.iceberg.spark.SparkCatalog")
        .put("spark.sql.catalog.polaris.type", "rest")
        .put("spark.sql.catalog.polaris.uri", polaris.getCatalogApiEndpoint().toString())
        .put("spark.sql.catalog.polaris.warehouse", WAREHOUSE)
        .put("spark.sql.catalog.polaris.header.Polaris-Realm", "POLARIS")
        .put("spark.sql.catalog.polaris.header.Accept-Encoding", "none") // for debugging
        .put("spark.sql.catalog.polaris.s3.path-style-access", "true")
        .put("spark.sql.catalog.polaris.s3.endpoint", s3.getHttpEndpoint())
        .put("spark.sql.catalog.polaris.rest.auth.type", OAuth2Manager.class.getName())
        .put("spark.sql.catalog.polaris.rest.auth.oauth2.client-id", CLIENT_ID1)
        .put("spark.sql.catalog.polaris.rest.auth.oauth2.client-secret", CLIENT_SECRET1)
        .build();
  }

  @Test
  public void smokeTest() {
    spark.sql("USE polaris");
    long namespaceCount = spark.sql("SHOW NAMESPACES").count();
    assertThat(namespaceCount).isEqualTo(0L);
    spark.sql("CREATE NAMESPACE ns1");
    spark.sql("USE ns1");
    spark.sql("CREATE TABLE tb1 (col1 integer, col2 string)");
    spark.sql("INSERT INTO tb1 VALUES (1, 'a'), (2, 'b'), (3, 'c')");
    long recordCount = spark.sql("SELECT * FROM tb1").count();
    assertThat(recordCount).isEqualTo(3);
  }

  @AfterAll
  public void stopAllContainers() {
    var polaris = this.polaris;
    var s3 = this.s3;
    try (polaris;
        s3) {
      if (spark != null) {
        spark.close();
      }
    }
  }
}
