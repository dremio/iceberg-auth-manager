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

import com.dremio.iceberg.authmgr.oauth2.test.container.PolarisContainer;
import com.google.common.collect.ImmutableMap;
import java.net.URI;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.TestInstance;
import org.testcontainers.containers.Network;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public abstract class SparkPolarisS3ITBase extends SparkS3ITBase {

  protected volatile PolarisContainer polaris;

  @Override
  protected CompletableFuture<Void> startAllContainers(Network network) {
    return CompletableFuture.allOf(
        super.startAllContainers(network),
        createPolarisContainer(network)
            .thenCompose(
                container -> {
                  polaris = container;
                  return CompletableFuture.runAsync(container::start);
                })
            .thenCompose(v -> fetchNewToken())
            .thenAccept(this::createPolarisCatalog));
  }

  protected abstract CompletableFuture<PolarisContainer> createPolarisContainer(Network network);

  protected abstract CompletableFuture<String> fetchNewToken();

  @Override
  protected URI catalogApiEndpoint() {
    return polaris.getCatalogApiEndpoint();
  }

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

  @Override
  protected Map<String, Object> sparkConfig(Path tempDir) {
    return ImmutableMap.<String, Object>builder()
        .putAll(super.sparkConfig(tempDir))
        .put("spark.sql.catalog.test.header.Polaris-Realm", "POLARIS")
        .build();
  }

  @AfterAll
  @Override
  public void stopAllContainers() throws Exception {
    var polaris = this.polaris;
    try (polaris) {
      super.stopAllContainers();
    }
  }
}
