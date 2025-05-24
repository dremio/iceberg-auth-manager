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

import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.ACCESS_TOKEN_LIFESPAN;

import com.dremio.iceberg.authmgr.oauth2.test.container.PolarisContainer;
import com.google.common.collect.ImmutableMap;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import org.testcontainers.containers.Network;

/** A test that exercises Spark with Polaris configured as its own authentication provider. */
public class SparkPolarisS3IT extends SparkPolarisS3ITBase {

  @SuppressWarnings("resource")
  @Override
  protected CompletableFuture<PolarisContainer> createPolarisContainer(Network network) {
    return CompletableFuture.completedFuture(
        new PolarisContainer()
            .withEnv("AWS_REGION", "us-west-2")
            .withEnv("polaris.features.\"SKIP_CREDENTIAL_SUBSCOPING_INDIRECTION\"", "true")
            .withEnv(
                "polaris-authentication.token-broker.max-token-generation",
                ACCESS_TOKEN_LIFESPAN.toString())
            .withNetwork(network));
  }

  @Override
  protected CompletableFuture<String> fetchNewToken() {
    return CompletableFuture.supplyAsync(polaris::fetchNewToken);
  }

  @Override
  protected Map<String, Object> sparkConfig(Path tempDir) {
    return ImmutableMap.<String, Object>builder()
        .putAll(super.sparkConfig(tempDir))
        .put("spark.sql.catalog.polaris.rest.auth.oauth2.dialect", "iceberg_rest")
        .put("spark.sql.catalog.polaris.rest.auth.oauth2.scope", "PRINCIPAL_ROLE:ALL")
        .build();
  }
}
