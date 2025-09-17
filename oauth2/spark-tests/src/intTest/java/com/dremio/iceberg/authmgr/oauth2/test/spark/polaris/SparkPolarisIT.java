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
package com.dremio.iceberg.authmgr.oauth2.test.spark.polaris;

import com.dremio.iceberg.authmgr.oauth2.test.spark.SparkITBase;
import com.google.common.collect.ImmutableMap;
import java.net.URI;
import java.nio.file.Path;
import java.util.Map;
import org.testcontainers.containers.Network;
import org.testcontainers.lifecycle.Startables;

/** A test that exercises Spark with Polaris as the catalog server and the identity provider. */
public class SparkPolarisIT extends SparkITBase {

  @Override
  protected void startContainers(Network network) {
    polaris = createPolarisContainer(network);
    Startables.deepStart(s3, polaris).join();
    String token = polaris.fetchNewToken();
    polaris.createCatalog(token, WAREHOUSE, "s3://test-bucket/path/to/data", "http://s3:9090");
  }

  @Override
  protected URI catalogApiEndpoint() {
    return polaris.getCatalogApiEndpoint();
  }

  @Override
  protected Map<String, Object> sparkConfig(Path tempDir) {
    return ImmutableMap.<String, Object>builder()
        .putAll(super.sparkConfig(tempDir))
        .put("spark.sql.catalog.test.header.Polaris-Realm", "POLARIS")
        .put("spark.sql.catalog.test.rest.auth.oauth2.token-endpoint", polaris.getTokenEndpoint())
        .put("spark.sql.catalog.test.rest.auth.oauth2.scope", "PRINCIPAL_ROLE:ALL")
        .build();
  }
}
