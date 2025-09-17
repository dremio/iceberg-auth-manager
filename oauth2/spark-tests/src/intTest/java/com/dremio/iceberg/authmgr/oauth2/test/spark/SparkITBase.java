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

import static org.assertj.core.api.Assertions.assertThat;

import com.adobe.testing.s3mock.testcontainers.S3MockContainer;
import com.dremio.iceberg.authmgr.oauth2.OAuth2Manager;
import com.dremio.iceberg.authmgr.oauth2.test.container.KeycloakContainer;
import com.dremio.iceberg.authmgr.oauth2.test.container.NessieContainer;
import com.dremio.iceberg.authmgr.oauth2.test.container.PolarisContainer;
import com.google.common.collect.ImmutableMap;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URI;
import java.nio.file.Path;
import java.util.Map;
import org.apache.iceberg.IcebergBuild;
import org.apache.iceberg.aws.s3.signer.S3V4RestSignerClient;
import org.apache.spark.sql.SparkSession;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.io.TempDir;
import org.testcontainers.containers.Network;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public abstract class SparkITBase {

  public static final String WAREHOUSE = "warehouse1";
  public static final String SCOPE = "catalog";
  public static final String CLIENT_ID = "Client1";
  public static final String CLIENT_SECRET = "s3cr3t";

  protected S3MockContainer s3;
  protected KeycloakContainer keycloak;
  protected NessieContainer nessie;
  protected PolarisContainer polaris;

  protected SparkSession spark;

  private String expectedIcebergVersion;
  private String expectedSparkVersion;

  @BeforeAll
  void recordExpectedVersions() {
    expectedIcebergVersion = System.getProperty("authmgr.test.iceberg.version");
    assertThat(expectedIcebergVersion).isNotNull();
    expectedSparkVersion = System.getProperty("authmgr.test.spark.version");
    assertThat(expectedSparkVersion).isNotNull();
  }

  @BeforeAll
  void setup(@TempDir Path tempDir) {
    var network = Network.newNetwork();
    s3 = createS3Container(network);
    startContainers(network);
    Map<String, Object> sparkConfig = sparkConfig(tempDir);
    spark = SparkSession.builder().master("local[1]").config(sparkConfig).getOrCreate();
  }

  protected abstract URI catalogApiEndpoint();

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

  @SuppressWarnings("resource")
  protected NessieContainer createNessieContainer(Network network) {
    return new NessieContainer()
        .withNetwork(network)
        .withEnv("AWS_REGION", "us-west-2")
        .withEnv("nessie.catalog.default-warehouse", WAREHOUSE)
        .withEnv(
            "nessie.catalog.warehouses." + WAREHOUSE + ".location", "s3://test-bucket/path/to/data")
        .withEnv("nessie.catalog.service.s3.default-options.region", "us-west-2")
        .withEnv("nessie.catalog.service.s3.default-options.endpoint", "http://s3:9090")
        .withEnv(
            "nessie.catalog.service.s3.default-options.external-endpoint", s3.getHttpEndpoint())
        .withEnv("nessie.catalog.service.s3.default-options.request-signing-enabled", "true")
        .withEnv("nessie.catalog.service.s3.default-options.path-style-access", "true")
        .withEnv(
            "nessie.catalog.service.s3.default-options.access-key",
            "urn:nessie-secret:quarkus:nessie-catalog-secrets.s3-access-key")
        .withEnv("nessie-catalog-secrets.s3-access-key.name", "fake")
        .withEnv("nessie-catalog-secrets.s3-access-key.secret", "fake")
        .withEnv("nessie.server.authentication.enabled", "true");
  }

  protected Map<String, Object> sparkConfig(Path tempDir) {
    return ImmutableMap.<String, Object>builder()
        .put(
            "spark.sql.extensions",
            "org.apache.iceberg.spark.extensions.IcebergSparkSessionExtensions")
        .put("spark.ui.showConsoleProgress", "false")
        .put("spark.ui.enabled", "false")
        .put("spark.sql.warehouse.dir", tempDir.toString())
        .put("spark.sql.catalog.test", "org.apache.iceberg.spark.SparkCatalog")
        .put("spark.sql.catalog.test.type", "rest")
        .put("spark.sql.catalog.test.uri", catalogApiEndpoint().toString())
        .put("spark.sql.catalog.test.warehouse", WAREHOUSE)
        .put("spark.sql.catalog.test.header.Accept-Encoding", "none") // for debugging
        .put("spark.sql.catalog.test.s3.path-style-access", "true")
        .put("spark.sql.catalog.test.s3.endpoint", s3.getHttpEndpoint())
        .put("spark.sql.catalog.test.rest.auth.type", OAuth2Manager.class.getName())
        .put("spark.sql.catalog.test.rest.auth.oauth2.client-id", CLIENT_ID)
        .put("spark.sql.catalog.test.rest.auth.oauth2.client-secret", CLIENT_SECRET)
        .put("spark.sql.catalog.test.rest.auth.oauth2.http.client-type", "apache")
        .build();
  }

  @Test
  public void smokeTest() {
    var actualIcebergVersion = IcebergBuild.version();
    assertThat(actualIcebergVersion).startsWith(expectedIcebergVersion);
    var actualSparkVersion = spark.sql("select version()").first().getString(0);
    assertThat(actualSparkVersion).startsWith(expectedSparkVersion);
    spark.sql("USE test");
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
  @SuppressWarnings("EmptyTryBlock")
  void stopContainers() throws Exception {
    var s3 = this.s3;
    var keycloak = this.keycloak;
    var nessie = this.nessie;
    var polaris = this.polaris;
    var spark = this.spark;
    try (s3;
        keycloak;
        nessie;
        polaris;
        spark) {}
  }

  @AfterEach
  void resetSignerClient() throws Exception {
    Field signedComponentCache =
        S3V4RestSignerClient.class.getDeclaredField("SIGNED_COMPONENT_CACHE");
    signedComponentCache.setAccessible(true);
    Object cache = signedComponentCache.get(null);
    Method invalidateAll = cache.getClass().getMethod("invalidateAll");
    invalidateAll.setAccessible(true);
    invalidateAll.invoke(cache);
    Field authManager = S3V4RestSignerClient.class.getDeclaredField("authManager");
    if (Modifier.isStatic(authManager.getModifiers())) {
      authManager.setAccessible(true);
      authManager.set(null, null);
    }
    Field httpClient = S3V4RestSignerClient.class.getDeclaredField("httpClient");
    if (Modifier.isStatic(httpClient.getModifiers())) {
      httpClient.setAccessible(true);
      httpClient.set(null, null);
    }
  }
}
