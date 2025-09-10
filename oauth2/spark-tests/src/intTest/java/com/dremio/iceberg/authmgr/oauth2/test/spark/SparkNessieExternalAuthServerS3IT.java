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

import static com.dremio.iceberg.authmgr.oauth2.test.spark.RemoteAuthServerSupport.OAUTH2_AGENT_CONFIG_ENV;

import com.dremio.iceberg.authmgr.oauth2.config.BasicConfig;
import com.dremio.iceberg.authmgr.oauth2.test.TestConstants;
import com.dremio.iceberg.authmgr.oauth2.test.container.NessieContainer;
import com.google.common.collect.ImmutableMap;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.testcontainers.containers.Network;

/**
 * A test that exercises Spark with Nessie configured with an external authentication provider and
 * request signing enabled.
 *
 * <p>The external authentication provider is configured via the {@link
 * RemoteAuthServerSupport#OAUTH2_AGENT_CONFIG_ENV} environment variable.
 */
@EnabledIfEnvironmentVariable(named = OAUTH2_AGENT_CONFIG_ENV, matches = ".+")
public class SparkNessieExternalAuthServerS3IT extends SparkNessieS3ITBase {

  @SuppressWarnings("resource")
  @Override
  protected CompletableFuture<NessieContainer> createNessieContainer(Network network) {
    Map<String, String> agentConfig = RemoteAuthServerSupport.INSTANCE.getAgentConfig();
    return CompletableFuture.completedFuture(
        new NessieContainer()
            .withEnv("AWS_REGION", "us-west-2")
            .withEnv("nessie.catalog.default-warehouse", TestConstants.WAREHOUSE)
            .withEnv(
                "nessie.catalog.warehouses." + TestConstants.WAREHOUSE + ".location",
                "s3://test-bucket/path/to/data")
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
            .withEnv("nessie.server.authentication.enabled", "true")
            .withEnv(
                "quarkus.oidc.auth-server-url",
                agentConfig.get(BasicConfig.PREFIX + '.' + BasicConfig.ISSUER_URL))
            .withEnv(
                "quarkus.oidc.client-id",
                agentConfig.get(BasicConfig.PREFIX + '.' + BasicConfig.CLIENT_ID))
            .withNetwork(network));
  }

  @Override
  protected Map<String, Object> sparkConfig(Path tempDir) {
    ImmutableMap.Builder<String, Object> builder =
        ImmutableMap.<String, Object>builder().putAll(super.sparkConfig(tempDir));
    Map<String, String> agentConfig = RemoteAuthServerSupport.INSTANCE.getAgentConfig();
    agentConfig.forEach((k, v) -> builder.put("spark.sql.catalog.test." + k, v));
    return builder.buildKeepingLast();
  }
}
