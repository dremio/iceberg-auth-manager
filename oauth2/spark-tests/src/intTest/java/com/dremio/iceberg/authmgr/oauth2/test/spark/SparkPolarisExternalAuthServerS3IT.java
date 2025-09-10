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
import com.dremio.iceberg.authmgr.oauth2.test.container.PolarisContainer;
import com.google.common.collect.ImmutableMap;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.testcontainers.containers.Network;

/**
 * A test that exercises Spark with Polaris configured with an external authentication provider.
 *
 * <p>The external authentication provider is configured via the {@link
 * RemoteAuthServerSupport#OAUTH2_AGENT_CONFIG_ENV} environment variable.
 */
@EnabledIfEnvironmentVariable(named = OAUTH2_AGENT_CONFIG_ENV, matches = ".+")
public class SparkPolarisExternalAuthServerS3IT extends SparkPolarisS3ITBase {

  @SuppressWarnings("resource")
  @Override
  protected CompletableFuture<PolarisContainer> createPolarisContainer(Network network) {
    Map<String, String> agentConfig = RemoteAuthServerSupport.INSTANCE.getAgentConfig();
    return CompletableFuture.completedFuture(
        new PolarisContainer(
                agentConfig.get(BasicConfig.PREFIX + '.' + BasicConfig.CLIENT_ID),
                agentConfig.get(BasicConfig.PREFIX + '.' + BasicConfig.CLIENT_SECRET))
            .withEnv("AWS_REGION", "us-west-2")
            .withEnv("polaris.features.\"SKIP_CREDENTIAL_SUBSCOPING_INDIRECTION\"", "true")
            .withEnv("quarkus.oidc.tenant-enabled", "true")
            .withEnv("polaris.authentication.type", "external")
            .withEnv("polaris.oidc.principal-mapper.id-claim-path", "principal_id")
            .withEnv("quarkus.oidc.roles.role-claim-path", "principal_role")
            .withEnv(
                "quarkus.oidc.auth-server-url",
                agentConfig.get(BasicConfig.PREFIX + '.' + BasicConfig.ISSUER_URL))
            .withEnv(
                "quarkus.oidc.client-id",
                agentConfig.get(BasicConfig.PREFIX + '.' + BasicConfig.CLIENT_ID))
            .withNetwork(network));
  }

  @Override
  protected CompletableFuture<String> fetchNewToken() {
    return CompletableFuture.completedFuture(RemoteAuthServerSupport.INSTANCE.fetchNewToken());
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
