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

import static com.dremio.iceberg.authmgr.oauth2.test.flink.RemoteAuthServerSupport.OAUTH2_AGENT_CONFIG_ENV;

import com.dremio.iceberg.authmgr.oauth2.config.BasicConfig;
import com.google.common.collect.ImmutableMap;
import java.util.Map;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.testcontainers.containers.Network;
import org.testcontainers.lifecycle.Startables;

/**
 * A test that exercises Flink with Polaris as the catalog server and a remote identity provider.
 *
 * <p>The external authentication provider is configured via the {@link
 * RemoteAuthServerSupport#OAUTH2_AGENT_CONFIG_ENV} environment variable.
 */
@EnabledIfEnvironmentVariable(named = OAUTH2_AGENT_CONFIG_ENV, matches = ".+")
public class FlinkPolarisRemoteIT extends FlinkITBase {

  @Override
  protected void startContainers(Network network) {
    Map<String, String> agentConfig = RemoteAuthServerSupport.INSTANCE.getAgentConfig();
    String clientId = agentConfig.get(BasicConfig.PREFIX + '.' + BasicConfig.CLIENT_ID);
    String clientSecret = agentConfig.get(BasicConfig.PREFIX + '.' + BasicConfig.CLIENT_SECRET);
    String issuerUrl = agentConfig.get(BasicConfig.PREFIX + '.' + BasicConfig.ISSUER_URL);
    polaris =
        createPolarisContainer(network)
            .withClient(clientId, clientSecret)
            .withEnv("quarkus.oidc.tenant-enabled", "true")
            .withEnv("polaris.authentication.type", "external")
            .withEnv("polaris.oidc.principal-mapper.id-claim-path", "principal_id")
            .withEnv("quarkus.oidc.roles.role-claim-path", "principal_role")
            .withEnv("quarkus.oidc.auth-server-url", issuerUrl)
            .withEnv("quarkus.oidc.client-id", clientId);
    Startables.deepStart(s3, polaris).join();
    String token = RemoteAuthServerSupport.INSTANCE.fetchNewToken();
    polaris.createCatalog(token, WAREHOUSE, "s3://test-bucket/path/to/data", "http://s3:9090");
  }

  @Override
  protected Map<String, String> flinkCatalogOptions() {
    ImmutableMap.Builder<String, String> builder =
        ImmutableMap.<String, String>builder().putAll(super.flinkCatalogOptions());
    Map<String, String> agentConfig = RemoteAuthServerSupport.INSTANCE.getAgentConfig();
    agentConfig.forEach(builder::put);
    return builder.buildKeepingLast();
  }
}
