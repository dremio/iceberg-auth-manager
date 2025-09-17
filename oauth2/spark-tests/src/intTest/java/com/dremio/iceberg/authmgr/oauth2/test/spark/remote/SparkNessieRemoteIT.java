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
package com.dremio.iceberg.authmgr.oauth2.test.spark.remote;

import static com.dremio.iceberg.authmgr.oauth2.test.spark.remote.RemoteAuthServerSupport.OAUTH2_AGENT_CONFIG_ENV;

import com.dremio.iceberg.authmgr.oauth2.config.BasicConfig;
import com.dremio.iceberg.authmgr.oauth2.test.spark.SparkITBase;
import com.google.common.collect.ImmutableMap;
import java.net.URI;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.testcontainers.containers.Network;

/**
 * A test that exercises Spark with Nessie as the catalog server and a remote identity provider.
 * Request signing is enabled.
 *
 * <p>The external authentication provider is configured via the {@link
 * RemoteAuthServerSupport#OAUTH2_AGENT_CONFIG_ENV} environment variable.
 */
@EnabledIfEnvironmentVariable(named = OAUTH2_AGENT_CONFIG_ENV, matches = ".+")
public class SparkNessieRemoteIT extends SparkITBase {

  @Override
  protected void startContainers(Network network) {
    s3.start();
    Map<String, String> agentConfig = RemoteAuthServerSupport.INSTANCE.getAgentConfig();
    String clientId = agentConfig.get(BasicConfig.PREFIX + '.' + BasicConfig.CLIENT_ID);
    String issuerUrl = agentConfig.get(BasicConfig.PREFIX + '.' + BasicConfig.ISSUER_URL);
    nessie =
        createNessieContainer(network)
            .withEnv("quarkus.oidc.auth-server-url", issuerUrl)
            .withEnv("quarkus.oidc.client-id", clientId);
    nessie.start();
  }

  @Override
  protected URI catalogApiEndpoint() {
    return nessie.getIcebergRestApiEndpoint();
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
