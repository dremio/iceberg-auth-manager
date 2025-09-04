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

import com.dremio.iceberg.authmgr.oauth2.OAuth2Config;
import com.dremio.iceberg.authmgr.oauth2.agent.OAuth2Agent;
import com.dremio.iceberg.authmgr.oauth2.agent.OAuth2AgentRuntime;
import com.dremio.iceberg.authmgr.oauth2.config.TokenRefreshConfig;
import com.google.common.base.Supplier;
import com.google.common.base.Suppliers;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.Executors;

/**
 * Remote auth server support.
 *
 * <p>To enable tests that require remote auth server support, set the following environment
 * variable:
 *
 * <pre>{@code
 * export OAUTH2_AGENT_CONFIG=/path/to/agent/config.properties
 * }</pre>
 *
 * The agent config file should contain everything needed to connect to the external auth server.
 *
 * <p>Example for Auth0:
 *
 * <pre>{@code
 * rest.auth.oauth2.issuer-url=https://<auth0-domain>
 * rest.auth.oauth2.grant-type=client_credentials
 * rest.auth.oauth2.client-id=<auth0-client-id>
 * rest.auth.oauth2.client-secret=<auth0-client-secret>
 * rest.auth.oauth2.client-auth=client_secret_basic
 * rest.auth.oauth2.scope=catalog
 * rest.auth.oauth2.extra-params.audience=<auth0-audience>
 * rest.auth.oauth2.auth-code.redirect-uri=<auth0-redirect-uri>
 * }</pre>
 *
 * Note: for any human-to-machine flows, the user running the test must follow the instructions
 * printed on the console to complete the flow.
 *
 * <p>Note: for Polaris, Auth0 needs to be configured to add the following custom claims to the
 * access token:
 *
 * <pre>
 * exports.onExecuteCredentialsExchange = async (event, api) => {
 *   api.accessToken.setCustomClaim('principal_id', 1);
 *   api.accessToken.setCustomClaim('principal_role', 'PRINCIPAL_ROLE:ALL');
 * };
 * </pre>
 */
public final class RemoteAuthServerSupport {

  public static final String OAUTH2_AGENT_CONFIG_ENV = "OAUTH2_AGENT_CONFIG";

  public static final RemoteAuthServerSupport INSTANCE = new RemoteAuthServerSupport();

  private RemoteAuthServerSupport() {}

  private static final Supplier<Map<String, String>> AGENT_CONFIG =
      Suppliers.memoize(
          () -> {
            Path agentConfigPath = Path.of(System.getenv(OAUTH2_AGENT_CONFIG_ENV));
            Properties props = new Properties();
            try (var in = Files.newInputStream(agentConfigPath)) {
              props.load(in);
            } catch (IOException e) {
              throw new RuntimeException(e);
            }
            @SuppressWarnings({"rawtypes", "unchecked"})
            Map<String, String> map = (Map) props;
            return map;
          });

  public Map<String, String> getAgentConfig() {
    return AGENT_CONFIG.get();
  }

  public String fetchNewToken() {
    var executor = Executors.newSingleThreadScheduledExecutor();
    try {
      Map<String, String> agentConfig = new HashMap<>(getAgentConfig());
      agentConfig.put(TokenRefreshConfig.PREFIX + '.' + TokenRefreshConfig.ENABLED, "false");
      try (var agent =
          new OAuth2Agent(OAuth2Config.from(agentConfig), OAuth2AgentRuntime.of(executor))) {
        return agent.authenticate().getValue();
      }
    } finally {
      executor.shutdownNow();
    }
  }
}
