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
package com.dremio.iceberg.authmgr.oauth2.tokenexchange;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Config;
import com.dremio.iceberg.authmgr.oauth2.agent.OAuth2AgentRuntime;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.nimbusds.oauth2.sdk.token.TokenTypeURI;
import com.nimbusds.oauth2.sdk.token.TypelessAccessToken;
import java.util.Map;
import java.util.Optional;
import org.immutables.value.Value;

/** A component that centralizes the logic for supplying the subject token for token exchanges. */
@AuthManagerImmutable
public abstract class SubjectTokenSupplier extends AbstractTokenSupplier {

  public static SubjectTokenSupplier create(OAuth2Config config, OAuth2AgentRuntime runtime) {
    return ImmutableSubjectTokenSupplier.builder().mainConfig(config).runtime(runtime).build();
  }

  @Override
  public SubjectTokenSupplier copy() {
    return ImmutableSubjectTokenSupplier.builder()
        .from(this)
        .tokenAgent(getTokenAgent() == null ? null : getTokenAgent().copy())
        .build();
  }

  @Value.Check
  protected void validate() {
    if (getStaticToken().isEmpty() && getTokenAgentConfig().isEmpty()) {
      throw new IllegalArgumentException(
          "Subject token is dynamic but no configuration is provided");
    }
  }

  @Override
  protected Optional<TypelessAccessToken> getStaticToken() {
    return getMainConfig().getTokenExchangeConfig().getSubjectToken();
  }

  @Override
  protected TokenTypeURI getStaticTokenType() {
    return getMainConfig().getTokenExchangeConfig().getSubjectTokenType();
  }

  @Override
  protected Map<String, String> getDynamicTokenConfig() {
    return getMainConfig().getTokenExchangeConfig().getSubjectTokenConfig();
  }

  @Override
  protected String getDefaultAgentName() {
    return getMainConfig().getSystemConfig().getAgentName() + "-subject";
  }
}
