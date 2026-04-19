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
package com.dremio.iceberg.authmgr.oauth2.jwtbearer;

import static com.dremio.iceberg.authmgr.oauth2.config.ConfigUtils.prefixedMap;

import com.dremio.iceberg.authmgr.oauth2.OAuth2Config;
import com.dremio.iceberg.authmgr.oauth2.agent.OAuth2Agent;
import com.dremio.iceberg.authmgr.oauth2.agent.OAuth2AgentRuntime;
import com.dremio.iceberg.authmgr.oauth2.config.JwtBearerConfig;
import com.dremio.iceberg.authmgr.oauth2.config.SystemConfig;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.id.Identifier;
import jakarta.annotation.Nullable;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import org.immutables.value.Value;

/** An assertion supplier for assertion grant requests. */
@AuthManagerImmutable
public abstract class AssertionSupplier implements AutoCloseable {

  public static AssertionSupplier create(OAuth2Config config, OAuth2AgentRuntime runtime) {
    return ImmutableAssertionSupplier.builder().mainConfig(config).runtime(runtime).build();
  }

  /**
   * Returns a stage that will supply the requested assertion when completed.
   *
   * <p>If the assertion is static, the returned stage will be already completed with the assertion
   * to use. Otherwise, the stage will complete when the underlying agent has completed its
   * authentication, and its token will become the assertion to use.
   *
   * <p>This supplier makes no assumption about the contents of the assertion. Assertions will be
   * validated later on, when creating the assertion grant.
   */
  public CompletionStage<String> supplyAssertionAsync() {
    if (getAssertionAgent() != null) {
      return getAssertionAgent().authenticateAsync().thenApply(Identifier::getValue);
    } else {
      return CompletableFuture.completedStage(getStaticAssertion().get());
    }
  }

  /**
   * Returns a copy of this supplier. The copy will share the same spec, executor and REST client
   * supplier as the original supplier, as well as its static assertion, if any. If the assertion is
   * dynamic, the original agent will be copied.
   */
  public AssertionSupplier copy() {
    return ImmutableAssertionSupplier.builder()
        .from(this)
        .assertionAgent(getAssertionAgent() == null ? null : getAssertionAgent().copy())
        .build();
  }

  @Value.Check
  protected void validate() {
    if (getStaticAssertion().isEmpty() && getAssertionAgentConfig().isEmpty()) {
      throw new IllegalArgumentException("Assertion is required");
    }
  }

  @Value.Default
  @Nullable
  protected OAuth2Agent getAssertionAgent() {
    if (!getMainConfig().getBasicConfig().getGrantType().equals(GrantType.JWT_BEARER)
        || getStaticAssertion().isPresent()
        || getAssertionAgentConfig().isEmpty()) {
      return null;
    }
    Map<String, String> assertionAgentProperties = getAssertionAgentConfig();
    if (!assertionAgentProperties.containsKey(
        SystemConfig.PREFIX + '.' + SystemConfig.AGENT_NAME)) {
      assertionAgentProperties = new HashMap<>(assertionAgentProperties);
      assertionAgentProperties.put(
          SystemConfig.PREFIX + '.' + SystemConfig.AGENT_NAME, getDefaultAgentName());
    }
    OAuth2Config assertionAgentConfig = OAuth2Config.from(assertionAgentProperties);
    return new OAuth2Agent(assertionAgentConfig, getRuntime());
  }

  @Override
  public void close() {
    if (getAssertionAgent() != null) {
      getAssertionAgent().close();
    }
  }

  @Value.Derived
  protected Map<String, String> getAssertionAgentConfig() {
    return prefixedMap(
        getMainConfig().getJwtBearerGrantConfig().getAssertionConfig(), OAuth2Config.PREFIX);
  }

  @Value.Derived
  protected Optional<String> getStaticAssertion() {
    JwtBearerConfig jwtBearerConfig = getMainConfig().getJwtBearerGrantConfig();
    return jwtBearerConfig
        .getAssertion()
        .or(() -> jwtBearerConfig.getAssertionFile().map(AssertionSupplier::readAssertionFromFile));
  }

  private static String readAssertionFromFile(Path path) {
    try {
      return Files.readString(path).strip();
    } catch (IOException e) {
      throw new UncheckedIOException("Failed to read assertion from file: " + path, e);
    }
  }

  @Value.Derived
  protected String getDefaultAgentName() {
    return getMainConfig().getSystemConfig().getAgentName() + "-assertion";
  }

  protected abstract OAuth2Config getMainConfig();

  protected abstract OAuth2AgentRuntime getRuntime();
}
