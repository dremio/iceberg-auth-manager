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
package com.dremio.iceberg.authmgr.oauth2.agent;

import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import com.dremio.iceberg.authmgr.oauth2.config.BasicConfig;
import com.dremio.iceberg.authmgr.oauth2.config.ResourceOwnerConfig;
import com.dremio.iceberg.authmgr.oauth2.config.validator.ConfigValidator;
import com.dremio.iceberg.authmgr.oauth2.grant.GrantType;
import java.net.URI;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class OAuth2AgentSpecTest {

  @ParameterizedTest
  @MethodSource
  void testValidate(OAuth2AgentSpec.Builder config, List<String> expected) {
    assertThatIllegalArgumentException()
        .isThrownBy(config::build)
        .withMessage(ConfigValidator.buildDescription(expected.stream()));
  }

  static Stream<Arguments> testValidate() {
    return Stream.of(
        Arguments.of(
            OAuth2AgentSpec.builder()
                .basicConfig(
                    BasicConfig.builder()
                        .grantType(GrantType.PASSWORD)
                        .tokenEndpoint(URI.create("https://issuer.com/token"))
                        .clientId("Client1")
                        .clientSecret("s3cr3t")
                        .build()),
            asList(
                "username must be set if grant type is 'password' (rest.auth.oauth2.resource-owner.username)",
                "password must be set if grant type is 'password' (rest.auth.oauth2.resource-owner.password)")),
        Arguments.of(
            OAuth2AgentSpec.builder()
                .basicConfig(
                    BasicConfig.builder()
                        .grantType(GrantType.PASSWORD)
                        .tokenEndpoint(URI.create("https://issuer.com/token"))
                        .clientId("Client1")
                        .clientSecret("s3cr3t")
                        .build())
                .resourceOwnerConfig(ResourceOwnerConfig.builder().username("").build()),
            asList(
                "username must be set if grant type is 'password' (rest.auth.oauth2.resource-owner.username)",
                "password must be set if grant type is 'password' (rest.auth.oauth2.resource-owner.password)")),
        Arguments.of(
            OAuth2AgentSpec.builder()
                .basicConfig(
                    BasicConfig.builder()
                        .grantType(GrantType.PASSWORD)
                        .tokenEndpoint(URI.create("https://issuer.com/token"))
                        .clientId("Client1")
                        .clientSecret("s3cr3t")
                        .build())
                .resourceOwnerConfig(ResourceOwnerConfig.builder().username("Alice").build()),
            singletonList(
                "password must be set if grant type is 'password' (rest.auth.oauth2.resource-owner.password)")),
        Arguments.of(
            OAuth2AgentSpec.builder()
                .basicConfig(
                    BasicConfig.builder()
                        .grantType(GrantType.AUTHORIZATION_CODE)
                        .tokenEndpoint(URI.create("https://issuer.com/token"))
                        .clientId("Client1")
                        .clientSecret("s3cr3t")
                        .build()),
            singletonList(
                "either issuer URL or authorization endpoint must be set if grant type is 'authorization_code' (rest.auth.oauth2.issuer-url / rest.auth.oauth2.auth-code.endpoint)")),
        Arguments.of(
            OAuth2AgentSpec.builder()
                .basicConfig(
                    BasicConfig.builder()
                        .grantType(GrantType.DEVICE_CODE)
                        .tokenEndpoint(URI.create("https://issuer.com/token"))
                        .clientId("Client1")
                        .clientSecret("s3cr3t")
                        .build()),
            singletonList(
                "either issuer URL or device authorization endpoint must be set if grant type is 'device_code' (rest.auth.oauth2.issuer-url / rest.auth.oauth2.device-code.endpoint)")));
  }
}
