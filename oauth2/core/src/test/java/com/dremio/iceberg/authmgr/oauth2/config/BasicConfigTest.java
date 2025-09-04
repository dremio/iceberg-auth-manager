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
package com.dremio.iceberg.authmgr.oauth2.config;

import static com.dremio.iceberg.authmgr.oauth2.OAuth2Config.PREFIX;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import com.dremio.iceberg.authmgr.oauth2.config.validator.ConfigValidator;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import io.smallrye.config.SmallRyeConfig;
import io.smallrye.config.SmallRyeConfigBuilder;
import io.smallrye.config.common.MapBackedConfigSource;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class BasicConfigTest {

  @ParameterizedTest
  @MethodSource
  void testValidate(Map<String, String> properties, List<String> expected) {
    SmallRyeConfig smallRyeConfig =
        new SmallRyeConfigBuilder()
            .withMapping(BasicConfig.class, PREFIX)
            .withSources(new MapBackedConfigSource("catalog-properties", properties, 1000) {})
            .build();
    BasicConfig config = smallRyeConfig.getConfigMapping(BasicConfig.class, PREFIX);
    assertThatIllegalArgumentException()
        .isThrownBy(config::validate)
        .withMessage(ConfigValidator.buildDescription(expected.stream()));
  }

  static Stream<Arguments> testValidate() {
    return Stream.of(
        Arguments.of(
            Map.of(
                PREFIX + '.' + BasicConfig.CLIENT_ID,
                "Client1",
                PREFIX + '.' + BasicConfig.CLIENT_SECRET,
                "s3cr3t"),
            singletonList(
                "either issuer URL or token endpoint must be set (rest.auth.oauth2.issuer-url / rest.auth.oauth2.token-endpoint)")),
        Arguments.of(
            Map.of(
                PREFIX + '.' + BasicConfig.CLIENT_ID,
                "Client1",
                PREFIX + '.' + BasicConfig.CLIENT_SECRET,
                "s3cr3t",
                PREFIX + '.' + "issuer-url",
                "realms/master"),
            singletonList("Issuer URL must not be relative (rest.auth.oauth2.issuer-url)")),
        Arguments.of(
            Map.of(
                PREFIX + '.' + BasicConfig.CLIENT_ID,
                "Client1",
                PREFIX + '.' + BasicConfig.CLIENT_SECRET,
                "s3cr3t",
                PREFIX + '.' + "issuer-url",
                "https://example.com?query"),
            singletonList("Issuer URL must not have a query part (rest.auth.oauth2.issuer-url)")),
        Arguments.of(
            Map.of(
                PREFIX + '.' + BasicConfig.CLIENT_ID,
                "Client1",
                PREFIX + '.' + BasicConfig.CLIENT_SECRET,
                "s3cr3t",
                PREFIX + '.' + "issuer-url",
                "https://example.com#fragment"),
            singletonList(
                "Issuer URL must not have a fragment part (rest.auth.oauth2.issuer-url)")),
        Arguments.of(
            Map.of(
                PREFIX + '.' + BasicConfig.CLIENT_ID,
                "Client1",
                PREFIX + '.' + BasicConfig.CLIENT_SECRET,
                "s3cr3t",
                PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT,
                "https://example.com?query"),
            singletonList(
                "Token endpoint must not have a query part (rest.auth.oauth2.token-endpoint)")),
        Arguments.of(
            Map.of(
                PREFIX + '.' + BasicConfig.CLIENT_ID,
                "Client1",
                PREFIX + '.' + BasicConfig.CLIENT_SECRET,
                "s3cr3t",
                PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT,
                "https://example.com#fragment"),
            singletonList(
                "Token endpoint must not have a fragment part (rest.auth.oauth2.token-endpoint)")),
        Arguments.of(
            Map.of(
                PREFIX + '.' + BasicConfig.CLIENT_SECRET,
                "s3cr3t",
                PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT,
                "https://example.com/token"),
            singletonList("client ID must not be empty (rest.auth.oauth2.client-id)")),
        Arguments.of(
            Map.of(
                PREFIX + '.' + BasicConfig.CLIENT_ID,
                "Client1",
                PREFIX + '.' + BasicConfig.CLIENT_AUTH,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue(),
                PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT,
                "https://example.com/token"),
            singletonList(
                "client secret must not be empty when client authentication is 'client_secret_basic' (rest.auth.oauth2.client-auth / rest.auth.oauth2.client-secret)")),
        Arguments.of(
            Map.of(
                PREFIX + '.' + BasicConfig.CLIENT_ID,
                "Client1",
                PREFIX + '.' + BasicConfig.CLIENT_AUTH,
                ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue(),
                PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT,
                "https://example.com/token"),
            singletonList(
                "client secret must not be empty when client authentication is 'client_secret_post' (rest.auth.oauth2.client-auth / rest.auth.oauth2.client-secret)")),
        Arguments.of(
            Map.of(
                PREFIX + '.' + BasicConfig.CLIENT_ID,
                "Client1",
                PREFIX + '.' + BasicConfig.CLIENT_AUTH,
                ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue(),
                PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT,
                "https://example.com/token"),
            singletonList(
                "client secret must not be empty when client authentication is 'client_secret_jwt' (rest.auth.oauth2.client-auth / rest.auth.oauth2.client-secret)")),
        Arguments.of(
            Map.of(
                PREFIX + '.' + BasicConfig.CLIENT_ID,
                "Client1",
                PREFIX + '.' + BasicConfig.CLIENT_SECRET,
                "s3cr3t",
                PREFIX + '.' + BasicConfig.CLIENT_AUTH,
                ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue(),
                PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT,
                "https://example.com/token"),
            singletonList(
                "client secret must not be set when client authentication is 'private_key_jwt' (rest.auth.oauth2.client-auth / rest.auth.oauth2.client-secret)")),
        Arguments.of(
            Map.of(
                PREFIX + '.' + BasicConfig.CLIENT_ID,
                "Client1",
                PREFIX + '.' + BasicConfig.CLIENT_SECRET,
                "s3cr3t",
                PREFIX + '.' + BasicConfig.GRANT_TYPE,
                GrantType.AUTHORIZATION_CODE.getValue(),
                PREFIX + '.' + BasicConfig.CLIENT_AUTH,
                ClientAuthenticationMethod.NONE.getValue(),
                PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT,
                "https://example.com/token"),
            singletonList(
                "client secret must not be set when client authentication is 'none' (rest.auth.oauth2.client-auth / rest.auth.oauth2.client-secret)")),
        Arguments.of(
            Map.of(
                PREFIX + '.' + BasicConfig.CLIENT_ID,
                "Client1",
                PREFIX + '.' + BasicConfig.GRANT_TYPE,
                GrantType.CLIENT_CREDENTIALS.getValue(),
                PREFIX + '.' + BasicConfig.CLIENT_AUTH,
                ClientAuthenticationMethod.NONE.getValue(),
                PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT,
                "https://example.com/token"),
            singletonList(
                "grant type must not be 'client_credentials' when client authentication is 'none' (rest.auth.oauth2.client-auth / rest.auth.oauth2.grant-type)")),
        Arguments.of(
            Map.of(
                PREFIX + '.' + BasicConfig.CLIENT_ID,
                "Client1",
                PREFIX + '.' + BasicConfig.CLIENT_SECRET,
                "s3cr3t",
                PREFIX + '.' + BasicConfig.GRANT_TYPE,
                GrantType.REFRESH_TOKEN.getValue(),
                PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT,
                "https://example.com/token"),
            singletonList(
                "grant type must be one of: 'client_credentials', 'password', 'authorization_code', 'urn:ietf:params:oauth:grant-type:device_code', 'urn:ietf:params:oauth:grant-type:token-exchange' (rest.auth.oauth2.grant-type)")),
        Arguments.of(
            Map.of(
                PREFIX + '.' + BasicConfig.CLIENT_AUTH,
                "unknown",
                PREFIX + '.' + BasicConfig.CLIENT_ID,
                "Client1",
                PREFIX + '.' + BasicConfig.CLIENT_SECRET,
                "s3cr3t",
                PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT,
                "https://example.com/token"),
            singletonList(
                "client authentication method must be one of: 'none', 'client_secret_basic', 'client_secret_post', 'client_secret_jwt', 'private_key_jwt' (rest.auth.oauth2.client-auth)")),
        Arguments.of(
            Map.of(
                PREFIX + '.' + BasicConfig.TIMEOUT,
                "PT1S",
                PREFIX + '.' + BasicConfig.CLIENT_ID,
                "Client1",
                PREFIX + '.' + BasicConfig.CLIENT_SECRET,
                "s3cr3t",
                PREFIX + '.' + "issuer-url",
                "https://example.com"),
            singletonList(
                "timeout must be greater than or equal to PT30S (rest.auth.oauth2.timeout)")));
  }

  @Test
  void testAsMap() {
    Map<String, String> properties =
        Map.of(
            PREFIX + '.' + BasicConfig.TOKEN_ENDPOINT, "https://example.com/token",
            PREFIX + '.' + BasicConfig.CLIENT_ID, "Client1",
            PREFIX + '.' + BasicConfig.CLIENT_SECRET, "s3cr3t",
            PREFIX + '.' + BasicConfig.GRANT_TYPE, GrantType.AUTHORIZATION_CODE.getValue(),
            PREFIX + '.' + BasicConfig.CLIENT_AUTH,
                ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue(),
            PREFIX + '.' + BasicConfig.SCOPE, "test",
            PREFIX + '.' + BasicConfig.EXTRA_PARAMS + ".extra1", "value1",
            PREFIX + '.' + BasicConfig.TIMEOUT, "PT1M",
            PREFIX + '.' + "min-timeout", "PT1M");
    SmallRyeConfig smallRyeConfig =
        new SmallRyeConfigBuilder()
            .withMapping(BasicConfig.class, PREFIX)
            .withSources(new MapBackedConfigSource("catalog-properties", properties, 1000) {})
            .build();
    BasicConfig config = smallRyeConfig.getConfigMapping(BasicConfig.class, PREFIX);
    assertThat(config.asMap()).isEqualTo(properties);
  }
}
