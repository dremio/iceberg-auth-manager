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
package com.dremio.iceberg.authmgr.oauth2.flow;

import static com.dremio.iceberg.authmgr.oauth2.test.TestConstants.ACCESS_TOKEN_INITIAL;
import static com.dremio.iceberg.authmgr.oauth2.test.TokenAssertions.assertTokensResult;
import static org.assertj.core.api.Assertions.assertThat;

import com.dremio.iceberg.authmgr.oauth2.http.HttpClientType;
import com.dremio.iceberg.authmgr.oauth2.test.TestCertificates;
import com.dremio.iceberg.authmgr.oauth2.test.TestEnvironment;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.PKITLSClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.SelfSignedTLSClientAuthentication;
import java.util.concurrent.ExecutionException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Verifies the RFC 8705 mTLS client-authentication branches of {@link AbstractFlow}: the token
 * request body must contain only {@code client_id} (no {@code client_secret}, no JWT assertion),
 * and the produced {@link com.nimbusds.oauth2.sdk.auth.ClientAuthentication} object must be of the
 * Nimbus TLS type matching the configured method.
 *
 * <p>The actual TLS handshake (client cert presentation) is exercised end-to-end against a live
 * Keycloak in {@code OAuth2AgentMtlsKeycloakIT}; here we only check the on-the-wire request shape.
 */
class TlsClientAuthFlowTest {

  enum TlsMethod {
    TLS_CLIENT_AUTH(ClientAuthenticationMethod.TLS_CLIENT_AUTH, PKITLSClientAuthentication.class),
    SELF_SIGNED_TLS_CLIENT_AUTH(
        ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH,
        SelfSignedTLSClientAuthentication.class);

    final ClientAuthenticationMethod method;
    final Class<?> expectedAuthClass;

    TlsMethod(ClientAuthenticationMethod method, Class<?> expectedAuthClass) {
      this.method = method;
      this.expectedAuthClass = expectedAuthClass;
    }
  }

  @ParameterizedTest
  @EnumSource(TlsMethod.class)
  void fetchNewTokensSendsClientIdOnly(TlsMethod tlsMethod)
      throws InterruptedException, ExecutionException {
    TestCertificates certs = TestCertificates.instance();
    try (TestEnvironment env =
            TestEnvironment.builder()
                .clientAuthenticationMethod(tlsMethod.method)
                // Mock-server doesn't enforce client TLS in unit tests; the keystore is plumbed so
                // OAuth2Config validation passes and the HTTP client is configured end-to-end.
                .sslKeyStorePath(certs.getRsaKeyStore())
                .sslKeyStorePassword(certs.getKeyStorePassword())
                .httpClientType(HttpClientType.APACHE)
                .build();
        FlowFactory flowFactory = env.newFlowFactory()) {
      Flow flow = flowFactory.createInitialFlow();
      assertThat(flow).isInstanceOf(ClientCredentialsFlow.class);
      AbstractFlow abstractFlow = (AbstractFlow) flow;
      assertThat(abstractFlow.createClientAuthentication())
          .isInstanceOf(tlsMethod.expectedAuthClass);
      TokensResult tokens = flow.fetchNewTokens().toCompletableFuture().get();
      assertTokensResult(tokens, ACCESS_TOKEN_INITIAL, null);
    }
  }
}
