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
package com.dremio.iceberg.authmgr.oauth2.auth;

import com.auth0.jwt.algorithms.Algorithm;
import com.dremio.iceberg.authmgr.tools.immutables.AuthManagerImmutable;
import java.nio.file.Path;
import java.security.interfaces.RSAPrivateKey;
import org.immutables.value.Value;

@AuthManagerImmutable
public abstract class PrivateKeyJwtClientAuthenticator extends JwtClientAuthenticator {

  public static final JwtSigningAlgorithm DEFAULT_ALGORITHM = JwtSigningAlgorithm.RSA_SHA512;

  @Value.Lazy
  @Override
  protected Algorithm getAlgorithm() {
    Path privateKeyPath = getClientAssertionConfig().getPrivateKey().orElseThrow();
    RSAPrivateKey privateKey = PemUtils.readPrivateKey(privateKeyPath);
    JwtSigningAlgorithm algorithm =
        getClientAssertionConfig().getAlgorithm().orElse(DEFAULT_ALGORITHM);
    return algorithm.getRsaAlgorithm(null, privateKey);
  }
}
